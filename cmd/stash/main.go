// Command stash is a lightweight, single-binary, highly-available secrets
// manager. State is replicated across nodes with embedded Raft.
//
//	stash init   [-unseal-key-out FILE]                 generate the cluster unseal key
//	stash server -data DIR [-unseal-key FILE] ...        run a node
//
// Bring up a cluster:
//
//	# box 1 (bootstrap):
//	stash server -data /data -unseal-key key -node-id n1 \
//	    -listen 0.0.0.0:8200 -raft-addr 10.0.0.1:8300 \
//	    -advertise-http http://10.0.0.1:8200 -bootstrap
//	# box 2 (join):
//	stash server -data /data -unseal-key key -node-id n2 \
//	    -listen 0.0.0.0:8200 -raft-addr 10.0.0.2:8300 \
//	    -advertise-http http://10.0.0.2:8200 -join http://10.0.0.1:8200
//	# witness (no key -> sealed voter, quorum only):
//	stash server -data /data -node-id w -raft-addr 10.0.0.3:8300 \
//	    -advertise-http http://10.0.0.3:8200 -join http://10.0.0.1:8200
package main

import (
	"context"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/jaigner-hub/stash/internal/cluster"
	"github.com/jaigner-hub/stash/internal/crypto"
	"github.com/jaigner-hub/stash/internal/server"
	"github.com/jaigner-hub/stash/internal/store"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "init":
		err = cmdInit(os.Args[2:])
	case "server":
		err = cmdServer(os.Args[2:])
	case "-h", "--help", "help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "stash: unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "stash: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `stash — lightweight HA secrets manager

usage:
  stash init   [-unseal-key-out FILE]            generate the cluster unseal key
  stash server -data DIR [flags]                 run a node

run "stash <command> -h" for command flags.
`)
}

func dbPath(dir string) string { return filepath.Join(dir, "stash.db") }

// cmdInit generates a fresh unseal key (KEK). The data key is created later, on
// cluster bootstrap, wrapped under this KEK. The KEK is the only secret you keep
// in SOPS/your bootstrap blob.
func cmdInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	keyOut := fs.String("unseal-key-out", "", "write the generated unseal key here (default: stdout)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	kek, err := crypto.GenerateKey()
	if err != nil {
		return err
	}
	encoded := base64.StdEncoding.EncodeToString(kek)

	const warn = "the unseal key is the ONLY thing that can decrypt your secrets — " +
		"store it in SOPS/your bootstrap blob, never commit it"
	if *keyOut == "" {
		fmt.Printf("unseal key (base64): %s\n", encoded)
		fmt.Fprintf(os.Stderr, "\nWARNING: %s.\n", warn)
		return nil
	}
	if err := os.WriteFile(*keyOut, []byte(encoded+"\n"), 0o600); err != nil {
		return fmt.Errorf("write unseal key: %w", err)
	}
	fmt.Printf("unseal key written to %s (0600)\n", *keyOut)
	fmt.Fprintf(os.Stderr, "\nWARNING: %s.\n", warn)
	return nil
}

func cmdServer(args []string) error {
	fs := flag.NewFlagSet("server", flag.ExitOnError)
	dir := fs.String("data", "./data", "data directory (raft logs, snapshots, store db)")
	keyFile := fs.String("unseal-key", "", "base64 unseal key file; omit to run as a sealed witness")
	listen := fs.String("listen", "127.0.0.1:8200", "HTTP API listen address")
	nodeID := fs.String("node-id", "node1", "unique stable node id")
	raftAddr := fs.String("raft-addr", "127.0.0.1:8300", "host:port for the raft transport")
	advertise := fs.String("advertise-http", "", "API URL other nodes use to reach this node (default: http://<listen>)")
	bootstrap := fs.Bool("bootstrap", false, "form a new cluster (first node only)")
	join := fs.String("join", "", "API URL of an existing node to join")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if err := os.MkdirAll(*dir, 0o700); err != nil {
		return fmt.Errorf("create data dir: %w", err)
	}

	var kek []byte
	if *keyFile != "" {
		var err error
		if kek, err = readKey(*keyFile); err != nil {
			return err
		}
	}

	st, err := store.Open(dbPath(*dir))
	if err != nil {
		return err
	}
	defer st.Close()

	httpAdvertise := *advertise
	if httpAdvertise == "" {
		httpAdvertise = "http://" + *listen
	}
	node, err := cluster.New(cluster.Config{
		NodeID:    *nodeID,
		RaftAddr:  *raftAddr,
		HTTPAddr:  httpAdvertise,
		DataDir:   *dir,
		Bootstrap: *bootstrap,
	}, st)
	if err != nil {
		return err
	}
	defer node.Close()

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))

	if *bootstrap {
		if kek == nil {
			return errors.New("-unseal-key is required when bootstrapping (it creates the data key)")
		}
		if err := node.Initialize(kek, 15*time.Second); err != nil {
			return fmt.Errorf("bootstrap init: %w", err)
		}
		log.Info("bootstrapped cluster", "node", *nodeID)
	}
	if *join != "" {
		if err := cluster.RequestJoin(*join, *nodeID, *raftAddr, httpAdvertise); err != nil {
			return fmt.Errorf("join %s: %w", *join, err)
		}
		log.Info("requested join", "leader", *join, "node", *nodeID)
	}

	// Unseal in the background so the node can serve (sealed) immediately and
	// flip to unsealed once the init material has replicated. Without a key the
	// node stays a sealed witness: consensus only.
	if kek != nil {
		go func() {
			if err := node.Unseal(kek, 60*time.Second); err != nil {
				log.Error("unseal failed", "err", err)
			} else {
				log.Info("store unsealed")
			}
		}()
	} else {
		log.Warn("no unseal key — running as a sealed witness (consensus only, cannot read secrets)")
	}

	httpSrv := &http.Server{
		Addr:         *listen,
		Handler:      server.New(node, log),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	errc := make(chan error, 1)
	go func() {
		log.Info("stash listening", "addr", *listen, "raft", *raftAddr, "node", *nodeID)
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errc <- err
		}
	}()

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
		log.Info("shutting down")
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return httpSrv.Shutdown(shutCtx)
	}
}

func readKey(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read unseal key: %w", err)
	}
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		return nil, fmt.Errorf("decode unseal key: %w", err)
	}
	if len(key) != crypto.KeyLen {
		return nil, fmt.Errorf("unseal key must be %d bytes, got %d", crypto.KeyLen, len(key))
	}
	return key, nil
}
