// Command stash is a lightweight, single-binary, highly-available secrets
// manager. State is replicated across nodes with embedded Raft.
//
//	stash init                       generate the cluster unseal key
//	stash server -bootstrap ...      start the first node (prints a join token)
//	stash join <token>               add a node — addresses auto-detected
//	stash token                      mint another join token
//	stash server                     restart an existing node (reads cluster.json)
//
// The easy path:
//
//	# box 1
//	stash init -unseal-key-out key
//	stash server -unseal-key key -bootstrap
//	  -> prints:  stash join stash1.eyJ...
//	# box 2 (and a witness with `stash join <token> --no-key`)
//	stash join stash1.eyJ...
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/jaigner-hub/stash/internal/agent"
	"github.com/jaigner-hub/stash/internal/audit"
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
	case "join":
		err = cmdJoin(os.Args[2:])
	case "token":
		err = cmdToken(os.Args[2:])
	case "agent":
		err = cmdAgent(os.Args[2:])
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
  stash init   [-unseal-key-out FILE]      generate the cluster unseal key
  stash server -bootstrap [flags]          start the first node (prints a join token)
  stash server [flags]                     restart an existing node
  stash join   <token> [flags]             add a node (addresses auto-detected)
  stash token  [--no-key] [flags]          mint another join token
  stash agent  -template T -out O [flags]  render secrets to a file (last-good cache)

run "stash <command> -h" for command flags.
`)
}

func dbPath(dir string) string { return filepath.Join(dir, "stash.db") }

func defaultKeyPath(dir string) string { return filepath.Join(dir, "unseal.key") }

// cmdInit mints a fresh unseal key (KEK). The data key is created later, at
// cluster bootstrap, wrapped under this KEK. This KEK is the only secret you
// keep in SOPS/your bootstrap blob.
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
	listen := fs.String("listen", "0.0.0.0:8200", "HTTP API listen address")
	nodeID := fs.String("node-id", "", "unique stable node id (default: hostname)")
	raftAddr := fs.String("raft-addr", "0.0.0.0:8300", "host:port for the raft transport to bind")
	advertise := fs.String("advertise-http", "", "API URL peers use to reach this node (default: detected)")
	bootstrap := fs.Bool("bootstrap", false, "form a new cluster (first node only)")
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

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))

	// On restart, recover this node's identity/addresses from cluster.json so
	// the operator need only re-supply the data dir + key.
	cfg := cluster.Config{DataDir: *dir, Bootstrap: *bootstrap}
	listenAddr := *listen
	if lc, err := cluster.ReadLocalConfig(*dir); err == nil && !*bootstrap {
		cfg.NodeID = lc.NodeID
		cfg.RaftAddr = lc.RaftBind
		cfg.RaftAdvertise = lc.RaftAdvertise
		cfg.HTTPAddr = lc.HTTPAdvertise
		if lc.Listen != "" {
			listenAddr = lc.Listen
		}
		log.Info("recovered node config", "node", cfg.NodeID, "raft", cfg.RaftAdvertise)
	} else {
		advHost := advertiseHost(*advertise, listenAddr)
		cfg.NodeID = orHostname(*nodeID)
		cfg.RaftAddr = *raftAddr
		cfg.RaftAdvertise = net.JoinHostPort(advHost, portOf(*raftAddr))
		cfg.HTTPAddr = "http://" + net.JoinHostPort(advHost, portOf(listenAddr))
	}
	cfg.Witness = kek == nil // restarted witness (no key) must not remain leader

	st, err := store.Open(dbPath(*dir))
	if err != nil {
		return err
	}
	defer st.Close()

	node, err := cluster.New(cfg, st)
	if err != nil {
		return err
	}
	defer node.Close()

	if *bootstrap {
		if kek == nil {
			return errors.New("-unseal-key is required when bootstrapping (it creates the data key)")
		}
		rootToken, err := node.Initialize(kek, 15*time.Second)
		if err != nil {
			return fmt.Errorf("bootstrap init: %w", err)
		}
		id, secret := node.ClusterConfig()
		if err := cluster.WriteLocalConfig(*dir, cluster.LocalConfig{
			ClusterID: id, Secret: secret, LeaderAPI: cfg.HTTPAddr,
			NodeID: cfg.NodeID, Listen: listenAddr,
			RaftBind: cfg.RaftAddr, RaftAdvertise: cfg.RaftAdvertise, HTTPAdvertise: cfg.HTTPAddr,
		}); err != nil {
			return err
		}
		log.Info("bootstrapped cluster", "node", cfg.NodeID, "cluster", id)
		if rootToken != "" {
			fmt.Printf("\nroot token (admin — store it; shown only once):\n\n    %s\n\n", rootToken)
			fmt.Fprintln(os.Stderr, "WARNING: the root token grants full access to all secrets. "+
				"Use it to log into the console and to create scoped identities.")
		}
		printJoinToken(cfg.HTTPAddr, id, secret, kek)
	}

	aud, err := audit.Open(filepath.Join(*dir, "audit.db"), cfg.NodeID)
	if err != nil {
		return err
	}
	defer aud.Close()

	return serve(node, aud, listenAddr, kek, log)
}

func cmdJoin(args []string) error {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return errors.New("usage: stash join <token> [flags]")
	}
	tokenStr := args[0]
	fs := flag.NewFlagSet("join", flag.ExitOnError)
	dir := fs.String("data", "./data", "data directory")
	listen := fs.String("listen", "0.0.0.0:8200", "HTTP API listen address")
	nodeID := fs.String("node-id", "", "unique stable node id (default: hostname)")
	raftPort := fs.Int("raft-port", 8300, "local raft port")
	keyOut := fs.String("unseal-key-out", "", "where to store the unseal key from the token (default: <data>/unseal.key)")
	noKey := fs.Bool("no-key", false, "ignore any key in the token and join as a sealed witness")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}

	token, err := cluster.DecodeToken(tokenStr)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(*dir, 0o700); err != nil {
		return fmt.Errorf("create data dir: %w", err)
	}

	// Self-detect the address peers will reach us at by checking the route to
	// the leader — no IPs to type.
	leaderHostPort, err := cluster.APIHostPort(token.LeaderAPI)
	if err != nil {
		return err
	}
	ip, err := cluster.OutboundIP(leaderHostPort)
	if err != nil {
		return fmt.Errorf("detect own address: %w", err)
	}
	id := orHostname(*nodeID)
	raftBind := fmt.Sprintf("0.0.0.0:%d", *raftPort)
	raftAdv := net.JoinHostPort(ip, fmt.Sprintf("%d", *raftPort))
	httpAdv := "http://" + net.JoinHostPort(ip, portOf(*listen))

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))

	// Materialize the unseal key from the token (unless witness / --no-key).
	var kek []byte
	if token.HasKey() && !*noKey {
		kek, err = base64.StdEncoding.DecodeString(token.UnsealKey)
		if err != nil {
			return fmt.Errorf("decode key from token: %w", err)
		}
		if len(kek) != crypto.KeyLen {
			return fmt.Errorf("token key is %d bytes, want %d", len(kek), crypto.KeyLen)
		}
		keyPath := *keyOut
		if keyPath == "" {
			keyPath = defaultKeyPath(*dir)
		}
		if err := os.WriteFile(keyPath, []byte(token.UnsealKey+"\n"), 0o600); err != nil {
			return fmt.Errorf("persist unseal key for restart: %w", err)
		}
		log.Info("stored unseal key for restart", "path", keyPath)
	}

	st, err := store.Open(dbPath(*dir))
	if err != nil {
		return err
	}
	defer st.Close()

	node, err := cluster.New(cluster.Config{
		NodeID: id, RaftAddr: raftBind, RaftAdvertise: raftAdv, HTTPAddr: httpAdv, DataDir: *dir,
		Witness: kek == nil, // no key => witness; must not remain leader
	}, st)
	if err != nil {
		return err
	}
	defer node.Close()

	if err := cluster.WriteLocalConfig(*dir, cluster.LocalConfig{
		ClusterID: token.ClusterID, Secret: token.Secret, LeaderAPI: token.LeaderAPI,
		NodeID: id, Listen: *listen, RaftBind: raftBind, RaftAdvertise: raftAdv, HTTPAdvertise: httpAdv,
	}); err != nil {
		return err
	}

	if err := cluster.RequestJoin(token.LeaderAPI, id, raftAdv, httpAdv, token.Secret); err != nil {
		return fmt.Errorf("join %s: %w", token.LeaderAPI, err)
	}
	log.Info("joined cluster", "leader", token.LeaderAPI, "node", id, "addr", raftAdv)

	aud, err := audit.Open(filepath.Join(*dir, "audit.db"), id)
	if err != nil {
		return err
	}
	defer aud.Close()

	return serve(node, aud, *listen, kek, log)
}

func cmdToken(args []string) error {
	fs := flag.NewFlagSet("token", flag.ExitOnError)
	dir := fs.String("data", "./data", "data directory of a node in the cluster")
	keyFile := fs.String("unseal-key", "", "unseal key file to bundle (default: <data>/unseal.key)")
	noKey := fs.Bool("no-key", false, "produce a keyless token (for a witness / SOPS-managed key)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	lc, err := cluster.ReadLocalConfig(*dir)
	if err != nil {
		return fmt.Errorf("read cluster config (run on a bootstrapped/joined node): %w", err)
	}
	token := cluster.JoinToken{ClusterID: lc.ClusterID, LeaderAPI: lc.LeaderAPI, Secret: lc.Secret}
	if !*noKey {
		path := *keyFile
		if path == "" {
			path = defaultKeyPath(*dir)
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read unseal key (use --no-key for a witness token): %w", err)
		}
		token.UnsealKey = strings.TrimSpace(string(raw))
	}
	enc, err := token.Encode()
	if err != nil {
		return err
	}
	fmt.Println(enc)
	if token.HasKey() {
		fmt.Fprintln(os.Stderr, "WARNING: this token contains the master unseal key — treat it like a password.")
	}
	return nil
}

func cmdAgent(args []string) error {
	fs := flag.NewFlagSet("agent", flag.ExitOnError)
	api := fs.String("api", "http://127.0.0.1:8200", "stash API URL")
	tokenFlag := fs.String("token", "", `access token (or $STASH_TOKEN)`)
	tmpl := fs.String("template", "", `template file using {{secret "path"}} (required)`)
	out := fs.String("out", "", "output file, typically on tmpfs (required)")
	cache := fs.String("cache", "", "last-good cache on persistent disk (default <out>.last)")
	interval := fs.Duration("interval", 0, "re-render every interval; 0 = render once and exit")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *tmpl == "" || *out == "" {
		return errors.New("-template and -out are required")
	}
	tok := *tokenFlag
	if tok == "" {
		tok = os.Getenv("STASH_TOKEN")
	}
	cachePath := *cache
	if cachePath == "" {
		cachePath = *out + ".last"
	}

	base := strings.TrimRight(*api, "/")
	fetch := func(path string) (string, error) {
		segs := strings.Split(path, "/")
		for i, s := range segs {
			segs[i] = url.PathEscape(s)
		}
		req, err := http.NewRequest(http.MethodGet, base+"/v1/secret/"+strings.Join(segs, "/"), nil)
		if err != nil {
			return "", err
		}
		if tok != "" {
			req.Header.Set("Authorization", "Bearer "+tok)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return "", fmt.Errorf("fetch %s: status %d", path, resp.StatusCode)
		}
		var body struct {
			Value string `json:"value"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			return "", err
		}
		return body.Value, nil
	}

	cfg := agent.Config{Template: *tmpl, Out: *out, Cache: cachePath}
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))

	renderOnce := func() error {
		fell, err := agent.RenderOnce(cfg, fetch)
		switch {
		case err != nil:
			return err
		case fell:
			log.Warn("cluster unreachable; served last-good cache", "out", *out)
		default:
			log.Info("rendered secrets", "out", *out)
		}
		return nil
	}

	if *interval <= 0 {
		return renderOnce()
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := renderOnce(); err != nil {
		log.Error("render failed", "err", err) // keep looping; the cluster may recover
	}
	t := time.NewTicker(*interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			if err := renderOnce(); err != nil {
				log.Error("render failed", "err", err)
			}
		}
	}
}

// serve runs the HTTP API and a background unsealer until interrupted.
func serve(node *cluster.Node, auditor server.Auditor, listen string, kek []byte, log *slog.Logger) error {
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
		Addr:         listen,
		Handler:      server.New(node, auditor, log),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	errc := make(chan error, 1)
	go func() {
		log.Info("stash listening", "addr", listen)
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

func printJoinToken(api, id, secret string, kek []byte) {
	tok := cluster.JoinToken{ClusterID: id, LeaderAPI: api, Secret: secret}
	if kek != nil {
		tok.UnsealKey = base64.StdEncoding.EncodeToString(kek)
	}
	enc, err := tok.Encode()
	if err != nil {
		fmt.Fprintf(os.Stderr, "stash: could not encode join token: %v\n", err)
		return
	}
	fmt.Printf("\nTo add a node, run on the new box:\n\n    stash join %s\n\n", enc)
	fmt.Fprintln(os.Stderr, "WARNING: this token contains the master unseal key — treat it like a password; "+
		"prefer your tailnet and don't paste it into shared logs. Use `stash token --no-key` for a witness.")
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

// advertiseHost returns the host other nodes should use to reach this one,
// preferring an explicit -advertise-http, then the listen host, then the IP of
// the default route (so a 0.0.0.0 bind still yields a reachable address).
func advertiseHost(advertiseFlag, listen string) string {
	if advertiseFlag != "" {
		if h, _, err := net.SplitHostPort(strings.TrimPrefix(strings.TrimPrefix(advertiseFlag, "http://"), "https://")); err == nil {
			return h
		}
	}
	if host, _, err := net.SplitHostPort(listen); err == nil && host != "" && host != "0.0.0.0" && host != "::" {
		return host
	}
	if ip, err := cluster.OutboundIP("8.8.8.8:53"); err == nil {
		return ip
	}
	return "127.0.0.1"
}

func portOf(hostPort string) string {
	if _, p, err := net.SplitHostPort(hostPort); err == nil {
		return p
	}
	return ""
}

func orHostname(id string) string {
	if id != "" {
		return id
	}
	if h, err := os.Hostname(); err == nil && h != "" {
		return h
	}
	return "node1"
}
