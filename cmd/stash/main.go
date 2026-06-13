// Command stash is a lightweight, single-binary secrets manager.
//
// Milestone 1 is a single encrypted node — no clustering yet. Raft-based HA
// lands in a later milestone behind the same store/server interfaces.
//
//	stash init   -data DIR [-unseal-key-out FILE]
//	stash server -data DIR -unseal-key FILE [-listen ADDR]
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
	fmt.Fprint(os.Stderr, `stash — lightweight secrets manager

usage:
  stash init   -data DIR [-unseal-key-out FILE]   initialize a new store
  stash server -data DIR -unseal-key FILE [-listen ADDR]   run the node

run "stash <command> -h" for command flags.
`)
}

func dbPath(dir string) string { return filepath.Join(dir, "stash.db") }

func cmdInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	dir := fs.String("data", "./data", "data directory for the bbolt database")
	keyOut := fs.String("unseal-key-out", "", "write the generated unseal key here (default: print to stdout)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if err := os.MkdirAll(*dir, 0o700); err != nil {
		return fmt.Errorf("create data dir: %w", err)
	}
	s, err := store.Open(dbPath(*dir))
	if err != nil {
		return err
	}
	defer s.Close()

	switch init, err := s.Initialized(); {
	case err != nil:
		return err
	case init:
		return errors.New("store already initialized (refusing to overwrite)")
	}

	kek, err := crypto.GenerateKey()
	if err != nil {
		return err
	}
	if err := s.Init(kek); err != nil {
		return err
	}
	encoded := base64.StdEncoding.EncodeToString(kek)

	const warn = "the unseal key is the ONLY thing that can decrypt your secrets — " +
		"store it in SOPS/your bootstrap blob, never commit it"
	if *keyOut == "" {
		fmt.Printf("unseal key (base64): %s\n", encoded)
		fmt.Fprintf(os.Stderr, "\nWARNING: %s.\nIt was NOT written to disk; copy it now.\n", warn)
		return nil
	}
	if err := os.WriteFile(*keyOut, []byte(encoded+"\n"), 0o600); err != nil {
		return fmt.Errorf("write unseal key: %w", err)
	}
	fmt.Printf("initialized %s\nunseal key written to %s (0600)\n", dbPath(*dir), *keyOut)
	fmt.Fprintf(os.Stderr, "\nWARNING: %s.\n", warn)
	return nil
}

func cmdServer(args []string) error {
	fs := flag.NewFlagSet("server", flag.ExitOnError)
	dir := fs.String("data", "./data", "data directory for the bbolt database")
	keyFile := fs.String("unseal-key", "", "file containing the base64 unseal key (required)")
	listen := fs.String("listen", "127.0.0.1:8200", "HTTP listen address")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *keyFile == "" {
		return errors.New("-unseal-key is required")
	}
	kek, err := readKey(*keyFile)
	if err != nil {
		return err
	}

	s, err := store.Open(dbPath(*dir))
	if err != nil {
		return err
	}
	defer s.Close()
	if err := s.Unseal(kek); err != nil {
		return err
	}

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	httpSrv := &http.Server{
		Addr:         *listen,
		Handler:      server.New(s, log),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	errc := make(chan error, 1)
	go func() {
		log.Info("stash listening", "addr", *listen)
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
