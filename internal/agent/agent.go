// Package agent renders secrets from a stash cluster into a local file via a
// template, keeping a last-good cache. The cache is the point: if the cluster is
// briefly unreachable (e.g. a box rebooting before the cluster is back), the
// agent re-serves the last successful render so the app still comes up — the
// reboot-self-heal property stash inherits from ADR-0001.
package agent

import (
	"bytes"
	"fmt"
	"os"
	"text/template"
)

// Fetcher returns the plaintext value of a secret path, or an error.
type Fetcher func(path string) (string, error)

// Config describes one render: a template file, the live output, and a
// last-good cache. For self-heal, Out is typically on tmpfs and Cache on
// persistent disk (so it survives a reboot).
type Config struct {
	Template string
	Out      string
	Cache    string
}

// Render executes tmpl with a `secret "path"` function backed by fetch. A failed
// fetch fails the whole render (so a partial file is never written).
func Render(tmpl string, fetch Fetcher) (string, error) {
	t, err := template.New("stash").Option("missingkey=error").Funcs(template.FuncMap{
		"secret": fetch,
	}).Parse(tmpl)
	if err != nil {
		return "", fmt.Errorf("agent: parse template: %w", err)
	}
	var buf bytes.Buffer
	if err := t.Execute(&buf, nil); err != nil {
		return "", fmt.Errorf("agent: render: %w", err)
	}
	return buf.String(), nil
}

// Result reports what a render did.
type Result struct {
	Changed  bool // the rendered content differs from the last successful render
	FellBack bool // the cluster was unreachable; the last-good cache was served
}

// RenderOnce renders the template and writes Out + Cache (both 0600), but only
// when the content actually changed (or the file is missing) — so a steady poll
// doesn't churn the file or fire reload hooks needlessly. If the render fails
// (e.g. cluster unreachable) but a cache exists, it serves the cache to Out and
// returns FellBack=true with a nil error. It errors only when it can neither
// render nor fall back.
func RenderOnce(cfg Config, fetch Fetcher) (Result, error) {
	tmpl, err := os.ReadFile(cfg.Template)
	if err != nil {
		return Result{}, fmt.Errorf("agent: read template: %w", err)
	}
	rendered, rerr := Render(string(tmpl), fetch)
	if rerr != nil {
		cached, cerr := os.ReadFile(cfg.Cache)
		if cerr != nil {
			return Result{}, fmt.Errorf("%w (and no last-good cache at %s)", rerr, cfg.Cache)
		}
		if cur, _ := os.ReadFile(cfg.Out); !bytes.Equal(cur, cached) {
			if err := os.WriteFile(cfg.Out, cached, 0o600); err != nil {
				return Result{}, fmt.Errorf("agent: write from cache: %w", err)
			}
		}
		return Result{FellBack: true}, nil
	}

	out := []byte(rendered)
	prev, _ := os.ReadFile(cfg.Cache) // last successful render
	changed := !bytes.Equal(out, prev)
	if changed || !fileExists(cfg.Out) {
		if err := os.WriteFile(cfg.Out, out, 0o600); err != nil {
			return Result{}, fmt.Errorf("agent: write out: %w", err)
		}
	}
	if changed || !fileExists(cfg.Cache) {
		if err := os.WriteFile(cfg.Cache, out, 0o600); err != nil {
			return Result{}, fmt.Errorf("agent: write cache: %w", err)
		}
	}
	return Result{Changed: changed}, nil
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}
