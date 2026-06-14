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

// RenderOnce renders the template and writes Out + Cache (both 0600). If the
// render fails (e.g. the cluster is unreachable) but a cache exists, it copies
// the cache to Out and returns fellBack=true with a nil error. It returns an
// error only when it can neither render nor fall back.
func RenderOnce(cfg Config, fetch Fetcher) (fellBack bool, err error) {
	tmpl, err := os.ReadFile(cfg.Template)
	if err != nil {
		return false, fmt.Errorf("agent: read template: %w", err)
	}
	rendered, rerr := Render(string(tmpl), fetch)
	if rerr != nil {
		cached, cerr := os.ReadFile(cfg.Cache)
		if cerr != nil {
			return false, fmt.Errorf("%w (and no last-good cache at %s)", rerr, cfg.Cache)
		}
		if err := os.WriteFile(cfg.Out, cached, 0o600); err != nil {
			return false, fmt.Errorf("agent: write from cache: %w", err)
		}
		return true, nil
	}
	if err := os.WriteFile(cfg.Out, []byte(rendered), 0o600); err != nil {
		return false, fmt.Errorf("agent: write out: %w", err)
	}
	if err := os.WriteFile(cfg.Cache, []byte(rendered), 0o600); err != nil {
		return false, fmt.Errorf("agent: write cache: %w", err)
	}
	return false, nil
}
