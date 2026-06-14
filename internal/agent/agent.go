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
	"sort"
	"strings"
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
	return commit(cfg.Out, cfg.Cache, func() (string, error) {
		tmpl, err := os.ReadFile(cfg.Template)
		if err != nil {
			return "", fmt.Errorf("agent: read template: %w", err)
		}
		return Render(string(tmpl), fetch)
	})
}

// commit runs produce and writes Out + Cache (both 0600) only when the content
// changed (or a file is missing) — so a steady poll doesn't churn the file or
// fire reload hooks needlessly. If produce fails but a cache exists, it serves
// the cache to Out and returns FellBack=true with a nil error; it errors only
// when it can neither produce nor fall back.
func commit(out, cache string, produce func() (string, error)) (Result, error) {
	rendered, rerr := produce()
	if rerr != nil {
		cached, cerr := os.ReadFile(cache)
		if cerr != nil {
			return Result{}, fmt.Errorf("%w (and no last-good cache at %s)", rerr, cache)
		}
		if cur, _ := os.ReadFile(out); !bytes.Equal(cur, cached) {
			if err := os.WriteFile(out, cached, 0o600); err != nil {
				return Result{}, fmt.Errorf("agent: write from cache: %w", err)
			}
		}
		return Result{FellBack: true}, nil
	}

	b := []byte(rendered)
	prev, _ := os.ReadFile(cache) // last successful render
	changed := !bytes.Equal(b, prev)
	if changed || !fileExists(out) {
		if err := os.WriteFile(out, b, 0o600); err != nil {
			return Result{}, fmt.Errorf("agent: write out: %w", err)
		}
	}
	if changed || !fileExists(cache) {
		if err := os.WriteFile(cache, b, 0o600); err != nil {
			return Result{}, fmt.Errorf("agent: write cache: %w", err)
		}
	}
	return Result{Changed: changed}, nil
}

// AutoConfig describes a prefix-based render: every secret the caller may read
// directly under Prefix becomes a KEY=value line, with KEY derived from the leaf
// path segment (see EnvName). Secrets directly under Overlay (if set) override
// the base by env-var name — used for per-host values, e.g. Overlay
// "kg/web/<node>" lets one node see a different value without a template edit.
// Adding a secret under Prefix makes it appear on the next render — no redeploy.
type AutoConfig struct {
	Prefix  string
	Overlay string
	Out     string
	Cache   string
}

// Lister returns every secret path the caller is allowed to read. (The stash
// API already scopes this to the identity's ACL, so an app token restricted to
// kg/web/* lists exactly that subtree.)
type Lister func() ([]string, error)

// RenderAutoOnce renders all readable secrets under cfg.Prefix (then cfg.Overlay,
// which overrides) to cfg.Out, with the same change detection + last-good cache
// as RenderOnce.
func RenderAutoOnce(cfg AutoConfig, list Lister, fetch Fetcher) (Result, error) {
	return commit(cfg.Out, cfg.Cache, func() (string, error) {
		return renderAuto(cfg, list, fetch)
	})
}

func renderAuto(cfg AutoConfig, list Lister, fetch Fetcher) (string, error) {
	keys, err := list()
	if err != nil {
		return "", fmt.Errorf("agent: list secrets: %w", err)
	}
	vals := map[string]string{}
	collect := func(prefix string) error {
		if prefix == "" {
			return nil
		}
		for _, k := range keys {
			leaf, ok := directChild(prefix, k)
			if !ok {
				continue
			}
			v, ferr := fetch(k)
			if ferr != nil {
				return fmt.Errorf("agent: fetch %s: %w", k, ferr)
			}
			vals[EnvName(leaf)] = v
		}
		return nil
	}
	if err := collect(cfg.Prefix); err != nil {
		return "", err
	}
	if err := collect(cfg.Overlay); err != nil { // overrides the base
		return "", err
	}
	names := make([]string, 0, len(vals))
	for n := range vals {
		names = append(names, n)
	}
	sort.Strings(names) // deterministic output so the cache/change check is stable
	var b strings.Builder
	for _, n := range names {
		b.WriteString(n)
		b.WriteByte('=')
		b.WriteString(vals[n])
		b.WriteByte('\n')
	}
	return b.String(), nil
}

// directChild reports whether key is exactly one segment below prefix, returning
// that leaf segment. Deeper paths (nested namespaces, e.g. per-host overlays) are
// not direct children, so the base prefix never renders them as junk vars.
func directChild(prefix, key string) (leaf string, ok bool) {
	p := strings.TrimSuffix(prefix, "/") + "/"
	if !strings.HasPrefix(key, p) {
		return "", false
	}
	leaf = key[len(p):]
	if leaf == "" || strings.Contains(leaf, "/") {
		return "", false
	}
	return leaf, true
}

// EnvName maps a secret leaf to an environment variable name: upper-cased, with
// '-' and '.' turned into '_'. e.g. "db_password" -> "DB_PASSWORD".
func EnvName(leaf string) string {
	return strings.ToUpper(strings.NewReplacer("-", "_", ".", "_").Replace(leaf))
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}
