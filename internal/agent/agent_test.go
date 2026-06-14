package agent

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestRender(t *testing.T) {
	fetch := func(path string) (string, error) {
		return map[string]string{"kg/web/A": "alpha", "kg/web/B": "bravo"}[path], nil
	}
	out, err := Render("A={{secret \"kg/web/A\"}}\nB={{secret \"kg/web/B\"}}\n", fetch)
	if err != nil {
		t.Fatal(err)
	}
	if out != "A=alpha\nB=bravo\n" {
		t.Fatalf("got %q", out)
	}
}

func TestRenderFetchError(t *testing.T) {
	fetch := func(path string) (string, error) { return "", errors.New("unreachable") }
	if _, err := Render("X={{secret \"p\"}}", fetch); err == nil {
		t.Fatal("expected render to fail when fetch fails")
	}
}

func TestRenderOnceWritesAndCaches(t *testing.T) {
	dir := t.TempDir()
	tmpl := filepath.Join(dir, "t.tmpl")
	out := filepath.Join(dir, "out.env")
	cache := filepath.Join(dir, "out.last")
	os.WriteFile(tmpl, []byte("K={{secret \"p\"}}\n"), 0o600)

	fetch := func(string) (string, error) { return "v1", nil }
	res, err := RenderOnce(Config{Template: tmpl, Out: out, Cache: cache}, fetch)
	if err != nil || res.FellBack || !res.Changed {
		t.Fatalf("render: %+v err=%v", res, err)
	}
	if b, _ := os.ReadFile(out); string(b) != "K=v1\n" {
		t.Fatalf("out = %q", b)
	}
	if b, _ := os.ReadFile(cache); string(b) != "K=v1\n" {
		t.Fatalf("cache = %q", b)
	}
}

func TestRenderOnceFallsBackToCache(t *testing.T) {
	dir := t.TempDir()
	tmpl := filepath.Join(dir, "t.tmpl")
	out := filepath.Join(dir, "out.env")
	cache := filepath.Join(dir, "out.last")
	os.WriteFile(tmpl, []byte("K={{secret \"p\"}}\n"), 0o600)

	// First render succeeds and populates the cache.
	ok := func(string) (string, error) { return "good", nil }
	if _, err := RenderOnce(Config{Template: tmpl, Out: out, Cache: cache}, ok); err != nil {
		t.Fatal(err)
	}
	os.Remove(out) // simulate tmpfs wiped by reboot

	// Now the cluster is unreachable: should fall back to cache, no error.
	down := func(string) (string, error) { return "", errors.New("down") }
	res, err := RenderOnce(Config{Template: tmpl, Out: out, Cache: cache}, down)
	if err != nil {
		t.Fatalf("expected cache fallback, got err %v", err)
	}
	if !res.FellBack {
		t.Fatal("expected FellBack=true")
	}
	if b, _ := os.ReadFile(out); string(b) != "K=good\n" {
		t.Fatalf("out after fallback = %q", b)
	}
}

func TestRenderOnceChangeDetection(t *testing.T) {
	dir := t.TempDir()
	tmpl := filepath.Join(dir, "t.tmpl")
	out := filepath.Join(dir, "out.env")
	cache := filepath.Join(dir, "out.last")
	os.WriteFile(tmpl, []byte("K={{secret \"p\"}}\n"), 0o600)
	cfg := Config{Template: tmpl, Out: out, Cache: cache}

	val := "one"
	fetch := func(string) (string, error) { return val, nil }

	r1, _ := RenderOnce(cfg, fetch)
	if !r1.Changed {
		t.Fatal("first render should be Changed")
	}
	r2, _ := RenderOnce(cfg, fetch) // same value
	if r2.Changed {
		t.Fatal("re-render of unchanged value should NOT be Changed")
	}
	val = "two"
	r3, _ := RenderOnce(cfg, fetch) // new value
	if !r3.Changed {
		t.Fatal("render after value change should be Changed")
	}
	if b, _ := os.ReadFile(out); string(b) != "K=two\n" {
		t.Fatalf("out = %q", b)
	}
}

func TestRenderOnceNoCacheNoFallback(t *testing.T) {
	dir := t.TempDir()
	tmpl := filepath.Join(dir, "t.tmpl")
	os.WriteFile(tmpl, []byte("K={{secret \"p\"}}\n"), 0o600)
	down := func(string) (string, error) { return "", errors.New("down") }
	if _, err := RenderOnce(Config{
		Template: tmpl, Out: filepath.Join(dir, "o"), Cache: filepath.Join(dir, "c"),
	}, down); err == nil {
		t.Fatal("expected hard error when render fails and no cache exists")
	}
}
