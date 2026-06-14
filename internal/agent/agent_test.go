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

func TestEnvName(t *testing.T) {
	cases := map[string]string{
		"db_password": "DB_PASSWORD",
		"sentry_dsn":  "SENTRY_DSN",
		"api-key":     "API_KEY",
		"a.b":         "A_B",
	}
	for in, want := range cases {
		if got := EnvName(in); got != want {
			t.Errorf("EnvName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestDirectChild(t *testing.T) {
	if leaf, ok := directChild("kg/web", "kg/web/db_password"); !ok || leaf != "db_password" {
		t.Errorf("direct child: leaf=%q ok=%v", leaf, ok)
	}
	// nested (a namespace, e.g. per-host overlay) is NOT a direct child of the base
	if _, ok := directChild("kg/web", "kg/web/vent.dog2/sentry_dsn"); ok {
		t.Error("nested path should not be a direct child of the base prefix")
	}
	// but it IS a direct child of the overlay prefix
	if leaf, ok := directChild("kg/web/vent.dog2", "kg/web/vent.dog2/sentry_dsn"); !ok || leaf != "sentry_dsn" {
		t.Errorf("overlay child: leaf=%q ok=%v", leaf, ok)
	}
	// a sibling prefix must not match
	if _, ok := directChild("kg/web", "kg/api/token"); ok {
		t.Error("different prefix should not match")
	}
}

func TestRenderAutoOnce(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "out.env")
	cache := filepath.Join(dir, "out.last")

	store := map[string]string{
		"kg/web/db_password":           "pw",
		"kg/web/sentry_dsn":            "base-dsn",   // base value
		"kg/web/vent.dog2/sentry_dsn":  "host-dsn",   // overlay overrides on this host
		"kg/api/token":                 "nope",       // outside prefix, must be ignored
	}
	list := func() ([]string, error) {
		ks := make([]string, 0, len(store))
		for k := range store {
			ks = append(ks, k)
		}
		return ks, nil
	}
	fetch := func(p string) (string, error) { return store[p], nil }

	cfg := AutoConfig{Prefix: "kg/web", Overlay: "kg/web/vent.dog2", Out: out, Cache: cache}
	res, err := RenderAutoOnce(cfg, list, fetch)
	if err != nil || !res.Changed {
		t.Fatalf("auto render: %+v err=%v", res, err)
	}
	// sorted, overlay wins for SENTRY_DSN, kg/api ignored, nested base path not junk-rendered
	want := "DB_PASSWORD=pw\nSENTRY_DSN=host-dsn\n"
	if b, _ := os.ReadFile(out); string(b) != want {
		t.Fatalf("out = %q, want %q", b, want)
	}

	// adding a new key under the prefix appears with no template change
	store["kg/web/new_thing"] = "fresh"
	res, _ = RenderAutoOnce(cfg, list, fetch)
	if !res.Changed {
		t.Fatal("adding a key should change the render")
	}
	if b, _ := os.ReadFile(out); string(b) != "DB_PASSWORD=pw\nNEW_THING=fresh\nSENTRY_DSN=host-dsn\n" {
		t.Fatalf("after add, out = %q", b)
	}

	// steady state: same store renders unchanged
	res, _ = RenderAutoOnce(cfg, list, fetch)
	if res.Changed {
		t.Fatal("re-render with no changes should not be Changed")
	}
}

func TestRenderAutoFallsBackToCache(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "o")
	cache := filepath.Join(dir, "c")
	cfg := AutoConfig{Prefix: "kg/web", Out: out, Cache: cache}

	good := func() ([]string, error) { return []string{"kg/web/a"}, nil }
	okFetch := func(string) (string, error) { return "v", nil }
	if _, err := RenderAutoOnce(cfg, good, okFetch); err != nil {
		t.Fatal(err)
	}
	// cluster unreachable -> serve last-good cache, no error
	down := func() ([]string, error) { return nil, errors.New("down") }
	res, err := RenderAutoOnce(cfg, down, okFetch)
	if err != nil || !res.FellBack {
		t.Fatalf("expected fallback, got %+v err=%v", res, err)
	}
	if b, _ := os.ReadFile(out); string(b) != "A=v\n" {
		t.Fatalf("out = %q", b)
	}
}
