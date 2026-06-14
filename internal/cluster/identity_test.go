package cluster

import (
	"testing"
	"time"
)

func TestIdentityCan(t *testing.T) {
	admin := &Identity{Admin: true}
	if !admin.Can(CapWrite, "anything") {
		t.Fatal("admin should allow everything")
	}

	id := &Identity{Policies: []Policy{
		{Prefix: "kg/web/", Caps: []string{CapRead}},
		{Prefix: "kg/", Caps: []string{"*"}},
	}}
	cases := []struct {
		cap, path string
		want      bool
	}{
		{CapRead, "kg/web/SECRET", true},
		{CapWrite, "kg/web/SECRET", true}, // matched by kg/ "*"
		{CapRead, "kg/other", true},
		{CapWrite, "other/x", false},
		{CapRead, "other/x", false},
	}
	for _, c := range cases {
		if got := id.Can(c.cap, c.path); got != c.want {
			t.Errorf("Can(%q,%q)=%v want %v", c.cap, c.path, got, c.want)
		}
	}

	ro := &Identity{Policies: []Policy{{Prefix: "", Caps: []string{CapRead}}}}
	if !ro.Can(CapRead, "anything") {
		t.Fatal("empty prefix should match all paths")
	}
	if ro.Can(CapWrite, "anything") {
		t.Fatal("read-only identity should not be able to write")
	}
}

func TestNodeIdentityLifecycle(t *testing.T) {
	kek := mustKey(t)
	n, _, _ := newNode(t, "n1", true)
	root, err := n.Initialize(kek, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Unseal(kek, 10*time.Second); err != nil {
		t.Fatal(err)
	}
	if root == "" || !n.HasIdentities() {
		t.Fatal("bootstrap should mint a root identity")
	}
	// The root token authenticates as admin.
	if id, _ := n.Authenticate(root); id == nil || !id.Admin {
		t.Fatalf("root token should authenticate as admin, got %+v", id)
	}

	tok, err := n.CreateIdentity("ci", false, []Policy{{Prefix: "kg/web/", Caps: []string{CapRead}}})
	if err != nil {
		t.Fatal(err)
	}
	id, err := n.Authenticate(tok)
	if err != nil || id == nil || id.Name != "ci" {
		t.Fatalf("authenticate(ci) = %+v, %v", id, err)
	}
	if !id.Can(CapRead, "kg/web/X") || id.Can(CapWrite, "kg/web/X") {
		t.Fatal("ci policy not enforced")
	}
	if got, _ := n.Authenticate("not-a-real-token"); got != nil {
		t.Fatal("unknown token should not authenticate")
	}

	ids, err := n.ListIdentities()
	if err != nil {
		t.Fatal(err)
	}
	for _, x := range ids {
		if x.TokenHash != "" {
			t.Fatalf("listed identity %q leaks token hash", x.Name)
		}
	}

	if err := n.DeleteIdentity("ci"); err != nil {
		t.Fatal(err)
	}
	if got, _ := n.Authenticate(tok); got != nil {
		t.Fatal("deleted identity should no longer authenticate")
	}
}
