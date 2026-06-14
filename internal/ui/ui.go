// Package ui serves stash's embedded web console: static HTML/CSS/JS that talks
// to the JSON API. It is deliberately dependency-free — no framework, no CDN —
// so the whole console ships inside the single binary and works offline / on a
// tailnet. Access control is currently network-level (front it with Tailscale
// Serve); in-app auth arrives with the identity milestone.
package ui

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed assets
var assets embed.FS

// Handler serves the console at / (index.html) plus its static assets.
func Handler() http.Handler {
	sub, err := fs.Sub(assets, "assets")
	if err != nil {
		panic(err) // the embedded FS is guaranteed at compile time
	}
	return http.FileServerFS(sub)
}
