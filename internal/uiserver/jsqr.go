package uiserver

import (
	_ "embed"
	"net/http"
)

// jsQR 1.4.0 (Apache-2.0, see assets_jsqr.LICENSE), vendored so the camera
// scanner works without BarcodeDetector and without any CDN.
//
//go:embed assets_jsqr.js
var jsqrJS []byte

func serveJSQR(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/javascript")
	w.Header().Set("Cache-Control", "max-age=86400")
	_, _ = w.Write(jsqrJS)
}
