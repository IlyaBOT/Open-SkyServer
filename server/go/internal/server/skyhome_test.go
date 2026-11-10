package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"image"
	"image/color"
	"image/gif"
	"image/png"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func skyHomeFixture(t *testing.T) (string, skyHomeManifest) {
	t.Helper()
	dir := t.TempDir()
	img := image.NewRGBA(image.Rect(0, 0, 2, 2))
	img.Set(0, 0, color.RGBA{R: 255, A: 255})
	var b bytes.Buffer
	if err := png.Encode(&b, img); err != nil {
		t.Fatal(err)
	}
	data := append(b.Bytes(), []byte("<script>untrusted trailing metadata</script>")...)
	if err := os.WriteFile(filepath.Join(dir, "picture.png"), data, 0600); err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(data)
	m := skyHomeManifest{Version: 1, Pages: []skyHomePage{
		{ID: "home", Title: "Skype Home", Text: []string{`<script>alert("x")</script>`}, Images: []string{"picture"}, Nodes: []skyHomeNode{{Tag: "div", ID: "feed", Class: "clearfix", Children: []skyHomeNode{{Text: "<img src=https://tracker/>"}, {Tag: "textarea", Text: "Update"}, {Tag: "img", Image: "picture"}}}}},
		{ID: "incall", Title: "In-Call Ad Widget"},
	}, Assets: []skyHomeAsset{{ID: "picture", File: "picture.png", SHA256: hex.EncodeToString(hash[:])}}}
	writeSkyHomeManifest(t, dir, m)
	return dir, m
}

func writeSkyHomeManifest(t *testing.T, dir string, m skyHomeManifest) {
	t.Helper()
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), b, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestSkyHomeConfigDefaultOff(t *testing.T) {
	for _, args := range [][]string{nil, {"--skyhome-dir", "/does/not/exist"}} {
		cfg, err := ParseConfig(args)
		if err != nil || cfg.EnableSkyHome {
			t.Fatalf("default not off: %+v %v", cfg, err)
		}
	}
	for _, args := range [][]string{{"--enable-skyhome"}, {"--enable-skyhome", "--skyhome-dir", " "}, {"--skyhome-dir"}} {
		if _, err := ParseConfig(args); err == nil {
			t.Fatalf("accepted %v", args)
		}
	}
	cfg, err := ParseConfig([]string{"--enable-skyhome", "--skyhome-dir", "private"})
	if err != nil || !cfg.EnableSkyHome || cfg.SkyHomeDir != "private" {
		t.Fatalf("flag parse: %+v %v", cfg, err)
	}
}

func TestSkyHomeInertRenderingAndHeaders(t *testing.T) {
	dir, _ := skyHomeFixture(t)
	s, err := NewSkyHome(dir, OpenAccess())
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/skyhome", "/skyhome/", "/skyhome/pages/home", "/incalladwidget/", "/skyhome/style.css", "/skyhome/assets/picture"} {
		t.Run(path, func(t *testing.T) {
			w := httptest.NewRecorder()
			s.ServeHTTP(w, httptest.NewRequest("GET", path+"?password=not-reflected", nil))
			if w.Code != 200 {
				t.Fatalf("status %d", w.Code)
			}
			for name, want := range map[string]string{"X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer", "Cache-Control": "no-store"} {
				if w.Header().Get(name) != want {
					t.Fatalf("%s=%s", name, w.Header().Get(name))
				}
			}
			if !strings.Contains(w.Header().Get("Content-Security-Policy"), "script-src 'none'") {
				t.Fatal("missing CSP")
			}
			if strings.Contains(w.Body.String(), "not-reflected") || strings.Contains(w.Body.String(), "<script>") {
				t.Fatal("active/untrusted markup rendered")
			}
			if path == "/skyhome/" && (!strings.Contains(w.Body.String(), `id="feed"`) || !strings.Contains(w.Body.String(), "readonly disabled")) {
				t.Fatal("recovered DOM missing")
			}
			if path == "/skyhome/assets/picture" {
				if _, err := png.Decode(bytes.NewReader(w.Body.Bytes())); err != nil {
					t.Fatal(err)
				}
				if bytes.Contains(w.Body.Bytes(), []byte("metadata")) {
					t.Fatal("original metadata survived re-encode")
				}
			}
		})
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest("HEAD", "/skyhome/", nil))
	if w.Code != 200 || w.Body.Len() != 0 || w.Header().Get("Content-Length") == "" {
		t.Fatal("invalid HEAD")
	}
}

func TestSkyHomeExplicitRoutesAndMethods(t *testing.T) {
	dir, _ := skyHomeFixture(t)
	s, err := NewSkyHome(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/", "/api/login", "/skyhome/manifest.json", "/skyhome/index.html", "/skyhome/assets/../manifest.json", "/skyhome/assets/%2e%2e%2fmanifest.json", "/skyhome/assets/%255c..", "/skyhome/assets/picture/", "/skyhome/assets/picture:stream", "/skyhome/pages/home/", "/incalladwidget/all.js"} {
		w := httptest.NewRecorder()
		s.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		if w.Code != 404 {
			t.Fatalf("path %s status %d", path, w.Code)
		}
	}
	for _, method := range []string{"POST", "PUT", "DELETE", "OPTIONS"} {
		w := httptest.NewRecorder()
		s.ServeHTTP(w, httptest.NewRequest(method, "/skyhome/", nil))
		if w.Code != 405 || w.Header().Get("Allow") != "GET, HEAD" {
			t.Fatalf("method %s", method)
		}
	}
}

func TestSkyHomeAPIMountAndAccess(t *testing.T) {
	dir, _ := skyHomeFixture(t)
	s, err := NewSkyHome(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, enabled := range []bool{false, true} {
		api := &APIServer{}
		if enabled {
			api.SkyHome = s
		}
		handler := api.handler()
		for _, path := range []string{"/healthz", "/skyhome/", "/incalladwidget/", "/api/not-an-endpoint"} {
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
			if path == "/healthz" && w.Body.String() != "ok\n" {
				t.Fatal("health route broken")
			}
			if strings.HasPrefix(path, "/api/") && !strings.HasPrefix(w.Body.String(), "ERR") {
				t.Fatal("API intercepted")
			}
			if path == "/skyhome/" && strings.Contains(w.Body.String(), "<!doctype") != enabled {
				t.Fatal("opt-in mount mismatch")
			}
		}
	}
	s.access = &AccessPolicy{nets: []*net.IPNet{{IP: net.ParseIP("127.0.0.1"), Mask: net.CIDRMask(32, 32)}}}
	for remote, want := range map[string]int{"192.0.2.1:1234": 403, "127.0.0.1:1234": 200} {
		r := httptest.NewRequest("GET", "/skyhome/", nil)
		r.RemoteAddr = remote
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		if w.Code != want {
			t.Fatalf("access %s status %d", remote, w.Code)
		}
	}
	ports := DefaultTCPPorts(33033, 33034)
	for _, port := range []int{80, 443} {
		found := false
		for _, p := range ports {
			if p == port {
				found = true
			}
		}
		if !found {
			t.Fatalf("native port %d removed", port)
		}
	}
}

func TestSkyHomeRejectsBadManifest(t *testing.T) {
	for name, change := range map[string]func(*skyHomeManifest){
		"version":         func(m *skyHomeManifest) { m.Version = 2 },
		"duplicate-page":  func(m *skyHomeManifest) { m.Pages = append(m.Pages, m.Pages[0]) },
		"duplicate-asset": func(m *skyHomeManifest) { m.Assets = append(m.Assets, m.Assets[0]) },
		"missing-home":    func(m *skyHomeManifest) { m.Pages = m.Pages[1:] },
		"missing-image":   func(m *skyHomeManifest) { m.Pages[0].Images = []string{"absent"} },
		"bad-id":          func(m *skyHomeManifest) { m.Pages[0].ID = "../secret" },
		"hash":            func(m *skyHomeManifest) { m.Assets[0].SHA256 = strings.Repeat("0", 64) },
		"unknown-kind":    func(m *skyHomeManifest) { m.Assets[0].Kind = "js" },
		"long-text":       func(m *skyHomeManifest) { m.Pages[0].Text = []string{strings.Repeat("x", 4097)} },
		"script-node":     func(m *skyHomeManifest) { m.Pages[0].Nodes = []skyHomeNode{{Tag: "script", Text: "alert(1)"}} },
		"event-attribute": func(m *skyHomeManifest) { m.Pages[0].Nodes = []skyHomeNode{{Tag: "div", Class: `x" onclick="steal`}} },
	} {
		t.Run(name, func(t *testing.T) {
			dir, m := skyHomeFixture(t)
			change(&m)
			writeSkyHomeManifest(t, dir, m)
			if _, err := NewSkyHome(dir, nil); err == nil {
				t.Fatal("accepted invalid manifest")
			}
		})
	}
	for _, suffix := range []string{" {}", " true"} {
		dir, _ := skyHomeFixture(t)
		b, _ := os.ReadFile(filepath.Join(dir, "manifest.json"))
		os.WriteFile(filepath.Join(dir, "manifest.json"), append(b, []byte(suffix)...), 0600)
		if _, err := NewSkyHome(dir, nil); err == nil {
			t.Fatal("accepted trailing JSON")
		}
	}
}

func TestSkyHomeRejectsFilesystemEscapes(t *testing.T) {
	for _, name := range []string{"../picture.png", "/picture.png", `C:\picture.png`, `sub\picture.png`, "picture.png:stream", "CON.png", "sub/../../picture.png", "sub//picture.png"} {
		t.Run(name, func(t *testing.T) {
			dir, m := skyHomeFixture(t)
			m.Assets[0].File = name
			writeSkyHomeManifest(t, dir, m)
			if _, err := NewSkyHome(dir, nil); err == nil {
				t.Fatal("accepted escape")
			}
		})
	}
	for _, intermediate := range []bool{false, true} {
		dir, m := skyHomeFixture(t)
		outside := t.TempDir()
		b, _ := os.ReadFile(filepath.Join(dir, "picture.png"))
		os.WriteFile(filepath.Join(outside, "picture.png"), b, 0600)
		link, target, name := filepath.Join(dir, "link.png"), filepath.Join(outside, "picture.png"), "link.png"
		if intermediate {
			link, target, name = filepath.Join(dir, "sub"), outside, "sub/picture.png"
		}
		if err := os.Symlink(target, link); err != nil {
			t.Skipf("symlink permission: %v", err)
		}
		m.Assets[0].File = name
		writeSkyHomeManifest(t, dir, m)
		if _, err := NewSkyHome(dir, nil); err == nil {
			t.Fatal("accepted symlink escape")
		}
	}
}

func TestSkyHomeSnapshotDoesNotReadChangedFiles(t *testing.T) {
	dir, _ := skyHomeFixture(t)
	s, err := NewSkyHome(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := append([]byte(nil), s.assets["picture"]...)
	os.WriteFile(filepath.Join(dir, "picture.png"), []byte("changed"), 0600)
	os.WriteFile(filepath.Join(dir, "manifest.json"), []byte("invalid"), 0600)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest("GET", "/skyhome/assets/picture", nil))
	if !bytes.Equal(w.Body.Bytes(), want) {
		t.Fatal("request reread changed source")
	}
}

func TestSkyHomeRasterAndCSSValidation(t *testing.T) {
	for _, data := range [][]byte{[]byte(`<svg onload="steal()"/>`), []byte("not an image")} {
		dir, m := skyHomeFixture(t)
		os.WriteFile(filepath.Join(dir, "picture.png"), data, 0600)
		h := sha256.Sum256(data)
		m.Assets[0].SHA256 = hex.EncodeToString(h[:])
		writeSkyHomeManifest(t, dir, m)
		if _, err := NewSkyHome(dir, nil); err == nil {
			t.Fatal("accepted non-raster")
		}
	}
	for _, css := range []string{`div{background:url("https://tracker/x")}`, `div{width:expression(steal())}`, `@import "x";`, `div{background:u\72l(x)}`, `div{background:image-set("x")}`, `/*comment*/div{color:red}`} {
		dir, m := skyHomeFixture(t)
		data := []byte(css)
		os.WriteFile(filepath.Join(dir, "style.css"), data, 0600)
		h := sha256.Sum256(data)
		m.Assets = append(m.Assets, skyHomeAsset{ID: "style", Kind: "css", File: "style.css", SHA256: hex.EncodeToString(h[:])})
		writeSkyHomeManifest(t, dir, m)
		if _, err := NewSkyHome(dir, nil); err == nil {
			t.Fatalf("accepted unsafe CSS %s", css)
		}
	}
	img := image.NewPaletted(image.Rect(0, 0, 1, 1), color.Palette{color.White, color.Black})
	var b bytes.Buffer
	if err := gif.EncodeAll(&b, &gif.GIF{Image: []*image.Paletted{img, img}, Delay: []int{1, 1}}); err != nil {
		t.Fatal(err)
	}
	dir, m := skyHomeFixture(t)
	os.WriteFile(filepath.Join(dir, "picture.png"), b.Bytes(), 0600)
	h := sha256.Sum256(b.Bytes())
	m.Assets[0].SHA256 = hex.EncodeToString(h[:])
	writeSkyHomeManifest(t, dir, m)
	s, err := NewSkyHome(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := png.Decode(bytes.NewReader(s.assets["picture"])); err != nil {
		t.Fatal("GIF not converted to PNG")
	}
}

func TestSkyHomeRecoveredPrivateManifest(t *testing.T) {
	dir := os.Getenv("SKYSERVER_SKYHOME_TEST_DIR")
	if dir == "" {
		t.Skip("set SKYSERVER_SKYHOME_TEST_DIR to a private recovered serve directory")
	}
	s, err := NewSkyHome(dir, OpenAccess())
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/skyhome/", "/skyhome/pages/classic", "/skyhome/pages/original", "/incalladwidget/"} {
		w := httptest.NewRecorder()
		s.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code != 200 {
			t.Fatalf("%s: %d", path, w.Code)
		}
	}
	t.Logf("loaded %d pages, %d raster assets, %d recovered stylesheets", len(s.pages), len(s.assets), len(s.styles))
}
