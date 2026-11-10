package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"html/template"
	"image"
	_ "image/gif"
	_ "image/jpeg"
	"image/png"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

const skyHomeFileLimit = 16 << 20
const skyHomeTotalLimit = 64 << 20

var skyHomeID = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)
var skyHomeDevice = regexp.MustCompile(`^(COM|LPT)[1-9]$`)
var skyHomeDOMToken = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)
var skyHomeCSSURL = regexp.MustCompile(`url\("/skyhome/assets/[a-z0-9-]+"\)`)
var skyHomeCSSUnsafe = regexp.MustCompile(`(?i)https?:|ftp:|data:|javascript:|vbscript:|expression|behavior|-moz-binding|progid|image-set|url\s*\(`)

type skyHomeAsset struct {
	ID     string `json:"id"`
	File   string `json:"file"`
	SHA256 string `json:"sha256"`
	Kind   string `json:"kind,omitempty"`
}

type skyHomePage struct {
	ID     string        `json:"id"`
	Title  string        `json:"title"`
	Text   []string      `json:"text"`
	Images []string      `json:"images"`
	Nodes  []skyHomeNode `json:"nodes,omitempty"`
	Style  string        `json:"style,omitempty"`
}

type skyHomeNode struct {
	Tag      string        `json:"tag,omitempty"`
	Text     string        `json:"text,omitempty"`
	ID       string        `json:"id,omitempty"`
	Class    string        `json:"class,omitempty"`
	Children []skyHomeNode `json:"children,omitempty"`
	Image    string        `json:"image,omitempty"`
}

type skyHomeManifest struct {
	Version int            `json:"version"`
	Pages   []skyHomePage  `json:"pages"`
	Assets  []skyHomeAsset `json:"assets"`
}

// SkyHome is an immutable, inert preview, not a bridge to Skype or recovered JS.
type SkyHome struct {
	pages  map[string][]byte
	assets map[string][]byte
	styles map[string][]byte
	access *AccessPolicy
}

const skyHomeTemplate = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{.Title}}</title>{{if .Style}}<link rel="stylesheet" href="/skyhome/styles/{{.Style}}">{{end}}<link rel="stylesheet" href="/skyhome/style.css"></head>
<body><header><a href="/skyhome/">SkyHome</a><nav>{{range .Pages}}<a href="/skyhome/pages/{{.ID}}">{{.Title}}</a>{{end}}<a href="/incalladwidget/">In-Call Ad Widget</a></nav></header>
<main><h1>{{.Title}}</h1>{{.Body}}{{range .Text}}<p>{{.}}</p>{{end}}
<div class="images">{{range .Images}}<img src="/skyhome/assets/{{.}}" alt="" loading="lazy">{{end}}</div></main></body></html>`

const skyHomeCSS = `*{box-sizing:border-box}body{margin:0;background:#fff;color:#222;font:14px "Segoe UI",Arial,sans-serif;letter-spacing:0}header{padding:16px 24px;border-bottom:1px solid #ddd;background:#f4f7f8}header>a{font-size:22px;color:#007eaa;text-decoration:none}nav{display:flex;flex-wrap:wrap;gap:10px 20px;margin-top:12px}a{color:#006b90}main{max-width:980px;margin:auto;padding:24px}h1{font-size:24px;margin:0 0 20px}p,a{overflow-wrap:anywhere}p{line-height:1.6}.images{display:flex;align-items:flex-start;flex-wrap:wrap;gap:16px}.images img{max-width:100%;height:auto;object-fit:contain}@media(max-width:480px){header,main{padding:16px}h1{font-size:22px}}`

// Minimal safety overrides are authored; the per-page stylesheet is recovered.
const skyHomeRecoveredCSS = `html,body{min-width:0!important;width:auto!important;height:auto!important;overflow:auto!important}body>header,body>main{position:relative!important;float:none!important}body>main{margin:auto!important}.recovered{position:relative;min-height:80px}.recovered textarea{max-width:100%;resize:none}.recovered img{max-width:100%;height:auto}#loading,#msBeacon,#fb-root,#fancybox-tmp,#fancybox-loading,#fancybox-overlay,#fancybox-wrap{display:none!important}`

// NewSkyHome reads only explicit manifest entries at startup. Requests never
// resolve a filesystem path, so later symlink/file changes cannot expose files.
func NewSkyHome(dir string, access *AccessPolicy) (*SkyHome, error) {
	if strings.TrimSpace(dir) == "" {
		return nil, fmt.Errorf("SkyHome requires --skyhome-dir")
	}
	root, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return nil, fmt.Errorf("SkyHome directory: %w", err)
	}
	data, err := skyHomeRead(root, "manifest.json", 1<<20)
	if err != nil {
		return nil, fmt.Errorf("SkyHome manifest: %w", err)
	}
	var m skyHomeManifest
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err = dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("SkyHome manifest: %w", err)
	}
	if dec.Decode(new(any)) != io.EOF || m.Version != 1 || len(m.Pages) == 0 || len(m.Pages) > 32 || len(m.Assets) > 256 {
		return nil, fmt.Errorf("invalid SkyHome manifest version, count or trailing data")
	}
	s := &SkyHome{pages: make(map[string][]byte), assets: make(map[string][]byte), styles: make(map[string][]byte), access: access}
	total, encodedTotal := 0, 0
	for _, a := range m.Assets {
		if !skyHomeID.MatchString(a.ID) || s.assets[a.ID] != nil || s.styles[a.ID] != nil {
			return nil, fmt.Errorf("invalid or duplicate SkyHome asset ID")
		}
		b, err := skyHomeRead(root, a.File, skyHomeFileLimit)
		if err != nil {
			return nil, fmt.Errorf("SkyHome asset %s: %w", a.ID, err)
		}
		hash := sha256.Sum256(b)
		if len(a.SHA256) != 64 || !strings.EqualFold(a.SHA256, hex.EncodeToString(hash[:])) {
			return nil, fmt.Errorf("SkyHome asset %s hash mismatch", a.ID)
		}
		total += len(b)
		if total > skyHomeTotalLimit {
			return nil, fmt.Errorf("SkyHome source assets exceed size limit")
		}
		if a.Kind == "css" {
			if len(b) > 1<<20 || strings.ContainsAny(string(b), "\\@\x00<") || bytes.Contains(b, []byte("/*")) || skyHomeCSSUnsafe.MatchString(skyHomeCSSURL.ReplaceAllString(string(b), "")) {
				return nil, fmt.Errorf("SkyHome stylesheet %s is not inert local CSS", a.ID)
			}
			s.styles[a.ID] = b
			encodedTotal += len(b)
			continue
		}
		if a.Kind != "" && a.Kind != "image" {
			return nil, fmt.Errorf("unsupported SkyHome asset kind")
		}
		info, format, err := image.DecodeConfig(bytes.NewReader(b))
		if err != nil || (format != "png" && format != "jpeg" && format != "gif") || info.Width < 1 || info.Height < 1 || info.Width > 4096 || info.Height > 4096 || int64(info.Width)*int64(info.Height) > 16<<20 {
			return nil, fmt.Errorf("SkyHome asset %s is not a bounded raster image", a.ID)
		}
		img, _, err := image.Decode(bytes.NewReader(b))
		if err != nil {
			return nil, fmt.Errorf("SkyHome asset %s: %w", a.ID, err)
		}
		var clean bytes.Buffer
		if err = png.Encode(&clean, img); err != nil {
			return nil, err
		}
		encodedTotal += clean.Len()
		if clean.Len() > skyHomeFileLimit || encodedTotal > skyHomeTotalLimit {
			return nil, fmt.Errorf("SkyHome re-encoded asset exceeds size limit")
		}
		s.assets[a.ID] = clean.Bytes()
	}
	tmpl := template.Must(template.New("skyhome").Parse(skyHomeTemplate))
	for _, p := range m.Pages {
		if !skyHomeID.MatchString(p.ID) || s.pages[p.ID] != nil || len(p.Title) > 256 || len(p.Text) > 128 || len(p.Images) > 32 {
			return nil, fmt.Errorf("invalid or duplicate SkyHome page")
		}
		for _, text := range p.Text {
			if len(text) > 4096 {
				return nil, fmt.Errorf("SkyHome text exceeds size limit")
			}
		}
		for _, id := range p.Images {
			if s.assets[id] == nil {
				return nil, fmt.Errorf("SkyHome page %s references missing image %s", p.ID, id)
			}
		}
		if p.Style != "" && s.styles[p.Style] == nil {
			return nil, fmt.Errorf("missing SkyHome stylesheet")
		}
		var out bytes.Buffer
		var body strings.Builder
		budget := 4096
		if err = skyHomeRenderNodes(&body, p.Nodes, 0, &budget, s.assets); err != nil {
			return nil, fmt.Errorf("SkyHome page %s: %w", p.ID, err)
		}
		if err = tmpl.Execute(&out, struct {
			skyHomePage
			Pages []skyHomePage
			Body  template.HTML
		}{p, m.Pages, template.HTML(`<div class="recovered">` + body.String() + `</div>`)}); err != nil {
			return nil, err
		}
		s.pages[p.ID] = out.Bytes()
	}
	if s.pages["home"] == nil || s.pages["incall"] == nil {
		return nil, fmt.Errorf("SkyHome requires home and incall pages")
	}
	return s, nil
}

// Only structural elements and escaped text survive recovery. In particular,
// there are no source-provided URLs, CSS, scripts, event handlers or form inputs.
func skyHomeRenderNodes(out *strings.Builder, nodes []skyHomeNode, depth int, budget *int, assets map[string][]byte) error {
	if depth > 32 || len(nodes) > *budget {
		return fmt.Errorf("recovered DOM size/depth limit")
	}
	*budget -= len(nodes)
	for _, n := range nodes {
		if len(n.Text) > 4096 || len(n.Class) > 512 || len(n.ID) > 128 {
			return fmt.Errorf("recovered DOM field size limit")
		}
		if n.Tag == "" {
			if n.ID != "" || n.Class != "" || n.Image != "" || len(n.Children) != 0 {
				return fmt.Errorf("invalid recovered text node")
			}
			out.WriteString(html.EscapeString(n.Text))
			continue
		}
		switch n.Tag {
		case "div", "span", "p", "h2", "h3", "h4", "ul", "ol", "li", "strong", "em", "b", "i", "br", "a", "textarea", "img":
		default:
			return fmt.Errorf("active or unsupported recovered element")
		}
		out.WriteString("<" + n.Tag)
		if n.ID != "" {
			if !skyHomeDOMToken.MatchString(n.ID) {
				return fmt.Errorf("invalid DOM id")
			}
			out.WriteString(` id="` + n.ID + `"`)
		}
		for _, token := range strings.Fields(n.Class) {
			if !skyHomeDOMToken.MatchString(token) {
				return fmt.Errorf("invalid DOM class")
			}
		}
		if n.Class != "" {
			out.WriteString(` class="` + html.EscapeString(n.Class) + `"`)
		}
		if n.Tag == "textarea" {
			out.WriteString(` readonly disabled`)
		}
		if n.Image != "" {
			if n.Tag != "img" || assets[n.Image] == nil {
				return fmt.Errorf("invalid recovered image")
			}
			out.WriteString(` src="/skyhome/assets/` + n.Image + `" alt=""`)
		}
		out.WriteString(">")
		out.WriteString(html.EscapeString(n.Text))
		if err := skyHomeRenderNodes(out, n.Children, depth+1, budget, assets); err != nil {
			return err
		}
		if n.Tag != "br" && n.Tag != "img" {
			out.WriteString("</" + n.Tag + ">")
		}
	}
	return nil
}

func skyHomeRead(root, name string, limit int64) ([]byte, error) {
	// Reject Windows alternate streams, device names and separator aliases even
	// on Unix, so a manifest has the same interpretation on both hosts.
	if name == "" || strings.ContainsAny(name, `\:`) || strings.HasPrefix(name, "/") {
		return nil, fmt.Errorf("invalid resource path")
	}
	current := root
	for _, part := range strings.Split(name, "/") {
		base := strings.ToUpper(strings.SplitN(part, ".", 2)[0])
		if part == "" || part == "." || part == ".." || strings.ContainsAny(part, "\x00<>\"|?*") || strings.TrimRight(part, " .") != part || base == "CON" || base == "PRN" || base == "AUX" || base == "NUL" || skyHomeDevice.MatchString(base) {
			return nil, fmt.Errorf("invalid resource path component")
		}
		current = filepath.Join(current, part)
		st, err := os.Lstat(current)
		if err != nil {
			return nil, err
		}
		if st.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("symlink resource denied")
		}
	}
	resolved, err := filepath.EvalSymlinks(current)
	if err != nil {
		return nil, err
	}
	rel, err := filepath.Rel(root, resolved)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return nil, fmt.Errorf("resource escapes root")
	}
	before, err := os.Lstat(resolved)
	if err != nil || !before.Mode().IsRegular() || before.Size() > limit {
		return nil, fmt.Errorf("resource is not a bounded regular file")
	}
	f, err := os.Open(resolved)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return nil, fmt.Errorf("resource changed while opening")
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(b)) > limit {
		return nil, fmt.Errorf("resource read failed or exceeded size limit")
	}
	return b, nil
}

func (s *SkyHome) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Security-Policy", "default-src 'none'; img-src 'self'; style-src 'self'; connect-src 'none'; script-src 'none'; form-action 'none'; base-uri 'none'; frame-ancestors 'self'; sandbox allow-same-origin")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "SAMEORIGIN")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Cache-Control", "no-store")
	if s.access != nil {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil || !s.access.Allows(net.ParseIP(host)) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// Match the decoded URL exactly. No redirects, path cleaning, file server or
	// historical host-wide aliases can steal native transport/API traffic.
	var b []byte
	contentType := "text/html; charset=utf-8"
	switch r.URL.Path {
	case "/skyhome", "/skyhome/":
		b = s.pages["home"]
	case "/incalladwidget", "/incalladwidget/":
		b = s.pages["incall"]
	case "/skyhome/style.css":
		b = []byte(skyHomeCSS + skyHomeRecoveredCSS)
		contentType = "text/css; charset=utf-8"
	default:
		if strings.HasPrefix(r.URL.Path, "/skyhome/pages/") {
			b = s.pages[strings.TrimPrefix(r.URL.Path, "/skyhome/pages/")]
		} else if strings.HasPrefix(r.URL.Path, "/skyhome/assets/") {
			b = s.assets[strings.TrimPrefix(r.URL.Path, "/skyhome/assets/")]
			contentType = "image/png"
		} else if strings.HasPrefix(r.URL.Path, "/skyhome/styles/") {
			b = s.styles[strings.TrimPrefix(r.URL.Path, "/skyhome/styles/")]
			contentType = "text/css; charset=utf-8"
		}
	}
	if b == nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Length", fmt.Sprint(len(b)))
	if r.Method != http.MethodHead {
		_, _ = w.Write(b)
	}
}
