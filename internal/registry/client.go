package registry

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// ErrOffline is returned in offline mode for anything not already cached.
var ErrOffline = errors.New("not in cache (offline)")

// Client fetches packuments and tarballs. Packuments are cached on disk as
// the reduced form graft reads (a full axios document is ~850 KB, mostly
// README; the cached form is a fraction of that), keyed by package name.
type Client struct {
	Base     string // default https://registry.npmjs.org/
	HTTP     *http.Client
	CacheDir string        // "" disables the disk cache
	TTL      time.Duration // 0 keeps cached documents forever
	Offline  bool
	Token    string // optional bearer token for private registries

	mu       sync.Mutex
	mem      map[string]*Packument
	inflight map[string]*call
	Requests int
	Hits     int
}

type call struct {
	done chan struct{}
	p    *Packument
	err  error
}

// New returns a client for the public registry.
func New(cacheDir string, offline bool) *Client {
	return &Client{
		Base:     "https://registry.npmjs.org/",
		HTTP:     &http.Client{Timeout: 60 * time.Second},
		CacheDir: cacheDir,
		Offline:  offline,
	}
}

// Seed preloads documents (tests, fixtures, the bundled case studies).
func (c *Client) Seed(ps ...*Packument) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.mem == nil {
		c.mem = map[string]*Packument{}
	}
	for _, p := range ps {
		c.mem[p.Name] = p
	}
}

// Packument returns the document for a package. Concurrent calls for the
// same name share one request.
func (c *Client) Packument(ctx context.Context, name string) (*Packument, error) {
	c.mu.Lock()
	if c.mem == nil {
		c.mem = map[string]*Packument{}
		c.inflight = map[string]*call{}
	}
	if c.inflight == nil {
		c.inflight = map[string]*call{}
	}
	if p, ok := c.mem[name]; ok {
		c.Hits++
		c.mu.Unlock()
		return p, nil
	}
	if cl, ok := c.inflight[name]; ok {
		c.mu.Unlock()
		<-cl.done
		return cl.p, cl.err
	}
	cl := &call{done: make(chan struct{})}
	c.inflight[name] = cl
	c.mu.Unlock()

	cl.p, cl.err = c.load(ctx, name)

	c.mu.Lock()
	if cl.err == nil {
		c.mem[name] = cl.p
	}
	delete(c.inflight, name)
	c.mu.Unlock()
	close(cl.done)
	return cl.p, cl.err
}

func (c *Client) cachePath(name string) string {
	sum := sha256.Sum256([]byte(name))
	safe := strings.NewReplacer("/", "__", "@", "").Replace(name)
	return filepath.Join(c.CacheDir, "packuments", safe+"."+hex.EncodeToString(sum[:4])+".json.gz")
}

type cached struct {
	Fetched   time.Time  `json:"fetched"`
	Missing   bool       `json:"missing,omitempty"`
	Packument *Packument `json:"packument,omitempty"`
}

func (c *Client) load(ctx context.Context, name string) (*Packument, error) {
	if c.CacheDir != "" {
		if b, err := readGz(c.cachePath(name)); err == nil {
			var e cached
			if json.Unmarshal(b, &e) == nil && (c.TTL == 0 || time.Since(e.Fetched) < c.TTL || c.Offline) {
				c.mu.Lock()
				c.Hits++
				c.mu.Unlock()
				if e.Missing {
					return &Packument{Name: name, Missing: true}, nil
				}
				return e.Packument, nil
			}
		}
	}
	if c.Offline {
		return nil, fmt.Errorf("%s: %w", name, ErrOffline)
	}

	p, err := c.fetch(ctx, name)
	if err != nil {
		return nil, err
	}
	if c.CacheDir != "" {
		e := cached{Fetched: time.Now().UTC(), Missing: p.Missing}
		if !p.Missing {
			e.Packument = p.Slim()
		}
		if b, err := json.Marshal(e); err == nil {
			path := c.cachePath(name)
			_ = os.MkdirAll(filepath.Dir(path), 0o755)
			if writeGz(path+".tmp", b) == nil {
				_ = os.Rename(path+".tmp", path)
			}
		}
	}
	return p, nil
}

func (c *Client) fetch(ctx context.Context, name string) (*Packument, error) {
	// Scoped names keep the @ but escape the slash: @scope%2fname.
	u := strings.TrimSuffix(c.Base, "/") + "/" + strings.Replace(url.PathEscape(name), "%40", "@", 1)
	var lastErr error
	for attempt := 0; attempt < 4; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(time.Duration(1<<attempt) * time.Second):
			}
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return nil, err
		}
		// The full document, not the abbreviated install form: that one
		// drops _npmUser, gitHead and repository, which are half of what
		// graft looks at.
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", "graft (+https://github.com/n4uu/graft)")
		if c.Token != "" {
			req.Header.Set("Authorization", "Bearer "+c.Token)
		}
		c.mu.Lock()
		c.Requests++
		c.mu.Unlock()
		resp, err := c.HTTP.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 256<<20))
		resp.Body.Close()
		switch {
		case resp.StatusCode == http.StatusNotFound:
			return &Packument{Name: name, Missing: true}, nil
		case resp.StatusCode == 429 || resp.StatusCode >= 500:
			lastErr = fmt.Errorf("%s: HTTP %d", name, resp.StatusCode)
			continue
		case resp.StatusCode != 200:
			return nil, fmt.Errorf("%s: HTTP %d", name, resp.StatusCode)
		case err != nil:
			lastErr = err
			continue
		}
		var p Packument
		if err := json.Unmarshal(body, &p); err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		if p.Name == "" {
			p.Name = name
		}
		return &p, nil
	}
	return nil, lastErr
}

// Tarball downloads a version's tarball. Size is capped; nothing is ever
// extracted to disk.
func (c *Client) Tarball(ctx context.Context, tarballURL string) ([]byte, error) {
	if c.Offline {
		return nil, fmt.Errorf("tarball: %w", ErrOffline)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, tarballURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "graft (+https://github.com/n4uu/graft)")
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("tarball %s: HTTP %d", tarballURL, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 64<<20))
}

func readGz(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(zr)
}

func writeGz(path string, b []byte) error {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(b); err != nil {
		return err
	}
	if err := zw.Close(); err != nil {
		return err
	}
	return os.WriteFile(path, buf.Bytes(), 0o644)
}
