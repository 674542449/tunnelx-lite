package client

import (
	"bufio"
	"bytes"
	"context"
	"github.com/674542449/tunnelx-lite/internal/config"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

// Some HTTP CDNs cancel a request if the peer half-closes before the response.
// Model that behavior inside a real H2 CONNECT stream, including a range GET
// and a chunked upload, so this covers the proxy and tunnel framing together.
func TestHTTPForwardKeepsWriteSideOpenUntilResponse(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodHead} {
		t.Run(method, func(t *testing.T) {
			payload := bytes.Repeat([]byte("steam-content-block"), 8192)
			upload := bytes.Repeat([]byte("upload"), 8192)
			c := poolServer(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Tunnelx-Version", config.Version)
				w.WriteHeader(200)
				http.NewResponseController(w).Flush()
				request, err := http.ReadRequest(bufio.NewReader(r.Body))
				if err != nil {
					t.Errorf("origin request: %v", err)
					return
				}
				body, err := io.ReadAll(request.Body)
				if err != nil {
					t.Errorf("origin body: %v", err)
					return
				}
				if request.URL.RequestURI() != "/depot/731/chunk/sample?key=preserved" || request.Host != "cdn.test" || request.Header.Get("Range") != "bytes=0-155647" || request.Header.Get("X-Hop") != "" {
					t.Errorf("request headers or signed path changed")
				}
				if method == http.MethodPost && !bytes.Equal(body, upload) {
					t.Error("upload changed")
				}
				eof := make(chan struct{})
				go func() { io.Copy(io.Discard, r.Body); close(eof) }()
				defer r.Body.Close()
				select {
				case <-eof:
					return // Origin cancels on an early TCP FIN.
				case <-time.After(150 * time.Millisecond):
				case <-r.Context().Done():
					return
				}
				response := &http.Response{StatusCode: 206, ProtoMajor: 1, ProtoMinor: 1,
					Request:       request,
					Header:        http.Header{"Content-Range": {"bytes 0-155647/311296"}},
					ContentLength: int64(len(payload)), Body: io.NopCloser(bytes.NewReader(payload)), Close: true}
				if method == http.MethodHead {
					response.Body = http.NoBody
				}
				if err := response.Write(w); err != nil {
					t.Errorf("origin response: %v", err)
				}
			})
			m, err := New(c)
			if err != nil {
				t.Fatal(err)
			}
			defer m.Close()
			p := NewProxy(m)
			defer p.Close()
			front := httptest.NewServer(p)
			defer front.Close()
			proxyURL, _ := url.Parse(front.URL)
			transport := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			var body io.Reader
			if method == http.MethodPost {
				body = io.NopCloser(bytes.NewReader(upload))
			}
			request, _ := http.NewRequestWithContext(ctx, method, "http://cdn.test/depot/731/chunk/sample?key=preserved", body)
			request.Header.Set("Range", "bytes=0-155647")
			request.Header.Set("Connection", "X-Hop")
			request.Header.Set("X-Hop", "strip-me")
			for i := 0; i < 2; i++ { // Also exercise reuse of the app's proxy connection.
				if i > 0 && method == http.MethodPost {
					break
				}
				response, err := client.Do(request.Clone(ctx))
				if err != nil {
					t.Fatal(err)
				}
				data, err := io.ReadAll(response.Body)
				response.Body.Close()
				if err != nil {
					t.Fatal(err)
				}
				if response.StatusCode != 206 {
					t.Fatalf("HTTP download failed: %d %q", response.StatusCode, data)
				}
				if response.Header.Get("Content-Range") != "bytes 0-155647/311296" {
					t.Fatal("range metadata changed")
				}
				if method != http.MethodHead && !bytes.Equal(data, payload) {
					t.Fatal("download payload changed")
				}
				if method == http.MethodHead && len(data) != 0 {
					t.Fatal("HEAD returned a body")
				}
			}
		})
	}
}
