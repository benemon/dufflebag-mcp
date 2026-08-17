package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// client speaks the dufflebag wire API. One http.Client carries every call,
// token minting included.
type client struct {
	endpoint     string
	clientID     string
	clientSecret string
	http         *http.Client

	mu         sync.Mutex
	token      string
	expires    time.Time
	bucketOnce sync.Once
	bucketName string
	bucketErr  error
}

func newClientFromEnv() (*client, error) {
	endpoint := strings.TrimRight(os.Getenv("DFBG_MCP_ENDPOINT"), "/")
	id := os.Getenv("DFBG_MCP_CLIENT_ID")
	secret := os.Getenv("DFBG_MCP_CLIENT_SECRET")
	if endpoint == "" || id == "" || secret == "" {
		return nil, fmt.Errorf("DFBG_MCP_ENDPOINT, DFBG_MCP_CLIENT_ID and DFBG_MCP_CLIENT_SECRET are required")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if caFile := os.Getenv("DFBG_MCP_CA_FILE"); caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("read CA file: %w", err)
		}
		pool, err := x509.SystemCertPool()
		if err != nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("no certificates parsed from %s", caFile)
		}
		transport.TLSClientConfig = &tls.Config{RootCAs: pool}
	}
	return &client{
		endpoint: endpoint, clientID: id, clientSecret: secret,
		http: &http.Client{Transport: transport, Timeout: 30 * time.Second},
	}, nil
}

// defaultBucket resolves the configured bucket id to the compat plane's
// bucket name when a tool call omits its bucket argument.
func (c *client) defaultBucket(org, project string, bucket *string) error {
	if *bucket != "" {
		return nil
	}
	bucketID := os.Getenv("DFBG_MCP_BUCKET_ID")
	if bucketID == "" {
		return nil
	}
	name, err := c.scopedBucketName(org, project, bucketID)
	if err != nil {
		return err
	}
	*bucket = name
	return nil
}

func (c *client) scopedBucketName(org, project, bucketID string) (string, error) {
	if bucketID == "" {
		return "", nil
	}
	c.bucketOnce.Do(func() {
		var out struct {
			Buckets []struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			} `json:"buckets"`
		}
		if err := c.call("GET", compatBase(org, project)+"/buckets", nil, &out); err != nil {
			c.bucketErr = err
			return
		}
		visible := make([]string, 0, len(out.Buckets))
		for _, bucket := range out.Buckets {
			visible = append(visible, bucket.ID)
			if bucket.ID == bucketID {
				c.bucketName = bucket.Name
			}
		}
		if c.bucketName == "" {
			ids := strings.Join(visible, ", ")
			if ids == "" {
				ids = "(none)"
			}
			c.bucketErr = fmt.Errorf("DFBG_MCP_BUCKET_ID %q does not match a visible bucket; visible bucket ids: %s", bucketID, ids)
		}
	})
	return c.bucketName, c.bucketErr
}

func (c *client) bearer() (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token != "" && time.Now().Before(c.expires) {
		return c.token, nil
	}
	form := url.Values{
		"grant_type": {"client_credentials"},
		"audience":   {"https://api.hashicorp.cloud"},
	}
	req, err := http.NewRequest(http.MethodPost, c.endpoint+"/oauth2/token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.SetBasicAuth(c.clientID, c.clientSecret)
	req.Header.Set("content-type", "application/x-www-form-urlencoded")
	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("mint token: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("mint token: %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	var minted struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &minted); err != nil {
		return "", fmt.Errorf("decode token response: %w", err)
	}
	if minted.AccessToken == "" {
		return "", fmt.Errorf("token response carried no access_token")
	}
	c.token = minted.AccessToken
	ttl := time.Duration(minted.ExpiresIn) * time.Second
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	c.expires = time.Now().Add(ttl - 30*time.Second)
	return c.token, nil
}

// call performs one authenticated request and decodes the JSON response into
// out (which may be nil for status-only calls). A 401 retries once with a
// fresh token so an expired cache never surfaces to the tool caller.
func (c *client) call(method, path string, payload any, out any) error {
	for attempt := 0; ; attempt++ {
		token, err := c.bearer()
		if err != nil {
			return err
		}
		var body io.Reader
		if payload != nil {
			encoded, err := json.Marshal(payload)
			if err != nil {
				return err
			}
			body = strings.NewReader(string(encoded))
		}
		req, err := http.NewRequest(method, c.endpoint+path, body)
		if err != nil {
			return err
		}
		req.Header.Set("authorization", "Bearer "+token)
		if payload != nil {
			req.Header.Set("content-type", "application/json")
		}
		resp, err := c.http.Do(req)
		if err != nil {
			return err
		}
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusUnauthorized && attempt == 0 {
			c.mu.Lock()
			c.token = ""
			c.mu.Unlock()
			continue
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return &httpError{status: resp.StatusCode, message: fmt.Sprintf("%s %s: %s: %s", method, path, resp.Status, strings.TrimSpace(string(data)))}
		}
		if out == nil {
			return nil
		}
		if err := json.Unmarshal(data, out); err != nil {
			return fmt.Errorf("decode %s %s: %w", method, path, err)
		}
		return nil
	}
}

// httpError carries the status code so a caller can react to a specific
// status (promote_channel creates the channel on 404).
type httpError struct {
	status  int
	message string
}

func (e *httpError) Error() string { return e.message }

func compatBase(org, project string) string {
	return fmt.Sprintf("/packer/2023-01-01/organizations/%s/projects/%s", url.PathEscape(org), url.PathEscape(project))
}

func platformBase(org, project string) string {
	return fmt.Sprintf("/api/v1/organizations/%s/projects/%s", url.PathEscape(org), url.PathEscape(project))
}
