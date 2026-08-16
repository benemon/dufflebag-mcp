package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

// The tests drive the tool handlers against a stub registry: an httptest
// server answering the exact compat- and platform-plane paths the client
// calls, with canned bodies. The stdio framing in main.go is thin enough
// that the handler layer is the surface worth pinning.

const (
	testOrg     = "org-1"
	testProject = "proj-1"
)

func testClient(t *testing.T, mux *http.ServeMux) *client {
	t.Helper()
	mux.HandleFunc("POST /oauth2/token", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "test-token", "expires_in": 600})
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	t.Setenv("DFBG_MCP_ORGANIZATION_ID", testOrg)
	t.Setenv("DFBG_MCP_PROJECT_ID", testProject)
	return &client{endpoint: server.URL, clientID: "id", clientSecret: "secret", http: server.Client()}
}

func compatPath(rest string) string {
	return "/packer/2023-01-01/organizations/" + testOrg + "/projects/" + testProject + rest
}

// resultText unwraps the MCP content envelope every handler returns.
func resultText(t *testing.T, result map[string]any) string {
	t.Helper()
	content, ok := result["content"].([]map[string]any)
	if !ok || len(content) == 0 {
		t.Fatalf("result has no content: %#v", result)
	}
	text, _ := content[0]["text"].(string)
	return text
}

func resultJSON(t *testing.T, result map[string]any) map[string]any {
	t.Helper()
	var decoded map[string]any
	if err := json.Unmarshal([]byte(resultText(t, result)), &decoded); err != nil {
		t.Fatalf("result is not JSON: %v\n%s", err, resultText(t, result))
	}
	return decoded
}

func writeJSON(w http.ResponseWriter, v any) {
	_ = json.NewEncoder(w).Encode(v)
}

// demoVersions is the canonical two-version bucket: v2 newest with a changed
// digest, v1 assigned to the release channel.
func demoVersions() map[string]any {
	return map[string]any{"versions": []map[string]any{
		{
			"name": "v2", "fingerprint": "fp-v2", "status": "VERSION_ACTIVE",
			"builds": []map[string]any{{
				"id": "b2", "component_type": "docker.distro", "status": "BUILD_DONE", "platform": "docker",
				"artifacts": []map[string]any{{"external_identifier": "sha256:new", "region": "docker"}},
			}},
		},
		{
			"name": "v1", "fingerprint": "fp-v1", "status": "VERSION_ACTIVE",
			"builds": []map[string]any{{
				"id": "b1", "component_type": "docker.distro", "status": "BUILD_DONE", "platform": "docker",
				"artifacts": []map[string]any{{"external_identifier": "sha256:old", "region": "docker"}},
			}},
		},
	}}
}

func TestConsumeSnippetHonoursChannel(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+compatPath("/buckets/demo/versions"), func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, demoVersions())
	})
	mux.HandleFunc("GET "+compatPath("/buckets/demo/channels/release"), func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"channel": map[string]any{"name": "release", "version": map[string]any{"fingerprint": "fp-v1"}}})
	})
	c := testClient(t, mux)

	result, err := consumeSnippet(c, json.RawMessage(`{"bucket":"demo","flavor":"terraform","channel":"release"}`))
	if err != nil {
		t.Fatalf("terraform snippet: %v", err)
	}
	snippet := resultText(t, result)
	// The regression this pins: the snippet must carry the channel's assigned
	// fingerprint, never the bucket's newest.
	if !strings.Contains(snippet, `version_fingerprint = "fp-v1"`) {
		t.Fatalf("snippet does not pin the release fingerprint:\n%s", snippet)
	}
	if strings.Contains(snippet, "fp-v2") {
		t.Fatalf("snippet leaked the newest fingerprint:\n%s", snippet)
	}

	result, err = consumeSnippet(c, json.RawMessage(`{"bucket":"demo","flavor":"aws","channel":"release"}`))
	if err != nil {
		t.Fatalf("aws fallback: %v", err)
	}
	if fallback := resultText(t, result); !strings.Contains(fallback, "no aws artifacts on version v1") {
		t.Fatalf("aws fallback names the wrong version: %s", fallback)
	}
}

func TestConsumeSnippetExplicitFingerprintAndErrors(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+compatPath("/buckets/demo/versions"), func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, demoVersions())
	})
	mux.HandleFunc("GET "+compatPath("/buckets/demo/channels/empty"), func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"channel": map[string]any{"name": "empty"}})
	})
	c := testClient(t, mux)

	result, err := consumeSnippet(c, json.RawMessage(`{"bucket":"demo","flavor":"docker","fingerprint":"fp-v2"}`))
	if err != nil {
		t.Fatalf("fingerprint override: %v", err)
	}
	if text := resultText(t, result); !strings.Contains(text, "sha256:new") {
		t.Fatalf("docker snippet missed the v2 digest: %s", text)
	}

	if _, err := consumeSnippet(c, json.RawMessage(`{"bucket":"demo","channel":"empty"}`)); err == nil || !strings.Contains(err.Error(), "no assigned version") {
		t.Fatalf("unassigned channel should be an explicit error, got %v", err)
	}
	if _, err := consumeSnippet(c, json.RawMessage(`{"bucket":"demo","flavor":"gcp","fingerprint":"fp-v1"}`)); err == nil || !strings.Contains(err.Error(), "unknown flavor") {
		t.Fatalf("unknown flavor should refuse, got %v", err)
	}
}

func TestVersionDiffComparesArtifactDigests(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+compatPath("/buckets/demo/versions"), func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, demoVersions())
	})
	c := testClient(t, mux)

	result, err := versionDiff(c, json.RawMessage(`{"bucket":"demo","fingerprint_a":"fp-v1","fingerprint_b":"fp-v2"}`))
	if err != nil {
		t.Fatalf("version_diff: %v", err)
	}
	decoded := resultJSON(t, result)
	builds := decoded["builds"].(map[string]any)
	// The regression this pins: same build shape, different digest, must
	// report changed — and the arrays serialize as [], not null.
	changed, ok := builds["changed"].([]any)
	if !ok || len(changed) != 1 || changed[0] != "docker/docker.distro" {
		t.Fatalf("digest change not detected: %#v", builds)
	}
	if _, ok := builds["added_in_b"].([]any); !ok {
		t.Fatalf("added_in_b is not an array: %#v", builds)
	}
}

func TestResolveChannelRevocation(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+compatPath("/buckets/demo/channels/release"), func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"channel": map[string]any{
			"name": "release",
			"version": map[string]any{
				"name": "v1", "fingerprint": "fp-v1", "status": "VERSION_REVOKED",
				"revoke_at": "2026-01-01T00:00:00Z", "revocation_message": "compromised base image",
			},
		}})
	})
	c := testClient(t, mux)

	decoded := resultJSON(t, mustCall(t, resolveChannel, c, `{"bucket":"demo","channel":"release"}`))
	if decoded["safe_to_consume"] != false {
		t.Fatalf("revoked version reported safe: %#v", decoded)
	}
	if reason, _ := decoded["reason"].(string); !strings.Contains(reason, "compromised base image") {
		t.Fatalf("revocation reason not surfaced: %#v", decoded)
	}
}

func TestPromoteChannelLifecycle(t *testing.T) {
	var patched, created bool
	mux := http.NewServeMux()
	mux.HandleFunc("PATCH "+compatPath("/buckets/demo/channels/staging"), func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["update_mask"] != "versionFingerprint" || body["version_fingerprint"] != "fp-v1" {
			t.Errorf("unexpected PATCH body: %v", body)
		}
		patched = true
		writeJSON(w, map[string]any{"channel": map[string]any{"name": "staging", "version": map[string]any{"name": "v1", "fingerprint": "fp-v1"}}})
	})
	mux.HandleFunc("PATCH "+compatPath("/buckets/demo/channels/ghost"), func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"code":5,"message":"does not exist"}`, http.StatusNotFound)
	})
	mux.HandleFunc("POST "+compatPath("/buckets/demo/channels"), func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["name"] != "ghost" || body["version_fingerprint"] != "fp-v2" {
			t.Errorf("unexpected create body: %v", body)
		}
		created = true
		writeJSON(w, map[string]any{"channel": map[string]any{"name": "ghost", "version": map[string]any{"name": "v2", "fingerprint": "fp-v2"}}})
	})
	mux.HandleFunc("PATCH "+compatPath("/buckets/demo/channels/latest"), func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"code":9,"message":"This channel is managed by Dufflebag"}`, http.StatusBadRequest)
	})
	c := testClient(t, mux)

	decoded := resultJSON(t, mustCall(t, promoteChannel, c, `{"bucket":"demo","channel":"staging","fingerprint":"fp-v1"}`))
	if !patched || decoded["created"] != false || decoded["fingerprint"] != "fp-v1" {
		t.Fatalf("existing-channel promote wrong: %#v", decoded)
	}

	decoded = resultJSON(t, mustCall(t, promoteChannel, c, `{"bucket":"demo","channel":"ghost","fingerprint":"fp-v2","create_if_missing":true}`))
	if !created || decoded["created"] != true {
		t.Fatalf("create_if_missing did not create: %#v", decoded)
	}

	if _, err := promoteChannel(c, json.RawMessage(`{"bucket":"demo","channel":"ghost","fingerprint":"fp-v2"}`)); err == nil || !strings.Contains(err.Error(), "404") {
		t.Fatalf("missing channel without create_if_missing should surface 404, got %v", err)
	}
	if _, err := promoteChannel(c, json.RawMessage(`{"bucket":"demo","channel":"latest","fingerprint":"fp-v1"}`)); err == nil || !strings.Contains(err.Error(), "managed") {
		t.Fatalf("managed channel refusal not surfaced, got %v", err)
	}
	if _, err := promoteChannel(c, json.RawMessage(`{"bucket":"demo","channel":"staging"}`)); err == nil || !strings.Contains(err.Error(), "fingerprint") {
		t.Fatalf("missing fingerprint must refuse, got %v", err)
	}
}

func TestReadOnlyPosture(t *testing.T) {
	t.Setenv("DFBG_MCP_READ_ONLY", "true")

	defs := toolDefinitions()
	if len(defs) != 14 {
		t.Fatalf("read-only listing has %d tools, want 14", len(defs))
	}
	for _, def := range defs {
		if writeTools[def["name"].(string)] {
			t.Fatalf("write tool %q listed under read-only posture", def["name"])
		}
	}

	params, _ := json.Marshal(map[string]any{"name": "promote_channel", "arguments": map[string]any{}})
	if _, err := callTool(nil, params); err == nil || !strings.Contains(err.Error(), "read-only") {
		t.Fatalf("read-only dispatch should refuse writes, got %v", err)
	}
}

func TestToolDefinitionsComplete(t *testing.T) {
	defs := toolDefinitions()
	if len(defs) != 17 {
		t.Fatalf("full listing has %d tools, want 17", len(defs))
	}
	for _, def := range defs {
		name := def["name"].(string)
		if _, ok := toolHandlers[name]; !ok {
			t.Fatalf("tool %q listed without a handler", name)
		}
	}
	if len(toolHandlers) != len(defs) {
		t.Fatalf("%d handlers for %d listed tools", len(toolHandlers), len(defs))
	}
}

func TestWhoamiResolvesDefaults(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/self", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"principal_id": "p-1", "name": "initial administrator", "role": "root"})
	})
	mux.HandleFunc("GET /api/v1/organizations/"+testOrg, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"id": testOrg, "name": "demo-organisation"})
	})
	mux.HandleFunc("GET /api/v1/organizations/"+testOrg+"/projects/"+testProject, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"id": testProject, "name": "demo-project"})
	})
	c := testClient(t, mux)

	decoded := resultJSON(t, mustCall(t, whoami, c, `{}`))
	if decoded["role"] != "root" || decoded["read_only"] != false {
		t.Fatalf("whoami basics wrong: %#v", decoded)
	}
	if _, bound := decoded["organization_id"]; bound {
		t.Fatalf("platform-scoped principal must not report a bound organization: %#v", decoded)
	}
	org := decoded["default_organization"].(map[string]any)
	if org["name"] != "demo-organisation" {
		t.Fatalf("default organization name not resolved: %#v", decoded)
	}
}

func TestFindArtifactEnumerates(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+compatPath("/buckets"), func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"buckets": []map[string]any{{"name": "demo"}, {"name": "other"}}})
	})
	mux.HandleFunc("GET "+compatPath("/buckets/demo/versions"), func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, demoVersions())
	})
	mux.HandleFunc("GET "+compatPath("/buckets/other/versions"), func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"versions": []map[string]any{}})
	})
	c := testClient(t, mux)

	decoded := resultJSON(t, mustCall(t, findArtifact, c, `{"external_identifier":"sha256:old"}`))
	matches := decoded["matches"].([]any)
	if len(matches) != 1 {
		t.Fatalf("want one match, got %#v", decoded)
	}
	match := matches[0].(map[string]any)
	if match["bucket"] != "demo" || match["version"] != "v1" {
		t.Fatalf("wrong match: %#v", match)
	}
	if decoded["buckets_searched"] != float64(2) {
		t.Fatalf("enumeration honesty missing: %#v", decoded)
	}

	decoded = resultJSON(t, mustCall(t, findArtifact, c, `{"external_identifier":"sha256:absent"}`))
	if len(decoded["matches"].([]any)) != 0 {
		t.Fatalf("absent digest matched: %#v", decoded)
	}
}

func TestListVulnerabilitiesFiltersAndTruncation(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+compatPath("/buckets/demo/vulnerabilities"), func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("criticality") != "critical" || q.Get("pagination.page_size") != "2" {
			t.Errorf("filters not forwarded: %v", q)
		}
		writeJSON(w, map[string]any{
			"vulnerabilities": []map[string]any{{
				"vulnerability":     map[string]any{"identifier": "CVE-1", "criticality": "critical", "fixed_version": "1.2.3"},
				"impacted_packages": []map[string]any{{"name": "libc6", "version": "2.31"}},
				"impacted_channels": []map[string]any{{"name": "release"}},
			}},
			"pagination": map[string]any{"next_page_token": "more"},
		})
	})
	c := testClient(t, mux)

	decoded := resultJSON(t, mustCall(t, listVulnerabilities, c, `{"bucket":"demo","criticality":"critical","limit":2}`))
	vulnerabilities := decoded["vulnerabilities"].([]any)
	entry := vulnerabilities[0].(map[string]any)
	if entry["fixed_version"] != "1.2.3" {
		t.Fatalf("fixed version dropped: %#v", entry)
	}
	if _, truncated := decoded["truncated"]; !truncated {
		t.Fatalf("truncation marker missing with next_page_token set: %#v", decoded)
	}
}

func TestCheckAncestryProjection(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+compatPath("/buckets/child/ancestry"), func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("type") != "ANCESTRY_TYPE_PARENTS" {
			t.Errorf("direction not mapped: %v", r.URL.Query())
		}
		writeJSON(w, map[string]any{
			"relations": []map[string]any{{
				"parent": map[string]any{
					"bucket_name": "base", "channel_name": "latest", "version_name": "v1", "version_fingerprint": "fp-base-v1",
					"channel_version": map[string]any{"name": "v3", "fingerprint": "fp-base-v3"},
				},
				"child":  map[string]any{"bucket_name": "child", "version_name": "v1", "version_fingerprint": "fp-child-v1"},
				"status": "OUT_OF_DATE",
			}},
			"total_count": 1,
		})
	})
	c := testClient(t, mux)

	decoded := resultJSON(t, mustCall(t, checkAncestry, c, `{"bucket":"child","direction":"parents"}`))
	relation := decoded["relations"].([]any)[0].(map[string]any)
	parent := relation["parent"].(map[string]any)
	drift := parent["channel_now_serves"].(map[string]any)
	if relation["status"] != "OUT_OF_DATE" || drift["version"] != "v3" {
		t.Fatalf("parent drift not projected: %#v", relation)
	}

	if _, err := checkAncestry(c, json.RawMessage(`{"bucket":"child","direction":"sideways"}`)); err == nil {
		t.Fatalf("invalid direction must refuse")
	}
}

func TestClientRetriesOnceOn401(t *testing.T) {
	var calls, mints int
	mux := http.NewServeMux()
	mux.HandleFunc("POST /oauth2/token", func(w http.ResponseWriter, r *http.Request) {
		mints++
		writeJSON(w, map[string]any{"access_token": "token", "expires_in": 600})
	})
	mux.HandleFunc("GET /api/v1/self", func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			http.Error(w, "expired", http.StatusUnauthorized)
			return
		}
		writeJSON(w, map[string]any{"principal_id": "p-1", "name": "n", "role": "root"})
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	c := &client{endpoint: server.URL, clientID: "id", clientSecret: "secret", http: server.Client()}

	var out struct {
		Role string `json:"role"`
	}
	if err := c.call("GET", "/api/v1/self", nil, &out); err != nil {
		t.Fatalf("401 retry failed: %v", err)
	}
	if calls != 2 || mints != 2 {
		t.Fatalf("want one retry with a fresh mint, got calls=%d mints=%d", calls, mints)
	}

	if err := c.call("GET", "/missing", nil, nil); err == nil {
		t.Fatalf("non-2xx must error")
	} else {
		var httpErr *httpError
		if !errors.As(err, &httpErr) || httpErr.status != http.StatusNotFound {
			t.Fatalf("want httpError 404, got %T %v", err, err)
		}
	}
}

func mustCall(t *testing.T, handler func(*client, json.RawMessage) (map[string]any, error), c *client, args string) map[string]any {
	t.Helper()
	result, err := handler(c, json.RawMessage(args))
	if err != nil {
		t.Fatalf("handler failed: %v", err)
	}
	return result
}

func TestListBucketsCompactProjection(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+compatPath("/buckets"), func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"buckets": []map[string]any{
			{
				"name": "demo", "platforms": []string{"docker"}, "updated_at": "2026-08-16T00:00:00Z",
				"latest_version": map[string]any{
					"name": "v2", "fingerprint": "fp-v2", "status": "VERSION_ACTIVE",
					"builds": []map[string]any{{"id": "b2", "labels": map[string]string{"huge": "metadata"}}},
				},
				"parents": map[string]any{"status": "OUT_OF_DATE"},
			},
			{"name": "empty-bucket", "platforms": []string{}, "updated_at": "2026-08-16T00:00:00Z"},
		}})
	})
	c := testClient(t, mux)

	decoded := resultJSON(t, mustCall(t, listBuckets, c, `{}`))
	buckets := decoded["buckets"].([]any)
	if len(buckets) != 2 {
		t.Fatalf("want 2 buckets, got %#v", decoded)
	}
	first := buckets[0].(map[string]any)
	latest := first["latest"].(map[string]any)
	if latest["version"] != "v2" || latest["revoked"] != false || first["ancestry"] != "OUT_OF_DATE" {
		t.Fatalf("projection wrong: %#v", first)
	}
	// The projection's whole point: build detail must not pass through.
	if strings.Contains(resultText(t, mustCall(t, listBuckets, c, `{}`)), "huge") {
		t.Fatalf("build metadata leaked through the projection")
	}
	second := buckets[1].(map[string]any)
	if _, ok := second["latest"]; ok {
		t.Fatalf("version-less bucket must omit latest: %#v", second)
	}
}

func TestVulnerabilitySummaryProjection(t *testing.T) {
	packages := []map[string]any{
		{"package_name": "libc6", "package_version": "2.31", "criticality": "critical", "vulnerability_count": "6"},
		{"package_name": "libc6", "package_version": "2.31", "criticality": "high", "vulnerability_count": "20"},
		{"package_name": "bzip2", "package_version": "1.0.8", "criticality": "medium", "vulnerability_count": "2"},
	}
	for i := 0; i < 16; i++ {
		packages = append(packages, map[string]any{
			"package_name": "filler-" + strconv.Itoa(i), "package_version": "1",
			"criticality": "low", "vulnerability_count": "1",
		})
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+compatPath("/buckets/demo/packages/vulnerability-summary"), func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{
			"total_by_criticality": []map[string]any{
				{"criticality": "high", "vulnerability_count": "106"},
				{"criticality": "critical", "vulnerability_count": "46"},
			},
			"packages_by_criticality": packages,
		})
	})
	c := testClient(t, mux)

	decoded := resultJSON(t, mustCall(t, vulnerabilitySummary, c, `{"bucket":"demo"}`))
	totals := decoded["total_by_criticality"].([]any)
	if totals[0].(map[string]any)["criticality"] != "critical" {
		t.Fatalf("totals not ordered worst-first: %#v", totals)
	}
	worst := decoded["worst_packages"].([]any)
	if len(worst) != summaryPackageCap {
		t.Fatalf("cap not applied: %d rows", len(worst))
	}
	top := worst[0].(map[string]any)
	if top["package"] != "libc6 2.31" || top["total"] != float64(26) {
		t.Fatalf("aggregation wrong: %#v", top)
	}
	omitted, _ := decoded["omitted"].(string)
	if !strings.Contains(omitted, "3 more packages") {
		t.Fatalf("omission not explicit: %#v", decoded)
	}
}
