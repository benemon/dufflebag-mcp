package main

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"
)

// testdata/plugin-catalogue.json and plugin-sync-job.json are written by
// dufflebag's platform handlers (TestPluginCatalogueFixtureMatchesTheHandler,
// TestPluginSyncJobFixtureMatchesTheHandler in internal/platform/v1, dufflebag
// e53d1c1). The versions body follows components.schemas.PluginVersion.

const pluginRegistry = "/api/v1/organizations/" + testOrg + "/plugin-registry"

func pluginStub(t *testing.T, exposed bool) (*client, *[]map[string]any) {
	t.Helper()
	catalogue, err := os.ReadFile("testdata/plugin-catalogue.json")
	if err != nil {
		t.Fatal(err)
	}
	job, err := os.ReadFile("testdata/plugin-sync-job.json")
	if err != nil {
		t.Fatal(err)
	}
	var synced []map[string]any
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/organizations/"+testOrg, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"id": testOrg, "name": "acme"})
	})
	mux.HandleFunc("GET "+pluginRegistry, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"enabled": true, "exposed": exposed})
	})
	mux.HandleFunc("GET "+pluginRegistry+"/plugins", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(catalogue)
	})
	mux.HandleFunc("GET "+pluginRegistry+"/plugins/amazon/versions", func(w http.ResponseWriter, r *http.Request) {
		platform := func(os, arch string) map[string]string { return map[string]string{"os": os, "arch": arch} }
		writeJSON(w, map[string]any{"name": "amazon", "source": map[string]any{"kind": "releases-hashicorp"}, "versions": []map[string]any{
			{"version": "1.8.3", "revoked": true, "created_at": "2026-10-09T00:00:00Z",
				"listed_platforms": []any{platform("linux", "amd64")}, "stored_platforms": []any{platform("linux", "amd64")}},
			{"version": "1.8.2", "revoked": false, "created_at": "2026-10-01T00:00:00Z",
				"listed_platforms": []any{platform("linux", "amd64"), platform("darwin", "arm64")}, "stored_platforms": []any{platform("linux", "amd64")}},
		}})
	})
	mux.HandleFunc("GET "+pluginRegistry+"/imports/job-1", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(job)
	})
	mux.HandleFunc("POST "+pluginRegistry+"/sync", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		synced = append(synced, body)
		writeJSON(w, map[string]any{"results": []map[string]any{{"plugin": "amazon", "version": "1.8.3", "import_id": "job-1"}}})
	})
	return testClient(t, mux), &synced
}

func callPluginTool(t *testing.T, c *client, name string, arguments map[string]any) (map[string]any, error) {
	t.Helper()
	params, _ := json.Marshal(map[string]any{"name": name, "arguments": arguments})
	return callTool(c, params)
}

func TestListPluginsReportsUpdatesAndQuietFailures(t *testing.T) {
	c, _ := pluginStub(t, true)
	result, err := callPluginTool(t, c, "list_plugins", nil)
	if err != nil {
		t.Fatal(err)
	}
	text := resultText(t, result)
	var out struct {
		Plugins []map[string]any `json:"plugins"`
	}
	if err := json.Unmarshal([]byte(text), &out); err != nil || len(out.Plugins) != 4 {
		t.Fatalf("plugins = %s", text)
	}
	amazon, docker := out.Plugins[0], out.Plugins[1]
	if amazon["update_available"] != true || amazon["update_check"].(map[string]any)["latest"] != "1.8.3" {
		t.Fatalf("amazon = %v", amazon)
	}
	if docker["update_available"] != false || docker["update_check"].(map[string]any)["last_error"] != "releases.hashicorp.com could not be reached" {
		t.Fatalf("docker = %v", docker)
	}
	if _, checked := out.Plugins[3]["update_check"]; checked {
		t.Fatalf("an upload reported an update check: %v", out.Plugins[3])
	}
}

func TestPluginStanzaNamesTheHostWithoutAPortAndSkipsRevokedVersions(t *testing.T) {
	c, _ := pluginStub(t, false)
	result, err := callPluginTool(t, c, "plugin_stanza", map[string]any{"plugin": "amazon"})
	if err != nil {
		t.Fatal(err)
	}
	text := resultText(t, result)
	if !strings.Contains(text, `source  = "127.0.0.1/plugins/acme/amazon"`) || !strings.Contains(text, `version = "1.8.2"`) {
		t.Fatalf("stanza = %s", text)
	}
	if !strings.Contains(text, "not exposed yet") {
		t.Fatalf("stanza does not warn that the registry is not exposed: %s", text)
	}
	if _, err := callPluginTool(t, c, "plugin_stanza", map[string]any{"plugin": "amazon", "version": "1.8.3"}); err == nil || !strings.Contains(err.Error(), "revoked") {
		t.Fatalf("a revoked version's stanza = %v", err)
	}
	if _, err := callPluginTool(t, c, "plugin_stanza", map[string]any{"plugin": "amazon", "version": "9.9.9"}); err == nil {
		t.Fatal("a stanza for a version that does not exist")
	}
}

func TestPluginVersionsSeparatesHeldFromListedPlatforms(t *testing.T) {
	c, _ := pluginStub(t, true)
	result, err := callPluginTool(t, c, "plugin_versions", map[string]any{"plugin": "amazon"})
	if err != nil {
		t.Fatal(err)
	}
	decoded := resultJSON(t, result)
	second := decoded["versions"].([]any)[1].(map[string]any)
	if second["version"] != "1.8.2" || second["platforms_listed_not_held"].([]any)[0] != "darwin_arm64" || len(second["platforms_held"].([]any)) != 1 {
		t.Fatalf("1.8.2 = %v", second)
	}
}

func TestPluginImportStatusAndSync(t *testing.T) {
	c, synced := pluginStub(t, true)
	result, err := callPluginTool(t, c, "plugin_import_status", map[string]any{"import_id": "job-1"})
	if err != nil {
		t.Fatal(err)
	}
	if text := resultText(t, result); !strings.Contains(text, `"outcome": "restored"`) || !strings.Contains(text, "digest does not match SHA256SUMS") {
		t.Fatalf("import status = %s", text)
	}
	if _, err := callPluginTool(t, c, "sync_plugin_updates", map[string]any{}); err == nil {
		t.Fatal("a sync without plugins was sent")
	}
	if _, err := callPluginTool(t, c, "sync_plugin_updates", map[string]any{"plugins": []string{"amazon"}}); err != nil {
		t.Fatal(err)
	}
	if len(*synced) != 1 || (*synced)[0]["plugins"].([]any)[0] != "amazon" {
		t.Fatalf("sync request = %v", *synced)
	}
	t.Setenv("DFBG_MCP_READ_ONLY", "true")
	if _, err := callPluginTool(t, c, "sync_plugin_updates", map[string]any{"plugins": []string{"amazon"}}); err == nil || !strings.Contains(err.Error(), "read-only") {
		t.Fatalf("read-only sync = %v", err)
	}
}

func TestPluginToolsNeedOnlyAnOrganization(t *testing.T) {
	c, _ := pluginStub(t, true)
	t.Setenv("DFBG_MCP_PROJECT_ID", "")
	if _, err := callPluginTool(t, c, "plugin_registry_status", nil); err != nil {
		t.Fatalf("a plugin tool required a project: %v", err)
	}
	t.Setenv("DFBG_MCP_ORGANIZATION_ID", "")
	if _, err := callPluginTool(t, c, "list_plugins", nil); err == nil || !strings.Contains(err.Error(), "organization_id is required") {
		t.Fatalf("no organization = %v", err)
	}
}
