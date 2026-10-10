package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"sort"
	"strings"
)

// Plugin registry tools are organization-scoped: the registry belongs to an
// organization, so they take no project.

var organizationProperty = map[string]any{"organization_id": tenancyProperties["organization_id"]}

func organizationSchema(extra map[string]any, required ...string) map[string]any {
	properties := map[string]any{}
	for k, v := range organizationProperty {
		properties[k] = v
	}
	for k, v := range extra {
		properties[k] = v
	}
	s := map[string]any{"type": "object", "properties": properties}
	if len(required) > 0 {
		s["required"] = required
	}
	return s
}

func pluginToolDefinitions() []map[string]any {
	plugin := map[string]any{"type": "string", "description": "Plugin name, as in its source address (amazon, git)"}
	return []map[string]any{
		{
			"name":        "plugin_registry_status",
			"description": "Whether the organization's plugin registry is enabled and exposed, and the source address prefix Packer templates use.",
			"inputSchema": organizationSchema(nil),
		},
		{
			"name":        "list_plugins",
			"description": "The organization's plugins: source, newest available version, and whether an update check has seen a newer release.",
			"inputSchema": organizationSchema(nil),
		},
		{
			"name":        "plugin_versions",
			"description": "A plugin's versions, newest first: revoked or served, and per platform whether its zip is held or only listed in SHA256SUMS.",
			"inputSchema": organizationSchema(map[string]any{"plugin": plugin}, "plugin"),
		},
		{
			"name":        "plugin_stanza",
			"description": "The packer required_plugins stanza that installs a plugin version from dufflebag. Omit version for the newest one not revoked.",
			"inputSchema": organizationSchema(map[string]any{
				"plugin":  plugin,
				"version": map[string]any{"type": "string"},
			}, "plugin"),
		},
		{
			"name":        "plugin_import_status",
			"description": "An import or sync job's state and its outcome per version or change.",
			"inputSchema": organizationSchema(map[string]any{"import_id": map[string]any{"type": "string"}}, "import_id"),
		},
		{
			"name":        "sync_plugin_updates",
			"description": "Bring plugins with an update available up to their newest stable release, one import job each, with the platforms each already has. Requires publisher authority; plugins without an update are refused individually.",
			"inputSchema": organizationSchema(map[string]any{
				"plugins": map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "Plugin names, as list_plugins reports them"},
			}, "plugins"),
		},
	}
}

type organizationArgs struct {
	OrganizationID string `json:"organization_id"`
}

func (o *organizationArgs) resolve() error {
	if o.OrganizationID == "" {
		o.OrganizationID = os.Getenv("DFBG_MCP_ORGANIZATION_ID")
	}
	if o.OrganizationID == "" {
		return fmt.Errorf("organization_id is required (or set DFBG_MCP_ORGANIZATION_ID)")
	}
	return nil
}

func registryPath(organizationID, suffix string) string {
	return "/api/v1/organizations/" + url.PathEscape(organizationID) + "/plugin-registry" + suffix
}

// Packer refuses a port in a plugin source address, so the stanza names the
// endpoint's host alone.
func (c *client) pluginHost() string {
	parsed, err := url.Parse(c.endpoint)
	if err != nil {
		return c.endpoint
	}
	if host, _, err := net.SplitHostPort(parsed.Host); err == nil {
		return host
	}
	return parsed.Host
}

func (c *client) organizationName(organizationID string) (string, error) {
	var organization struct {
		Name string `json:"name"`
	}
	if err := c.call("GET", "/api/v1/organizations/"+url.PathEscape(organizationID), nil, &organization); err != nil {
		return "", err
	}
	return organization.Name, nil
}

type wireRegistry struct {
	Enabled bool `json:"enabled"`
	Exposed bool `json:"exposed"`
}

func pluginRegistryStatus(c *client, args json.RawMessage) (map[string]any, error) {
	var in organizationArgs
	_ = json.Unmarshal(args, &in)
	if err := in.resolve(); err != nil {
		return nil, err
	}
	var registry wireRegistry
	if err := c.call("GET", registryPath(in.OrganizationID, ""), nil, &registry); err != nil {
		return nil, err
	}
	name, err := c.organizationName(in.OrganizationID)
	if err != nil {
		return nil, err
	}
	result := map[string]any{"enabled": registry.Enabled, "exposed": registry.Exposed, "source_prefix": c.pluginHost() + "/plugins/" + name}
	if registry.Enabled && !registry.Exposed {
		result["note"] = "Packer cannot install from the registry until a maintainer exposes it."
	}
	return textResult(result)
}

type wirePlugin struct {
	Name   string `json:"name"`
	Source struct {
		Kind       string `json:"kind"`
		Repository string `json:"repository,omitempty"`
	} `json:"source"`
	PublishedVersions int    `json:"published_versions"`
	NewestVersion     string `json:"newest_version,omitempty"`
	UpdateCheck       struct {
		Enabled   bool   `json:"enabled"`
		CheckedAt string `json:"checked_at,omitempty"`
		Error     string `json:"error,omitempty"`
		Latest    string `json:"latest,omitempty"`
	} `json:"update_check"`
	UpdateAvailable bool `json:"update_available"`
}

func listPlugins(c *client, args json.RawMessage) (map[string]any, error) {
	var in organizationArgs
	_ = json.Unmarshal(args, &in)
	if err := in.resolve(); err != nil {
		return nil, err
	}
	var out struct {
		Plugins []wirePlugin `json:"plugins"`
	}
	if err := c.call("GET", registryPath(in.OrganizationID, "/plugins"), nil, &out); err != nil {
		return nil, err
	}
	plugins := make([]map[string]any, 0, len(out.Plugins))
	for _, p := range out.Plugins {
		entry := map[string]any{
			"name": p.Name, "source": p.Source, "published_versions": p.PublishedVersions,
			"newest_version": p.NewestVersion, "update_available": p.UpdateAvailable,
		}
		if p.UpdateCheck.Enabled {
			check := map[string]any{"checked_at": p.UpdateCheck.CheckedAt, "latest": p.UpdateCheck.Latest}
			if p.UpdateCheck.Error != "" {
				check["last_error"] = p.UpdateCheck.Error
			}
			entry["update_check"] = check
		}
		plugins = append(plugins, entry)
	}
	return textResult(map[string]any{"plugins": plugins})
}

type wirePluginVersion struct {
	Version         string `json:"version"`
	Revoked         bool   `json:"revoked"`
	CreatedAt       string `json:"created_at"`
	ListedPlatforms []struct {
		OS   string `json:"os"`
		Arch string `json:"arch"`
	} `json:"listed_platforms"`
	StoredPlatforms []struct {
		OS   string `json:"os"`
		Arch string `json:"arch"`
	} `json:"stored_platforms"`
}

type pluginArgs struct {
	organizationArgs
	Plugin  string `json:"plugin"`
	Version string `json:"version"`
}

func (c *client) pluginVersions(in pluginArgs) ([]wirePluginVersion, error) {
	var out struct {
		Versions []wirePluginVersion `json:"versions"`
	}
	err := c.call("GET", registryPath(in.OrganizationID, "/plugins/"+url.PathEscape(in.Plugin)+"/versions"), nil, &out)
	return out.Versions, err
}

func decodePluginArgs(args json.RawMessage) (pluginArgs, error) {
	var in pluginArgs
	_ = json.Unmarshal(args, &in)
	if err := in.resolve(); err != nil {
		return in, err
	}
	if in.Plugin == "" {
		return in, fmt.Errorf("plugin is required")
	}
	return in, nil
}

func pluginVersions(c *client, args json.RawMessage) (map[string]any, error) {
	in, err := decodePluginArgs(args)
	if err != nil {
		return nil, err
	}
	versions, err := c.pluginVersions(in)
	if err != nil {
		return nil, err
	}
	rendered := make([]map[string]any, 0, len(versions))
	for _, v := range versions {
		held := map[string]bool{}
		platforms := []string{}
		for _, p := range v.StoredPlatforms {
			held[p.OS+"_"+p.Arch] = true
			platforms = append(platforms, p.OS+"_"+p.Arch)
		}
		listedOnly := []string{}
		for _, p := range v.ListedPlatforms {
			if !held[p.OS+"_"+p.Arch] {
				listedOnly = append(listedOnly, p.OS+"_"+p.Arch)
			}
		}
		sort.Strings(platforms)
		sort.Strings(listedOnly)
		rendered = append(rendered, map[string]any{
			"version": v.Version, "revoked": v.Revoked, "created_at": v.CreatedAt,
			"platforms_held": platforms, "platforms_listed_not_held": listedOnly,
		})
	}
	return textResult(map[string]any{"plugin": in.Plugin, "versions": rendered})
}

func pluginStanza(c *client, args json.RawMessage) (map[string]any, error) {
	in, err := decodePluginArgs(args)
	if err != nil {
		return nil, err
	}
	versions, err := c.pluginVersions(in)
	if err != nil {
		return nil, err
	}
	version := in.Version
	for _, v := range versions {
		if version == "" && !v.Revoked {
			version = v.Version
		}
		if v.Version == version && v.Revoked {
			return nil, fmt.Errorf("%s %s is revoked: Packer gets 404 for it until it is restored", in.Plugin, version)
		}
	}
	if version == "" {
		return nil, fmt.Errorf("%s has no version that is not revoked", in.Plugin)
	}
	found := false
	for _, v := range versions {
		found = found || v.Version == version
	}
	if !found {
		return nil, fmt.Errorf("%s has no version %s", in.Plugin, version)
	}
	name, err := c.organizationName(in.OrganizationID)
	if err != nil {
		return nil, err
	}
	var registry wireRegistry
	if err := c.call("GET", registryPath(in.OrganizationID, ""), nil, &registry); err != nil {
		return nil, err
	}
	source := c.pluginHost() + "/plugins/" + name + "/" + in.Plugin
	var hcl strings.Builder
	fmt.Fprintf(&hcl, "packer {\n  required_plugins {\n    %s = {\n      source  = %q\n      version = %q\n    }\n  }\n}\n", in.Plugin, source, version)
	text := hcl.String()
	if !registry.Exposed {
		text += "\n# The registry is not exposed yet: packer init cannot resolve this source until a maintainer exposes it.\n"
	}
	return plainResult(text), nil
}

func pluginImportStatus(c *client, args json.RawMessage) (map[string]any, error) {
	var in struct {
		organizationArgs
		ImportID string `json:"import_id"`
	}
	_ = json.Unmarshal(args, &in)
	if err := in.resolve(); err != nil {
		return nil, err
	}
	if in.ImportID == "" {
		return nil, fmt.Errorf("import_id is required")
	}
	var out json.RawMessage
	if err := c.call("GET", registryPath(in.OrganizationID, "/imports/"+url.PathEscape(in.ImportID)), nil, &out); err != nil {
		return nil, err
	}
	return textResult(out)
}

func syncPluginUpdates(c *client, args json.RawMessage) (map[string]any, error) {
	var in struct {
		organizationArgs
		Plugins []string `json:"plugins"`
	}
	_ = json.Unmarshal(args, &in)
	if err := in.resolve(); err != nil {
		return nil, err
	}
	if len(in.Plugins) == 0 {
		return nil, fmt.Errorf("plugins is required: name the plugins to update, as list_plugins reports them")
	}
	var out json.RawMessage
	if err := c.call("POST", registryPath(in.OrganizationID, "/sync"), map[string]any{"plugins": in.Plugins}, &out); err != nil {
		return nil, err
	}
	return textResult(out)
}
