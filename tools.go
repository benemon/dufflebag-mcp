package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strings"
)

// Tenancy arguments fall back to the optional environment defaults so a
// server registered against one project does not need them repeated on
// every call.
type tenancyArgs struct {
	OrganizationID string `json:"organization_id"`
	ProjectID      string `json:"project_id"`
}

func (t *tenancyArgs) resolve() error {
	if t.OrganizationID == "" {
		t.OrganizationID = os.Getenv("DUFFLEBAG_MCP_ORGANIZATION_ID")
	}
	if t.ProjectID == "" {
		t.ProjectID = os.Getenv("DUFFLEBAG_MCP_PROJECT_ID")
	}
	if t.OrganizationID == "" || t.ProjectID == "" {
		return fmt.Errorf("organization_id and project_id are required (or set DUFFLEBAG_MCP_ORGANIZATION_ID / DUFFLEBAG_MCP_PROJECT_ID)")
	}
	return nil
}

var tenancyProperties = map[string]any{
	"organization_id": map[string]any{"type": "string", "description": "Organization id (falls back to DUFFLEBAG_MCP_ORGANIZATION_ID)"},
	"project_id":      map[string]any{"type": "string", "description": "Project id (falls back to DUFFLEBAG_MCP_PROJECT_ID)"},
}

func schema(extra map[string]any, required ...string) map[string]any {
	properties := map[string]any{}
	for k, v := range tenancyProperties {
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

func toolDefinitions() []map[string]any {
	return []map[string]any{
		{
			"name":        "list_organizations",
			"description": "List the organizations the credential can see.",
			"inputSchema": map[string]any{"type": "object", "properties": map[string]any{}},
		},
		{
			"name":        "create_organization",
			"description": "Create an organization. Requires a credential with platform authority.",
			"inputSchema": map[string]any{"type": "object", "properties": map[string]any{"name": map[string]any{"type": "string"}}, "required": []string{"name"}},
		},
		{
			"name":        "list_projects",
			"description": "List an organization's projects.",
			"inputSchema": map[string]any{"type": "object", "properties": map[string]any{"organization_id": tenancyProperties["organization_id"]}, "required": []string{"organization_id"}},
		},
		{
			"name":        "create_project",
			"description": "Create a project in an organization.",
			"inputSchema": map[string]any{"type": "object", "properties": map[string]any{"organization_id": tenancyProperties["organization_id"], "name": map[string]any{"type": "string"}}, "required": []string{"organization_id", "name"}},
		},
		{
			"name":        "list_buckets",
			"description": "List a project's registry buckets with their latest version and platforms.",
			"inputSchema": schema(nil),
		},
		{
			"name":        "list_versions",
			"description": "List a bucket's versions, newest first, with builds and artifacts.",
			"inputSchema": schema(map[string]any{"bucket": map[string]any{"type": "string"}}, "bucket"),
		},
		{
			"name":        "list_channels",
			"description": "List a bucket's channels and their assigned versions.",
			"inputSchema": schema(map[string]any{"bucket": map[string]any{"type": "string"}}, "bucket"),
		},
		{
			"name":        "resolve_channel",
			"description": "Resolve a channel to its assigned version and report whether it is safe to consume (revocation state).",
			"inputSchema": schema(map[string]any{"bucket": map[string]any{"type": "string"}, "channel": map[string]any{"type": "string"}}, "bucket", "channel"),
		},
		{
			"name":        "version_diff",
			"description": "Summarize what changed between two versions of a bucket (builds, platforms, artifacts, revocation).",
			"inputSchema": schema(map[string]any{
				"bucket":        map[string]any{"type": "string"},
				"fingerprint_a": map[string]any{"type": "string"},
				"fingerprint_b": map[string]any{"type": "string"},
			}, "bucket", "fingerprint_a", "fingerprint_b"),
		},
		{
			"name":        "vulnerability_summary",
			"description": "The bucket's package vulnerability summary as reported by the registry's scanner.",
			"inputSchema": schema(map[string]any{"bucket": map[string]any{"type": "string"}}, "bucket"),
		},
		{
			"name":        "bagdrop_status",
			"description": "Bag Drop mirror status for the project: configuration, cadence, per-bucket sync state.",
			"inputSchema": schema(nil),
		},
		{
			"name":        "consume_snippet",
			"description": "Ready-to-paste consumption for a version: flavor 'terraform' (always available), 'docker' or 'aws' (only when that platform was built). Terraform is the fallback for every other platform.",
			"inputSchema": schema(map[string]any{
				"bucket":      map[string]any{"type": "string"},
				"fingerprint": map[string]any{"type": "string", "description": "Version fingerprint; omit to use the channel's assignment"},
				"channel":     map[string]any{"type": "string", "description": "Channel to resolve when no fingerprint is given (default latest)"},
				"flavor":      map[string]any{"type": "string", "enum": []string{"terraform", "docker", "aws"}},
			}, "bucket"),
		},
	}
}

func callTool(c *client, params json.RawMessage) (map[string]any, error) {
	var call struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(params, &call); err != nil {
		return nil, fmt.Errorf("decode tool call: %w", err)
	}
	args := call.Arguments
	if len(args) == 0 {
		args = json.RawMessage("{}")
	}
	handler, ok := toolHandlers[call.Name]
	if !ok {
		return nil, fmt.Errorf("unknown tool %q", call.Name)
	}
	return handler(c, args)
}

var toolHandlers = map[string]func(*client, json.RawMessage) (map[string]any, error){
	"list_organizations":    listOrganizations,
	"create_organization":   createOrganization,
	"list_projects":         listProjects,
	"create_project":        createProject,
	"list_buckets":          listBuckets,
	"list_versions":         listVersions,
	"list_channels":         listChannels,
	"resolve_channel":       resolveChannel,
	"version_diff":          versionDiff,
	"vulnerability_summary": vulnerabilitySummary,
	"bagdrop_status":        bagdropStatus,
	"consume_snippet":       consumeSnippet,
}

func textResult(v any) (map[string]any, error) {
	encoded, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, err
	}
	return map[string]any{"content": []map[string]any{{"type": "text", "text": string(encoded)}}}, nil
}

func plainResult(text string) map[string]any {
	return map[string]any{"content": []map[string]any{{"type": "text", "text": text}}}
}

func listOrganizations(c *client, _ json.RawMessage) (map[string]any, error) {
	var out struct {
		Organizations []json.RawMessage `json:"organizations"`
	}
	if err := c.call("GET", "/api/v1/organizations", nil, &out); err != nil {
		return nil, err
	}
	return textResult(out)
}

func createOrganization(c *client, args json.RawMessage) (map[string]any, error) {
	var in struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(args, &in); err != nil || in.Name == "" {
		return nil, fmt.Errorf("name is required")
	}
	var out json.RawMessage
	if err := c.call("POST", "/api/v1/organizations", map[string]string{"name": in.Name}, &out); err != nil {
		return nil, err
	}
	return textResult(out)
}

func listProjects(c *client, args json.RawMessage) (map[string]any, error) {
	var in struct {
		OrganizationID string `json:"organization_id"`
	}
	_ = json.Unmarshal(args, &in)
	if in.OrganizationID == "" {
		in.OrganizationID = os.Getenv("DUFFLEBAG_MCP_ORGANIZATION_ID")
	}
	if in.OrganizationID == "" {
		return nil, fmt.Errorf("organization_id is required")
	}
	var out json.RawMessage
	if err := c.call("GET", "/api/v1/organizations/"+url.PathEscape(in.OrganizationID)+"/projects", nil, &out); err != nil {
		return nil, err
	}
	return textResult(out)
}

func createProject(c *client, args json.RawMessage) (map[string]any, error) {
	var in struct {
		OrganizationID string `json:"organization_id"`
		Name           string `json:"name"`
	}
	if err := json.Unmarshal(args, &in); err != nil || in.Name == "" || in.OrganizationID == "" {
		return nil, fmt.Errorf("organization_id and name are required")
	}
	var out json.RawMessage
	if err := c.call("POST", "/api/v1/organizations/"+url.PathEscape(in.OrganizationID)+"/projects", map[string]string{"name": in.Name}, &out); err != nil {
		return nil, err
	}
	return textResult(out)
}

func listBuckets(c *client, args json.RawMessage) (map[string]any, error) {
	var in tenancyArgs
	_ = json.Unmarshal(args, &in)
	if err := in.resolve(); err != nil {
		return nil, err
	}
	var out json.RawMessage
	if err := c.call("GET", compatBase(in.OrganizationID, in.ProjectID)+"/buckets", nil, &out); err != nil {
		return nil, err
	}
	return textResult(out)
}

type wireArtifact struct {
	ExternalIdentifier string `json:"external_identifier"`
	Region             string `json:"region"`
}

type wireBuild struct {
	ID            string         `json:"id"`
	ComponentType string         `json:"component_type"`
	Status        string         `json:"status"`
	Platform      string         `json:"platform"`
	Artifacts     []wireArtifact `json:"artifacts"`
	Labels        map[string]string `json:"labels"`
}

type wireVersion struct {
	Name              string      `json:"name"`
	Fingerprint       string      `json:"fingerprint"`
	Status            string      `json:"status"`
	Builds            []wireBuild `json:"builds"`
	RevokeAt          *string     `json:"revoke_at"`
	RevocationMessage string      `json:"revocation_message"`
	RevocationType    string      `json:"revocation_type"`
}

func fetchVersions(c *client, t tenancyArgs, bucket string) ([]wireVersion, error) {
	var out struct {
		Versions []wireVersion `json:"versions"`
	}
	err := c.call("GET", compatBase(t.OrganizationID, t.ProjectID)+"/buckets/"+url.PathEscape(bucket)+"/versions", nil, &out)
	return out.Versions, err
}

func listVersions(c *client, args json.RawMessage) (map[string]any, error) {
	var in struct {
		tenancyArgs
		Bucket string `json:"bucket"`
	}
	_ = json.Unmarshal(args, &in)
	if err := in.resolve(); err != nil {
		return nil, err
	}
	if in.Bucket == "" {
		return nil, fmt.Errorf("bucket is required")
	}
	versions, err := fetchVersions(c, in.tenancyArgs, in.Bucket)
	if err != nil {
		return nil, err
	}
	return textResult(map[string]any{"versions": versions})
}

func listChannels(c *client, args json.RawMessage) (map[string]any, error) {
	var in struct {
		tenancyArgs
		Bucket string `json:"bucket"`
	}
	_ = json.Unmarshal(args, &in)
	if err := in.resolve(); err != nil {
		return nil, err
	}
	if in.Bucket == "" {
		return nil, fmt.Errorf("bucket is required")
	}
	var out json.RawMessage
	if err := c.call("GET", compatBase(in.OrganizationID, in.ProjectID)+"/buckets/"+url.PathEscape(in.Bucket)+"/channels", nil, &out); err != nil {
		return nil, err
	}
	return textResult(out)
}

func resolveChannel(c *client, args json.RawMessage) (map[string]any, error) {
	var in struct {
		tenancyArgs
		Bucket  string `json:"bucket"`
		Channel string `json:"channel"`
	}
	_ = json.Unmarshal(args, &in)
	if err := in.resolve(); err != nil {
		return nil, err
	}
	if in.Bucket == "" || in.Channel == "" {
		return nil, fmt.Errorf("bucket and channel are required")
	}
	var out struct {
		Channel struct {
			Name    string       `json:"name"`
			Managed bool         `json:"managed"`
			Version *wireVersion `json:"version"`
		} `json:"channel"`
	}
	if err := c.call("GET", compatBase(in.OrganizationID, in.ProjectID)+"/buckets/"+url.PathEscape(in.Bucket)+"/channels/"+url.PathEscape(in.Channel), nil, &out); err != nil {
		return nil, err
	}
	result := map[string]any{"channel": out.Channel.Name, "managed": out.Channel.Managed}
	if out.Channel.Version == nil {
		result["assigned"] = false
		result["safe_to_consume"] = false
		result["reason"] = "the channel has no assigned version"
		return textResult(result)
	}
	v := out.Channel.Version
	result["assigned"] = true
	result["version"] = v.Name
	result["fingerprint"] = v.Fingerprint
	revoked := v.RevokeAt != nil || v.RevocationType != "" && v.RevocationType != "REVOCATION_TYPE_UNSET"
	result["safe_to_consume"] = !revoked
	if revoked {
		result["reason"] = strings.TrimSpace("version is revoked or scheduled for revocation: " + v.RevocationMessage)
		result["revoke_at"] = v.RevokeAt
	}
	return textResult(result)
}

func versionDiff(c *client, args json.RawMessage) (map[string]any, error) {
	var in struct {
		tenancyArgs
		Bucket       string `json:"bucket"`
		FingerprintA string `json:"fingerprint_a"`
		FingerprintB string `json:"fingerprint_b"`
	}
	_ = json.Unmarshal(args, &in)
	if err := in.resolve(); err != nil {
		return nil, err
	}
	if in.Bucket == "" || in.FingerprintA == "" || in.FingerprintB == "" {
		return nil, fmt.Errorf("bucket, fingerprint_a and fingerprint_b are required")
	}
	versions, err := fetchVersions(c, in.tenancyArgs, in.Bucket)
	if err != nil {
		return nil, err
	}
	var a, b *wireVersion
	for i := range versions {
		if versions[i].Fingerprint == in.FingerprintA {
			a = &versions[i]
		}
		if versions[i].Fingerprint == in.FingerprintB {
			b = &versions[i]
		}
	}
	if a == nil || b == nil {
		return nil, fmt.Errorf("both fingerprints must exist in bucket %s", in.Bucket)
	}
	key := func(build wireBuild) string { return build.Platform + "/" + build.ComponentType }
	index := func(v *wireVersion) map[string]wireBuild {
		m := map[string]wireBuild{}
		for _, build := range v.Builds {
			m[key(build)] = build
		}
		return m
	}
	artifactKey := func(build wireBuild) string {
		ids := make([]string, 0, len(build.Artifacts))
		for _, artifact := range build.Artifacts {
			ids = append(ids, artifact.Region+"="+artifact.ExternalIdentifier)
		}
		sort.Strings(ids)
		return strings.Join(ids, ",")
	}
	am, bm := index(a), index(b)
	added, removed, changed := []string{}, []string{}, []string{}
	for k, bb := range bm {
		ab, ok := am[k]
		if !ok {
			added = append(added, k)
			continue
		}
		if ab.Status != bb.Status || artifactKey(ab) != artifactKey(bb) {
			changed = append(changed, k)
		}
	}
	for k := range am {
		if _, ok := bm[k]; !ok {
			removed = append(removed, k)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	sort.Strings(changed)
	return textResult(map[string]any{
		"bucket": in.Bucket,
		"a":      map[string]any{"name": a.Name, "fingerprint": a.Fingerprint, "status": a.Status, "revoked": a.RevokeAt != nil},
		"b":      map[string]any{"name": b.Name, "fingerprint": b.Fingerprint, "status": b.Status, "revoked": b.RevokeAt != nil},
		"builds": map[string]any{"added_in_b": added, "removed_in_b": removed, "changed": changed},
	})
}

func vulnerabilitySummary(c *client, args json.RawMessage) (map[string]any, error) {
	var in struct {
		tenancyArgs
		Bucket string `json:"bucket"`
	}
	_ = json.Unmarshal(args, &in)
	if err := in.resolve(); err != nil {
		return nil, err
	}
	if in.Bucket == "" {
		return nil, fmt.Errorf("bucket is required")
	}
	var out json.RawMessage
	if err := c.call("GET", compatBase(in.OrganizationID, in.ProjectID)+"/buckets/"+url.PathEscape(in.Bucket)+"/packages/vulnerability-summary", nil, &out); err != nil {
		return nil, err
	}
	return textResult(out)
}

func bagdropStatus(c *client, args json.RawMessage) (map[string]any, error) {
	var in tenancyArgs
	_ = json.Unmarshal(args, &in)
	if err := in.resolve(); err != nil {
		return nil, err
	}
	var out json.RawMessage
	if err := c.call("GET", platformBase(in.OrganizationID, in.ProjectID)+"/bagdrop/status", nil, &out); err != nil {
		return nil, err
	}
	return textResult(out)
}

func consumeSnippet(c *client, args json.RawMessage) (map[string]any, error) {
	var in struct {
		tenancyArgs
		Bucket      string `json:"bucket"`
		Fingerprint string `json:"fingerprint"`
		Channel     string `json:"channel"`
		Flavor      string `json:"flavor"`
	}
	_ = json.Unmarshal(args, &in)
	if err := in.resolve(); err != nil {
		return nil, err
	}
	if in.Bucket == "" {
		return nil, fmt.Errorf("bucket is required")
	}
	if in.Flavor == "" {
		in.Flavor = "terraform"
	}
	channel := in.Channel
	if channel == "" {
		channel = "latest"
	}
	versions, err := fetchVersions(c, in.tenancyArgs, in.Bucket)
	if err != nil {
		return nil, err
	}
	fingerprint := in.Fingerprint
	if fingerprint == "" {
		var out struct {
			Channel struct {
				Version *wireVersion `json:"version"`
			} `json:"channel"`
		}
		if err := c.call("GET", compatBase(in.OrganizationID, in.ProjectID)+"/buckets/"+url.PathEscape(in.Bucket)+"/channels/"+url.PathEscape(channel), nil, &out); err != nil {
			return nil, err
		}
		if out.Channel.Version == nil {
			return nil, fmt.Errorf("channel %s in bucket %s has no assigned version", channel, in.Bucket)
		}
		fingerprint = out.Channel.Version.Fingerprint
	}
	var version *wireVersion
	for i := range versions {
		if versions[i].Fingerprint == fingerprint {
			version = &versions[i]
		}
	}
	if version == nil {
		return nil, fmt.Errorf("fingerprint %s not found in bucket %s", fingerprint, in.Bucket)
	}

	switch in.Flavor {
	case "terraform":
		label := terraformLabel(in.Bucket)
		snippet := fmt.Sprintf("data \"hcp_packer_version\" %q {\n  bucket_name  = %q\n  channel_name = %q\n}", label, in.Bucket, channel)
		if len(version.Builds) > 0 && len(version.Builds[0].Artifacts) > 0 {
			artifact := version.Builds[0].Artifacts[0]
			snippet += fmt.Sprintf("\n\ndata \"hcp_packer_artifact\" %q {\n  bucket_name         = %q\n  version_fingerprint = %q\n  platform            = %q\n  region              = %q\n}",
				label, in.Bucket, version.Fingerprint, version.Builds[0].Platform, artifact.Region)
		}
		return plainResult(snippet), nil
	case "docker", "aws":
		var lines []string
		for _, build := range version.Builds {
			if build.Platform != in.Flavor {
				continue
			}
			for _, artifact := range build.Artifacts {
				if in.Flavor == "docker" {
					lines = append(lines, fmt.Sprintf("# image digest for %s %s\ndocker image inspect %s", in.Bucket, version.Name, artifact.ExternalIdentifier))
				} else {
					lines = append(lines, fmt.Sprintf("aws ec2 describe-images --image-ids %s --region %s", artifact.ExternalIdentifier, artifact.Region))
				}
			}
		}
		if len(lines) == 0 {
			return plainResult(fmt.Sprintf("no %s artifacts on version %s — use flavor \"terraform\" (the fallback for every platform)", in.Flavor, version.Name)), nil
		}
		return plainResult(strings.Join(lines, "\n\n")), nil
	default:
		return nil, fmt.Errorf("unknown flavor %q — terraform, docker and aws are served; terraform is the fallback for everything else", in.Flavor)
	}
}

func terraformLabel(value string) string {
	label := strings.ToLower(value)
	var b strings.Builder
	for _, r := range label {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_' {
			b.WriteRune(r)
		} else {
			b.WriteRune('_')
		}
	}
	out := b.String()
	if out == "" {
		return "version"
	}
	if out[0] >= '0' && out[0] <= '9' {
		return "v_" + out
	}
	return out
}
