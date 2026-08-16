package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
)

// readOnly reports the deployment posture: with DFBG_MCP_READ_ONLY set,
// mutating tools are neither listed nor callable.
func readOnly() bool {
	v, _ := strconv.ParseBool(os.Getenv("DFBG_MCP_READ_ONLY"))
	return v
}

var writeTools = map[string]bool{
	"create_organization": true,
	"create_project":      true,
	"promote_channel":     true,
}

// Tenancy arguments fall back to the optional environment defaults so a
// server registered against one project does not need them repeated on
// every call.
type tenancyArgs struct {
	OrganizationID string `json:"organization_id"`
	ProjectID      string `json:"project_id"`
}

func (t *tenancyArgs) resolve() error {
	if t.OrganizationID == "" {
		t.OrganizationID = os.Getenv("DFBG_MCP_ORGANIZATION_ID")
	}
	if t.ProjectID == "" {
		t.ProjectID = os.Getenv("DFBG_MCP_PROJECT_ID")
	}
	if t.OrganizationID == "" || t.ProjectID == "" {
		return fmt.Errorf("organization_id and project_id are required (or set DFBG_MCP_ORGANIZATION_ID / DFBG_MCP_PROJECT_ID)")
	}
	return nil
}

var tenancyProperties = map[string]any{
	"organization_id": map[string]any{"type": "string", "description": "Organization id (falls back to DFBG_MCP_ORGANIZATION_ID)"},
	"project_id":      map[string]any{"type": "string", "description": "Project id (falls back to DFBG_MCP_PROJECT_ID)"},
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
	defs := []map[string]any{
		{
			"name":        "whoami",
			"description": "The current credential: principal, role, bound scope, and the tenancy defaults this server is configured with.",
			"inputSchema": map[string]any{"type": "object", "properties": map[string]any{}},
		},
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
			"description": "List a project's registry buckets: latest version, platforms and ancestry freshness. list_versions carries the full build detail.",
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
			"description": "Headline vulnerability counts for a bucket: totals by criticality and the worst packages. list_vulnerabilities carries the per-finding detail.",
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
		{
			"name":        "promote_channel",
			"description": "Assign a version, by explicit fingerprint, to a bucket channel. Requires publisher authority; managed channels are refused.",
			"inputSchema": schema(map[string]any{
				"bucket":            map[string]any{"type": "string"},
				"channel":           map[string]any{"type": "string"},
				"fingerprint":       map[string]any{"type": "string", "description": "The exact version fingerprint to assign — verify it first (version_diff, vulnerability_summary, resolve_channel)"},
				"create_if_missing": map[string]any{"type": "boolean", "description": "Create the channel with this assignment when it does not exist"},
			}, "bucket", "channel", "fingerprint"),
		},
		{
			"name":        "check_ancestry",
			"description": "A bucket's parent/child lineage with per-relation freshness: is each child built from what its parent channel currently serves?",
			"inputSchema": schema(map[string]any{
				"bucket":              map[string]any{"type": "string"},
				"version_fingerprint": map[string]any{"type": "string", "description": "Limit to one version's relations"},
				"direction":           map[string]any{"type": "string", "enum": []string{"parents", "children", "all"}, "description": "Default all"},
			}, "bucket"),
		},
		{
			"name":        "list_vulnerabilities",
			"description": "Individual vulnerabilities for a bucket with impacted packages and fix versions. Filter by criticality or identifier; vulnerability_summary gives the headline counts.",
			"inputSchema": schema(map[string]any{
				"bucket":      map[string]any{"type": "string"},
				"criticality": map[string]any{"type": "string", "enum": []string{"critical", "high", "medium", "low", "unknown"}},
				"identifier":  map[string]any{"type": "string", "description": "Exact CVE/GHSA id"},
				"limit":       map[string]any{"type": "number", "description": "Max results (default 20)"},
			}, "bucket"),
		},
		{
			"name":        "find_artifact",
			"description": "Find which bucket and version produced an artifact from its external identifier (image digest, AMI id) — provenance in reverse. Uses the registry's search endpoint, enumerating buckets only against registries that predate it.",
			"inputSchema": schema(map[string]any{
				"external_identifier": map[string]any{"type": "string"},
			}, "external_identifier"),
		},
	}
	if !readOnly() {
		return defs
	}
	filtered := make([]map[string]any, 0, len(defs))
	for _, def := range defs {
		if !writeTools[def["name"].(string)] {
			filtered = append(filtered, def)
		}
	}
	return filtered
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
	if writeTools[call.Name] && readOnly() {
		return nil, fmt.Errorf("tool %q is disabled: this server runs read-only (DFBG_MCP_READ_ONLY)", call.Name)
	}
	return handler(c, args)
}

var toolHandlers = map[string]func(*client, json.RawMessage) (map[string]any, error){
	"whoami":                whoami,
	"list_organizations":    listOrganizations,
	"create_organization":   createOrganization,
	"list_projects":         listProjects,
	"create_project":        createProject,
	"list_buckets":          listBuckets,
	"list_versions":         listVersions,
	"list_channels":         listChannels,
	"resolve_channel":       resolveChannel,
	"promote_channel":       promoteChannel,
	"check_ancestry":        checkAncestry,
	"version_diff":          versionDiff,
	"vulnerability_summary": vulnerabilitySummary,
	"list_vulnerabilities":  listVulnerabilities,
	"bagdrop_status":        bagdropStatus,
	"consume_snippet":       consumeSnippet,
	"find_artifact":         findArtifact,
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
		in.OrganizationID = os.Getenv("DFBG_MCP_ORGANIZATION_ID")
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

// listBuckets projects the compat response down to what a listing is for:
// the full latest_version carries builds, artifacts and Packer host metadata
// that costs kilobytes per bucket and answers questions list_versions serves.
func listBuckets(c *client, args json.RawMessage) (map[string]any, error) {
	var in tenancyArgs
	_ = json.Unmarshal(args, &in)
	if err := in.resolve(); err != nil {
		return nil, err
	}
	var out struct {
		Buckets []struct {
			Name          string   `json:"name"`
			Platforms     []string `json:"platforms"`
			UpdatedAt     string   `json:"updated_at"`
			LatestVersion *struct {
				Name        string  `json:"name"`
				Fingerprint string  `json:"fingerprint"`
				Status      string  `json:"status"`
				RevokeAt    *string `json:"revoke_at"`
			} `json:"latest_version"`
			Parents *struct {
				Status string `json:"status"`
			} `json:"parents"`
		} `json:"buckets"`
	}
	if err := c.call("GET", compatBase(in.OrganizationID, in.ProjectID)+"/buckets", nil, &out); err != nil {
		return nil, err
	}
	buckets := make([]map[string]any, 0, len(out.Buckets))
	for _, bucket := range out.Buckets {
		entry := map[string]any{"name": bucket.Name, "platforms": bucket.Platforms, "updated_at": bucket.UpdatedAt}
		if v := bucket.LatestVersion; v != nil {
			entry["latest"] = map[string]any{"version": v.Name, "fingerprint": v.Fingerprint, "status": v.Status, "revoked": v.RevokeAt != nil}
		}
		if p := bucket.Parents; p != nil && p.Status != "" {
			entry["ancestry"] = p.Status
		}
		buckets = append(buckets, entry)
	}
	return textResult(map[string]any{"buckets": buckets})
}

type wireArtifact struct {
	ExternalIdentifier string `json:"external_identifier"`
	Region             string `json:"region"`
}

type wireBuild struct {
	ID            string            `json:"id"`
	ComponentType string            `json:"component_type"`
	Status        string            `json:"status"`
	Platform      string            `json:"platform"`
	Artifacts     []wireArtifact    `json:"artifacts"`
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

// summaryPackageCap bounds the worst-packages list; anything past it is
// reported as an explicit omission, never silently truncated.
const summaryPackageCap = 15

var criticalityRank = map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}

// vulnerabilitySummary projects the raw summary — one row per package per
// criticality, duplicated per channel — down to the totals headline and one
// aggregated row per package, worst first. list_vulnerabilities is the
// drill-down.
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
	var out struct {
		Totals []struct {
			Criticality string `json:"criticality"`
			Count       string `json:"vulnerability_count"`
		} `json:"total_by_criticality"`
		Packages []struct {
			Name        string `json:"package_name"`
			Version     string `json:"package_version"`
			Criticality string `json:"criticality"`
			Count       string `json:"vulnerability_count"`
		} `json:"packages_by_criticality"`
	}
	if err := c.call("GET", compatBase(in.OrganizationID, in.ProjectID)+"/buckets/"+url.PathEscape(in.Bucket)+"/packages/vulnerability-summary", nil, &out); err != nil {
		return nil, err
	}

	sort.SliceStable(out.Totals, func(i, j int) bool {
		return criticalityRank[out.Totals[i].Criticality] < criticalityRank[out.Totals[j].Criticality]
	})
	totals := make([]map[string]any, 0, len(out.Totals))
	for _, total := range out.Totals {
		count, _ := strconv.Atoi(total.Count)
		totals = append(totals, map[string]any{"criticality": total.Criticality, "count": count})
	}

	type packageRow struct {
		name   string
		counts map[string]int
		total  int
		worst  int
	}
	aggregated := map[string]*packageRow{}
	for _, p := range out.Packages {
		key := p.Name + " " + p.Version
		row, ok := aggregated[key]
		if !ok {
			row = &packageRow{name: key, counts: map[string]int{}, worst: len(criticalityRank)}
			aggregated[key] = row
		}
		count, _ := strconv.Atoi(p.Count)
		row.counts[p.Criticality] += count
		row.total += count
		if rank := criticalityRank[p.Criticality]; rank < row.worst {
			row.worst = rank
		}
	}
	rows := make([]*packageRow, 0, len(aggregated))
	for _, row := range aggregated {
		rows = append(rows, row)
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].worst != rows[j].worst {
			return rows[i].worst < rows[j].worst
		}
		if rows[i].total != rows[j].total {
			return rows[i].total > rows[j].total
		}
		return rows[i].name < rows[j].name
	})
	omitted := 0
	if len(rows) > summaryPackageCap {
		omitted = len(rows) - summaryPackageCap
		rows = rows[:summaryPackageCap]
	}
	packages := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		packages = append(packages, map[string]any{"package": row.name, "counts": row.counts, "total": row.total})
	}

	result := map[string]any{"bucket": in.Bucket, "total_by_criticality": totals, "worst_packages": packages}
	if omitted > 0 {
		result["omitted"] = fmt.Sprintf("%d more packages — use list_vulnerabilities to drill down", omitted)
	}
	return textResult(result)
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

func whoami(c *client, _ json.RawMessage) (map[string]any, error) {
	var self struct {
		PrincipalID    string `json:"principal_id"`
		Name           string `json:"name"`
		Role           string `json:"role"`
		OrganizationID string `json:"organization_id"`
		ProjectID      string `json:"project_id"`
	}
	if err := c.call("GET", "/api/v1/self", nil, &self); err != nil {
		return nil, err
	}
	result := map[string]any{
		"principal_id": self.PrincipalID,
		"name":         self.Name,
		"role":         self.Role,
		"endpoint":     c.endpoint,
		"read_only":    readOnly(),
	}
	if self.OrganizationID != "" {
		result["organization_id"] = self.OrganizationID
	}
	if self.ProjectID != "" {
		result["project_id"] = self.ProjectID
	}
	if org := os.Getenv("DFBG_MCP_ORGANIZATION_ID"); org != "" {
		result["default_organization"] = tenantRef(c, "/api/v1/organizations/"+url.PathEscape(org), org)
		if project := os.Getenv("DFBG_MCP_PROJECT_ID"); project != "" {
			result["default_project"] = tenantRef(c, "/api/v1/organizations/"+url.PathEscape(org)+"/projects/"+url.PathEscape(project), project)
		}
	}
	return textResult(result)
}

// tenantRef resolves a tenant's name, falling back to the bare id when the
// credential cannot read it.
func tenantRef(c *client, path, id string) map[string]any {
	var out struct {
		Name string `json:"name"`
	}
	if err := c.call("GET", path, nil, &out); err != nil || out.Name == "" {
		return map[string]any{"id": id}
	}
	return map[string]any{"id": id, "name": out.Name}
}

func promoteChannel(c *client, args json.RawMessage) (map[string]any, error) {
	var in struct {
		tenancyArgs
		Bucket          string `json:"bucket"`
		Channel         string `json:"channel"`
		Fingerprint     string `json:"fingerprint"`
		CreateIfMissing bool   `json:"create_if_missing"`
	}
	_ = json.Unmarshal(args, &in)
	if err := in.resolve(); err != nil {
		return nil, err
	}
	if in.Bucket == "" || in.Channel == "" || in.Fingerprint == "" {
		return nil, fmt.Errorf("bucket, channel and fingerprint are required — promote the exact version you verified")
	}
	channels := compatBase(in.OrganizationID, in.ProjectID) + "/buckets/" + url.PathEscape(in.Bucket) + "/channels"
	var out struct {
		Channel struct {
			Name    string       `json:"name"`
			Version *wireVersion `json:"version"`
		} `json:"channel"`
	}
	created := false
	err := c.call("PATCH", channels+"/"+url.PathEscape(in.Channel),
		map[string]string{"update_mask": "versionFingerprint", "version_fingerprint": in.Fingerprint}, &out)
	var httpErr *httpError
	if errors.As(err, &httpErr) && httpErr.status == 404 && in.CreateIfMissing {
		created = true
		err = c.call("POST", channels, map[string]string{"name": in.Channel, "version_fingerprint": in.Fingerprint}, &out)
	}
	if err != nil {
		return nil, err
	}
	result := map[string]any{"bucket": in.Bucket, "channel": out.Channel.Name, "created": created}
	if v := out.Channel.Version; v != nil {
		result["version"] = v.Name
		result["fingerprint"] = v.Fingerprint
	}
	return textResult(result)
}

func checkAncestry(c *client, args json.RawMessage) (map[string]any, error) {
	var in struct {
		tenancyArgs
		Bucket             string `json:"bucket"`
		VersionFingerprint string `json:"version_fingerprint"`
		Direction          string `json:"direction"`
	}
	_ = json.Unmarshal(args, &in)
	if err := in.resolve(); err != nil {
		return nil, err
	}
	if in.Bucket == "" {
		return nil, fmt.Errorf("bucket is required")
	}
	query := url.Values{}
	switch in.Direction {
	case "parents":
		query.Set("type", "ANCESTRY_TYPE_PARENTS")
	case "children":
		query.Set("type", "ANCESTRY_TYPE_CHILDREN")
	case "", "all":
	default:
		return nil, fmt.Errorf("direction %q — parents, children and all are served", in.Direction)
	}
	if in.VersionFingerprint != "" {
		query.Set("version_fingerprint", in.VersionFingerprint)
	}
	path := compatBase(in.OrganizationID, in.ProjectID) + "/buckets/" + url.PathEscape(in.Bucket) + "/ancestry"
	if encoded := query.Encode(); encoded != "" {
		path += "?" + encoded
	}
	var out struct {
		Relations []struct {
			Parent *struct {
				BucketName         string `json:"bucket_name"`
				ChannelName        string `json:"channel_name"`
				VersionFingerprint string `json:"version_fingerprint"`
				VersionName        string `json:"version_name"`
				ChannelVersion     *struct {
					Name        string `json:"name"`
					Fingerprint string `json:"fingerprint"`
				} `json:"channel_version"`
			} `json:"parent"`
			Child *struct {
				BucketName         string `json:"bucket_name"`
				VersionFingerprint string `json:"version_fingerprint"`
				VersionName        string `json:"version_name"`
			} `json:"child"`
			Status string `json:"status"`
		} `json:"relations"`
		TotalCount int `json:"total_count"`
	}
	if err := c.call("GET", path, nil, &out); err != nil {
		return nil, err
	}
	relations := make([]map[string]any, 0, len(out.Relations))
	for _, relation := range out.Relations {
		entry := map[string]any{"status": relation.Status}
		if p := relation.Parent; p != nil {
			parent := map[string]any{"bucket": p.BucketName, "channel": p.ChannelName, "version": p.VersionName, "fingerprint": p.VersionFingerprint}
			if cv := p.ChannelVersion; cv != nil && cv.Fingerprint != p.VersionFingerprint {
				parent["channel_now_serves"] = map[string]any{"version": cv.Name, "fingerprint": cv.Fingerprint}
			}
			entry["parent"] = parent
		}
		if child := relation.Child; child != nil {
			entry["child"] = map[string]any{"bucket": child.BucketName, "version": child.VersionName, "fingerprint": child.VersionFingerprint}
		}
		relations = append(relations, entry)
	}
	return textResult(map[string]any{"bucket": in.Bucket, "relations": relations, "total_count": out.TotalCount})
}

func listVulnerabilities(c *client, args json.RawMessage) (map[string]any, error) {
	var in struct {
		tenancyArgs
		Bucket      string  `json:"bucket"`
		Criticality string  `json:"criticality"`
		Identifier  string  `json:"identifier"`
		Limit       float64 `json:"limit"`
	}
	_ = json.Unmarshal(args, &in)
	if err := in.resolve(); err != nil {
		return nil, err
	}
	if in.Bucket == "" {
		return nil, fmt.Errorf("bucket is required")
	}
	limit := int(in.Limit)
	if limit <= 0 {
		limit = 20
	}
	query := url.Values{"pagination.page_size": {strconv.Itoa(limit)}}
	if in.Criticality != "" {
		query.Set("criticality", in.Criticality)
	}
	if in.Identifier != "" {
		query.Set("identifier", in.Identifier)
	}
	var out struct {
		Vulnerabilities []struct {
			Vulnerability struct {
				Identifier   string `json:"identifier"`
				Criticality  string `json:"criticality"`
				Description  string `json:"description"`
				FixedVersion string `json:"fixed_version"`
			} `json:"vulnerability"`
			ImpactedPackages []struct {
				Name    string `json:"name"`
				Version string `json:"version"`
			} `json:"impacted_packages"`
			ImpactedChannels []struct {
				Name string `json:"name"`
			} `json:"impacted_channels"`
		} `json:"vulnerabilities"`
		Pagination struct {
			NextPageToken string `json:"next_page_token"`
		} `json:"pagination"`
	}
	path := compatBase(in.OrganizationID, in.ProjectID) + "/buckets/" + url.PathEscape(in.Bucket) + "/vulnerabilities?" + query.Encode()
	if err := c.call("GET", path, nil, &out); err != nil {
		return nil, err
	}
	vulnerabilities := make([]map[string]any, 0, len(out.Vulnerabilities))
	for _, v := range out.Vulnerabilities {
		packages := make([]string, 0, len(v.ImpactedPackages))
		for _, p := range v.ImpactedPackages {
			packages = append(packages, p.Name+" "+p.Version)
		}
		channels := make([]string, 0, len(v.ImpactedChannels))
		for _, channel := range v.ImpactedChannels {
			channels = append(channels, channel.Name)
		}
		entry := map[string]any{
			"identifier":  v.Vulnerability.Identifier,
			"criticality": v.Vulnerability.Criticality,
			"packages":    packages,
			"channels":    channels,
		}
		if v.Vulnerability.FixedVersion != "" {
			entry["fixed_version"] = v.Vulnerability.FixedVersion
		}
		if v.Vulnerability.Description != "" {
			entry["description"] = v.Vulnerability.Description
		}
		vulnerabilities = append(vulnerabilities, entry)
	}
	result := map[string]any{"bucket": in.Bucket, "vulnerabilities": vulnerabilities}
	if out.Pagination.NextPageToken != "" {
		result["truncated"] = fmt.Sprintf("more results beyond the first %d — raise limit or filter by criticality", limit)
	}
	return textResult(result)
}

func findArtifact(c *client, args json.RawMessage) (map[string]any, error) {
	var in struct {
		tenancyArgs
		ExternalIdentifier string `json:"external_identifier"`
	}
	_ = json.Unmarshal(args, &in)
	if err := in.resolve(); err != nil {
		return nil, err
	}
	if in.ExternalIdentifier == "" {
		return nil, fmt.Errorf("external_identifier is required")
	}

	var out struct {
		Artifacts []struct {
			Bucket *struct {
				Name string `json:"name"`
			} `json:"bucket"`
			Build   *wireBuild `json:"build"`
			Version *struct {
				Name        string  `json:"name"`
				Fingerprint string  `json:"fingerprint"`
				Status      string  `json:"status"`
				RevokeAt    *string `json:"revoke_at"`
			} `json:"version"`
		} `json:"artifacts"`
	}
	err := c.call("POST", compatBase(in.OrganizationID, in.ProjectID)+"/_search/external_artifact",
		map[string]string{"external_identifier": in.ExternalIdentifier}, &out)
	var httpErr *httpError
	if errors.As(err, &httpErr) && httpErr.status == 404 {
		// The registry predates the search endpoint; fall back to walking
		// the project's buckets and say so.
		return findArtifactByEnumeration(c, in.tenancyArgs, in.ExternalIdentifier)
	}
	if err != nil {
		return nil, err
	}
	matches := []map[string]any{}
	for _, artifact := range out.Artifacts {
		entry := map[string]any{}
		if artifact.Bucket != nil {
			entry["bucket"] = artifact.Bucket.Name
		}
		if v := artifact.Version; v != nil {
			entry["version"] = v.Name
			entry["fingerprint"] = v.Fingerprint
			entry["status"] = v.Status
			entry["revoked"] = v.RevokeAt != nil
		}
		if build := artifact.Build; build != nil {
			entry["platform"] = build.Platform
			entry["component_type"] = build.ComponentType
			for _, candidate := range build.Artifacts {
				if candidate.ExternalIdentifier == in.ExternalIdentifier {
					entry["region"] = candidate.Region
				}
			}
		}
		matches = append(matches, entry)
	}
	return textResult(map[string]any{
		"external_identifier": in.ExternalIdentifier,
		"matches":             matches,
	})
}

func findArtifactByEnumeration(c *client, tenancy tenancyArgs, externalIdentifier string) (map[string]any, error) {
	var buckets struct {
		Buckets []struct {
			Name string `json:"name"`
		} `json:"buckets"`
	}
	if err := c.call("GET", compatBase(tenancy.OrganizationID, tenancy.ProjectID)+"/buckets", nil, &buckets); err != nil {
		return nil, err
	}
	matches := []map[string]any{}
	for _, bucket := range buckets.Buckets {
		versions, err := fetchVersions(c, tenancy, bucket.Name)
		if err != nil {
			return nil, err
		}
		for _, version := range versions {
			for _, build := range version.Builds {
				for _, artifact := range build.Artifacts {
					if artifact.ExternalIdentifier != externalIdentifier {
						continue
					}
					matches = append(matches, map[string]any{
						"bucket":         bucket.Name,
						"version":        version.Name,
						"fingerprint":    version.Fingerprint,
						"status":         version.Status,
						"revoked":        version.RevokeAt != nil,
						"platform":       build.Platform,
						"component_type": build.ComponentType,
						"region":         artifact.Region,
					})
				}
			}
		}
	}
	return textResult(map[string]any{
		"external_identifier": externalIdentifier,
		"matches":             matches,
		"buckets_searched":    len(buckets.Buckets),
		"fallback":            "the registry predates the search endpoint; buckets were enumerated",
	})
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
