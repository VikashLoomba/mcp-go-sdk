package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// ProxyManager manages dynamic connections to external MCP servers and
// proxies their tools through a primary server.
type ProxyManager struct {
	server  *mcp.Server
	mu      sync.Mutex
	remotes map[string]*remoteClient // keyed by name
}

func NewProxyManager(server *mcp.Server) *ProxyManager {
	return &ProxyManager{server: server, remotes: make(map[string]*remoteClient)}
}

// AddServerRequest describes the payload for /add-server.
type AddServerRequest struct {
	Name    string            `json:"name"`              // required logical name; used for namespacing
	Command string            `json:"command"`           // required binary or script to exec via stdio
	Args    []string          `json:"args,omitempty"`    // optional args
	Env     map[string]string `json:"env,omitempty"`     // optional extra env vars (merged onto process env)
	Dir     string            `json:"dir,omitempty"`     // optional working directory
	Include []string          `json:"include,omitempty"` // optional allowed tool names
	Exclude []string          `json:"exclude,omitempty"` // optional excluded tool names
	Prefix  string            `json:"prefix,omitempty"`  // optional prefix for proxied tools (default: name + "/")
}

type RemoveServerRequest struct {
	Name string `json:"name"`
}

type ListServersResponse struct {
	Servers []ServerInfo `json:"servers"`
}

type ServerInfo struct {
	Name              string                       `json:"name"`
	Command           string                       `json:"command"`
	Args              []string                     `json:"args,omitempty"`
	Dir               string                       `json:"dir,omitempty"`
	ToolPrefix        string                       `json:"toolPrefix"`
	Tools             []string                     `json:"tools"`
	RemoteTools       []RemoteToolInfo             `json:"remoteTools"`
	Prompts           []RemotePromptInfo           `json:"prompts"`
	Resources         []RemoteResourceInfo         `json:"resources"`
	ResourceTemplates []RemoteResourceTemplateInfo `json:"resourceTemplates"`
}

// RemoteToolInfo describes a single tool available on the remote server,
// along with whether it is currently enabled (proxied) and its proxied name.
type RemoteToolInfo struct {
	Name        string `json:"name"`
	ProxiedName string `json:"proxiedName,omitempty"`
	Enabled     bool   `json:"enabled"`
	Description string `json:"description,omitempty"`
}

// RemotePromptInfo describes a prompt available on the remote server.
type RemotePromptInfo struct {
	Name        string                     `json:"name"`
	ProxiedName string                     `json:"proxiedName,omitempty"`
	Description string                     `json:"description,omitempty"`
	Arguments   []RemotePromptArgumentInfo `json:"arguments,omitempty"`
}

// RemoteResourceInfo describes a resource available on the remote server.
type RemoteResourceInfo struct {
	Name        string `json:"name,omitempty"`
	URI         string `json:"uri"`
	ProxiedURI  string `json:"proxiedUri"`
	Description string `json:"description,omitempty"`
	MIMEType    string `json:"mimeType,omitempty"`
}

// RemoteResourceTemplateInfo describes a resource template available on the remote.
type RemoteResourceTemplateInfo struct {
	URITemplate string `json:"uriTemplate"`
	Description string `json:"description,omitempty"`
	MIMEType    string `json:"mimeType,omitempty"`
}

// RemotePromptArgumentInfo mirrors a prompt argument for UI display.
type RemotePromptArgumentInfo struct {
	Name        string `json:"name"`
	Title       string `json:"title,omitempty"`
	Description string `json:"description,omitempty"`
	Required    bool   `json:"required,omitempty"`
}

// HandleAddServer handles POST /add-server.
func (pm *ProxyManager) HandleAddServer(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	var req AddServerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("invalid JSON: %v", err), http.StatusBadRequest)
		return
	}
	added, err := pm.AddServer(r.Context(), &req)
	if err != nil {
		code := http.StatusInternalServerError
		if errors.Is(err, errAlreadyExists) || errors.Is(err, errInvalidRequest) {
			code = http.StatusBadRequest
		}
		http.Error(w, err.Error(), code)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(added)
}

// HandleRemoveServer handles POST /remove-server.
func (pm *ProxyManager) HandleRemoveServer(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	var req RemoveServerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("invalid JSON: %v", err), http.StatusBadRequest)
		return
	}
	count, err := pm.RemoveServer(r.Context(), req.Name)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"removedTools": count})
}

// HandleListServers handles GET /servers.
func (pm *ProxyManager) HandleListServers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	resp := pm.ListServersDetailed(r.Context())
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// HandleUpdateServer handles POST /update-server.
func (pm *ProxyManager) HandleUpdateServer(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	var req UpdateServerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("invalid JSON: %v", err), http.StatusBadRequest)
		return
	}
	info, err := pm.UpdateServer(r.Context(), &req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(info)
}

var (
	errAlreadyExists  = errors.New("server already exists")
	errInvalidRequest = errors.New("invalid add-server request")
)

// AddServer connects to a remote MCP server and proxies its tools.
func (pm *ProxyManager) AddServer(ctx context.Context, req *AddServerRequest) (*ServerInfo, error) {
	if req == nil || req.Name == "" || req.Command == "" {
		return nil, fmt.Errorf("%w: name and command are required", errInvalidRequest)
	}
	prefix := req.Prefix
	if prefix == "" {
		prefix = req.Name + "/"
	}

	pm.mu.Lock()
	if _, ok := pm.remotes[req.Name]; ok {
		pm.mu.Unlock()
		return nil, fmt.Errorf("%w: %s", errAlreadyExists, req.Name)
	}
	pm.mu.Unlock()

	rc := &remoteClient{
		name:         req.Name,
		command:      req.Command,
		args:         append([]string(nil), req.Args...),
		dir:          req.Dir,
		env:          req.Env,
		include:      setFromSlice(req.Include),
		exclude:      setFromSlice(req.Exclude),
		prefix:       prefix,
		server:       pm.server,
		toolsByProxy: make(map[string]*mcp.Tool),
		proxyByTool:  make(map[string]string),
	}

	if err := rc.connect(ctx); err != nil {
		return nil, err
	}

	// Validate prefix collisions before initial sync (tools).
	remoteNames, err := rc.listRemoteToolNames(ctx)
	if err != nil {
		_ = rc.close()
		return nil, fmt.Errorf("list remote tools: %w", err)
	}
	proposed := make([]string, 0, len(remoteNames))
	for _, n := range remoteNames {
		proposed = append(proposed, rc.prefix+n)
	}
	if err := pm.checkCollisions(ctx, proposed, nil); err != nil {
		_ = rc.close()
		return nil, err
	}

	// Validate prompt name collisions
	promptNames, err := rc.listRemotePromptNames(ctx)
	if err != nil {
		_ = rc.close()
		return nil, fmt.Errorf("list remote prompts: %w", err)
	}
	proposedPrompts := make([]string, 0, len(promptNames))
	for _, n := range promptNames {
		proposedPrompts = append(proposedPrompts, rc.prefix+n)
	}
	if err := pm.checkPromptCollisions(ctx, proposedPrompts, nil); err != nil {
		_ = rc.close()
		return nil, err
	}

	// Initial sync.
	added, err := rc.syncTools(ctx)
	if err != nil {
		// Best effort cleanup if sync fails.
		_ = rc.close()
		return nil, err
	}
	if _, err := rc.syncPrompts(ctx); err != nil {
		_ = rc.close()
		return nil, err
	}
	if _, err := rc.syncResources(ctx); err != nil {
		_ = rc.close()
		return nil, err
	}

	pm.mu.Lock()
	pm.remotes[rc.name] = rc
	pm.mu.Unlock()

	log.Printf("<%s> connected to stdio command %q; proxied %d tools", rc.name, rc.command, added)
	return rc.info(), nil
}

// RemoveServer disconnects from a remote and removes proxied tools.
func (pm *ProxyManager) RemoveServer(ctx context.Context, name string) (int, error) {
	if strings.TrimSpace(name) == "" {
		return 0, fmt.Errorf("name is required")
	}
	pm.mu.Lock()
	rc := pm.remotes[name]
	if rc != nil {
		delete(pm.remotes, name)
	}
	pm.mu.Unlock()
	if rc == nil {
		return 0, fmt.Errorf("server not found: %s", name)
	}
	removed := rc.removeAll()
	_ = rc.close()
	log.Printf("<%s> removed server; removed %d tools", name, removed)
	return removed, nil
}

// ListServers returns information about connected remotes.
func (pm *ProxyManager) ListServers() *ListServersResponse {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	out := &ListServersResponse{}
	for _, rc := range pm.remotes {
		out.Servers = append(out.Servers, *rc.info())
	}
	// Keep results stable
	slices.SortFunc(out.Servers, func(a, b ServerInfo) int { return strings.Compare(a.Name, b.Name) })
	return out
}

// ListServersDetailed returns server info including remote tool list and enabled states.
func (pm *ProxyManager) ListServersDetailed(ctx context.Context) *ListServersResponse {
	pm.mu.Lock()
	remotes := make([]*remoteClient, 0, len(pm.remotes))
	for _, rc := range pm.remotes {
		remotes = append(remotes, rc)
	}
	pm.mu.Unlock()

	out := &ListServersResponse{}
	for _, rc := range remotes {
		info := rc.info()
		// Attempt to enrich with remote tools.
		if rtools, err := rc.listRemoteTools(ctx); err == nil {
			// Build a map of enabled proxied names for quick lookup.
			rc.mu.Lock()
			enabledSet := make(map[string]struct{}, len(rc.proxyByTool))
			for orig, prox := range rc.proxyByTool {
				_ = orig
				enabledSet[prox] = struct{}{}
			}
			prefix := rc.prefix
			rc.mu.Unlock()
			for _, t := range rtools {
				if t == nil || t.Name == "" {
					continue
				}
				enabled := rc.filter(t.Name)
				proxied := ""
				if enabled {
					proxied = prefix + t.Name
				}
				info.RemoteTools = append(info.RemoteTools, RemoteToolInfo{
					Name:        t.Name,
					ProxiedName: proxied,
					Enabled:     enabled,
					Description: t.Description,
				})
			}
			// Keep stable order
			slices.SortFunc(info.RemoteTools, func(a, b RemoteToolInfo) int { return strings.Compare(a.Name, b.Name) })
		}
		// Enrich with prompts
		if rprompts, err := rc.listRemotePrompts(ctx); err == nil {
			prefix := rc.prefix
			for _, p := range rprompts {
				if p == nil || p.Name == "" {
					continue
				}
				info.Prompts = append(info.Prompts, RemotePromptInfo{
					Name:        p.Name,
					ProxiedName: prefix + p.Name,
					Description: p.Description,
				})
			}
			slices.SortFunc(info.Prompts, func(a, b RemotePromptInfo) int { return strings.Compare(a.Name, b.Name) })
		}
		// Enrich with resources
		if rres, err := rc.listRemoteResources(ctx); err == nil {
			for _, rr := range rres {
				if rr == nil || rr.URI == "" {
					continue
				}
				info.Resources = append(info.Resources, RemoteResourceInfo{
					Name:        rr.Name,
					URI:         rr.URI,
					ProxiedURI:  rc.proxiedURI(rr.URI),
					Description: rr.Description,
					MIMEType:    rr.MIMEType,
				})
			}
			slices.SortFunc(info.Resources, func(a, b RemoteResourceInfo) int { return strings.Compare(a.URI, b.URI) })
		}
		// Enrich with prompts
		if rprompts, err := rc.listRemotePrompts(ctx); err == nil {
			prefix := rc.prefix
			for _, p := range rprompts {
				if p == nil || p.Name == "" {
					continue
				}
				rp := RemotePromptInfo{
					Name:        p.Name,
					ProxiedName: prefix + p.Name,
					Description: p.Description,
				}
				if len(p.Arguments) > 0 {
					for _, a := range p.Arguments {
						if a == nil {
							continue
						}
						rp.Arguments = append(rp.Arguments, RemotePromptArgumentInfo{
							Name:        a.Name,
							Title:       a.Title,
							Description: a.Description,
							Required:    a.Required,
						})
					}
				}
				info.Prompts = append(info.Prompts, rp)
			}
			slices.SortFunc(info.Prompts, func(a, b RemotePromptInfo) int { return strings.Compare(a.Name, b.Name) })
		}
		// Enrich with resources
		if rres, err := rc.listRemoteResources(ctx); err == nil {
			for _, rr := range rres {
				if rr == nil || rr.URI == "" {
					continue
				}
				info.Resources = append(info.Resources, RemoteResourceInfo{
					Name:        rr.Name,
					URI:         rr.URI,
					ProxiedURI:  rc.proxiedURI(rr.URI),
					Description: rr.Description,
					MIMEType:    rr.MIMEType,
				})
			}
			slices.SortFunc(info.Resources, func(a, b RemoteResourceInfo) int { return strings.Compare(a.URI, b.URI) })
		}
		// Enrich with resource templates
		if rtemps, err := rc.listRemoteResourceTemplates(ctx); err == nil {
			for _, rt := range rtemps {
				if rt == nil || rt.URITemplate == "" {
					continue
				}
				info.ResourceTemplates = append(info.ResourceTemplates, RemoteResourceTemplateInfo{
					URITemplate: rt.URITemplate,
					Description: rt.Description,
					MIMEType:    rt.MIMEType,
				})
			}
			slices.SortFunc(info.ResourceTemplates, func(a, b RemoteResourceTemplateInfo) int { return strings.Compare(a.URITemplate, b.URITemplate) })
		}
		out.Servers = append(out.Servers, *info)
	}
	slices.SortFunc(out.Servers, func(a, b ServerInfo) int { return strings.Compare(a.Name, b.Name) })
	return out
}

// --- remote client management ---

type remoteClient struct {
	name    string
	command string
	args    []string
	dir     string
	env     map[string]string
	include map[string]struct{}
	exclude map[string]struct{}
	prefix  string

	server  *mcp.Server
	client  *mcp.Client
	session *mcp.ClientSession

	toolsByProxy map[string]*mcp.Tool // proxied name -> remote tool (original)
	proxyByTool  map[string]string    // original name -> proxied name

	promptsByProxy map[string]*mcp.Prompt // proxied name -> remote prompt
	proxyByPrompt  map[string]string      // original name -> proxied name

	resourcesByProxy map[string]string // proxied URI -> original remote URI
	proxyByResource  map[string]string // original remote URI -> proxied URI

	// track roots mirrored to remote client
	remoteRoots map[string]struct{} // uri -> present

	mu sync.Mutex
}

func (rc *remoteClient) info() *ServerInfo {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	var toolNames []string
	for name := range rc.toolsByProxy {
		toolNames = append(toolNames, name)
	}
	slices.Sort(toolNames)
	return &ServerInfo{
		Name:       rc.name,
		Command:    rc.command,
		Args:       append([]string(nil), rc.args...),
		Dir:        rc.dir,
		ToolPrefix: rc.prefix,
		Tools:      toolNames,
	}
}

func (rc *remoteClient) connect(ctx context.Context) error {
	// Prepare exec command for stdio transport
	cmd := exec.CommandContext(ctx, rc.command, rc.args...)
	if rc.dir != "" {
		cmd.Dir = rc.dir
	}
	if len(rc.env) > 0 {
		// Merge onto existing environment
		envMap := make(map[string]string)
		for _, kv := range os.Environ() {
			if i := strings.IndexByte(kv, '='); i >= 0 {
				envMap[kv[:i]] = kv[i+1:]
			}
		}
		for k, v := range rc.env {
			envMap[k] = v
		}
		var merged []string
		for k, v := range envMap {
			merged = append(merged, k+"="+v)
		}
		// Keep order stable-ish by sorting
		slices.Sort(merged)
		cmd.Env = merged
	}
	t := &mcp.CommandTransport{Command: cmd}

	// Create client with change handlers to keep proxy in sync.
	rc.client = mcp.NewClient(&mcp.Implementation{Name: "proxy-client-" + rc.name, Version: "v1.0.0"}, &mcp.ClientOptions{
		ToolListChangedHandler: func(ctx context.Context, _ *mcp.ToolListChangedRequest) {
			go func() {
				time.Sleep(100 * time.Millisecond)
				if _, err := rc.syncTools(context.Background()); err != nil {
					log.Printf("<%s> sync tools after change failed: %v", rc.name, err)
				}
			}()
		},
		PromptListChangedHandler: func(ctx context.Context, _ *mcp.PromptListChangedRequest) {
			go func() {
				time.Sleep(100 * time.Millisecond)
				if _, err := rc.syncPrompts(context.Background()); err != nil {
					log.Printf("<%s> sync prompts after change failed: %v", rc.name, err)
				}
			}()
		},
		ResourceListChangedHandler: func(ctx context.Context, _ *mcp.ResourceListChangedRequest) {
			go func() {
				time.Sleep(100 * time.Millisecond)
				if _, err := rc.syncResources(context.Background()); err != nil {
					log.Printf("<%s> sync resources after change failed: %v", rc.name, err)
				}
			}()
		},
		KeepAlive: 30 * time.Second,
	})

	// Connect
	cs, err := rc.client.Connect(ctx, t, nil)
	if err != nil {
		return fmt.Errorf("connect to remote: %w", err)
	}
	rc.session = cs
	// Initialize resource template for proxy reads (catch-all for this server)
	rc.installResourceTemplate()
	return nil
}

// close terminates the remote session.
func (rc *remoteClient) close() error {
	if rc.session != nil {
		return rc.session.Close()
	}
	return nil
}

// filter returns true if the tool name should be included.
func (rc *remoteClient) filter(toolName string) bool {
	// If an include set is present (non-nil), only those tools are enabled.
	if rc.include != nil {
		_, ok := rc.include[toolName]
		return ok
	}
	// Otherwise, exclude acts as a deny-list; default is enabled.
	if _, ex := rc.exclude[toolName]; ex {
		return false
	}
	return true
}

// syncTools lists remote tools and reconciles proxied tools on the primary server.
// It returns the number of proxied tools after synchronization.
func (rc *remoteClient) syncTools(ctx context.Context) (int, error) {
	if rc.session == nil {
		return 0, fmt.Errorf("not connected")
	}

	// Fetch the latest tool list (paged).
	toolsRes, err := rc.session.ListTools(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("list tools: %w", err)
	}

	// Aggregate all pages if more than one.
	current := append([]*mcp.Tool{}, toolsRes.Tools...)
	cursor := ""
	if toolsRes != nil {
		cursor = toolsRes.NextCursor
	}
	for cursor != "" {
		toolsRes, err = rc.session.ListTools(ctx, &mcp.ListToolsParams{Cursor: cursor})
		if err != nil {
			return 0, fmt.Errorf("list tools (page): %w", err)
		}
		current = append(current, toolsRes.Tools...)
		cursor = toolsRes.NextCursor
	}

	// Build sets for reconciliation.
	desired := make(map[string]*mcp.Tool) // original name -> tool
	for _, t := range current {
		if t == nil || t.Name == "" {
			continue
		}
		if !rc.filter(t.Name) {
			continue
		}
		desired[t.Name] = t
	}

	rc.mu.Lock()
	defer rc.mu.Unlock()

	// Remove tools no longer present or filtered out.
	var toRemove []string
	for origName, proxied := range rc.proxyByTool {
		if _, ok := desired[origName]; !ok {
			toRemove = append(toRemove, proxied)
		}
	}
	if len(toRemove) > 0 {
		rc.server.RemoveTools(toRemove...)
		for _, pn := range toRemove {
			orig := ""
			if o, ok := rc.toolsByProxy[pn]; ok {
				orig = o.Name
			}
			delete(rc.toolsByProxy, pn)
			if orig != "" {
				delete(rc.proxyByTool, orig)
			}
		}
	}

	// Add or update desired tools.
	for origName, rt := range desired {
		proxiedName := rc.prefix + origName
		// If already present, update by re-adding if schemas/desc changed.
		// For simplicity, always re-add: Server.AddTool replaces existing.
		handler := rc.forwardHandler(origName)

		// Make a shallow copy of the tool struct with a new name.
		tt := *rt
		tt.Name = proxiedName
		if tt.InputSchema == nil {
			// Enforce SDK requirements. Remote servers should include schemas,
			// but if not, reject this tool to avoid undefined behavior.
			log.Printf("<%s> skipping tool %q due to missing input schema", rc.name, origName)
			continue
		}

		rc.server.AddTool(&tt, handler)
		rc.toolsByProxy[proxiedName] = rt
		rc.proxyByTool[origName] = proxiedName
	}

	return len(rc.toolsByProxy), nil
}

// syncPrompts lists remote prompts and reconciles proxied prompts.
func (rc *remoteClient) syncPrompts(ctx context.Context) (int, error) {
	if rc.session == nil {
		return 0, fmt.Errorf("not connected")
	}
	// List prompts (paged)
	res, err := rc.session.ListPrompts(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("list prompts: %w", err)
	}
	current := append([]*mcp.Prompt{}, res.Prompts...)
	cursor := res.NextCursor
	for cursor != "" {
		res, err = rc.session.ListPrompts(ctx, &mcp.ListPromptsParams{Cursor: cursor})
		if err != nil {
			return 0, fmt.Errorf("list prompts (page): %w", err)
		}
		current = append(current, res.Prompts...)
		cursor = res.NextCursor
	}

	desired := make(map[string]*mcp.Prompt)
	for _, p := range current {
		if p == nil || p.Name == "" {
			continue
		}
		desired[p.Name] = p
	}

	if rc.promptsByProxy == nil {
		rc.promptsByProxy = make(map[string]*mcp.Prompt)
	}
	if rc.proxyByPrompt == nil {
		rc.proxyByPrompt = make(map[string]string)
	}

	// Remove
	var toRemove []string
	for orig, prox := range rc.proxyByPrompt {
		if _, ok := desired[orig]; !ok {
			toRemove = append(toRemove, prox)
		}
	}
	if len(toRemove) > 0 {
		rc.server.RemovePrompts(toRemove...)
		for _, pn := range toRemove {
			orig := ""
			for o, p := range rc.proxyByPrompt {
				if p == pn {
					orig = o
					break
				}
			}
			delete(rc.promptsByProxy, pn)
			if orig != "" {
				delete(rc.proxyByPrompt, orig)
			}
		}
	}

	// Add/update
	for origName, rp := range desired {
		proxName := rc.prefix + origName
		pcopy := *rp
		pcopy.Name = proxName
		handler := rc.forwardPromptHandler(origName)
		rc.server.AddPrompt(&pcopy, handler)
		rc.promptsByProxy[proxName] = rp
		rc.proxyByPrompt[origName] = proxName
	}
	return len(rc.promptsByProxy), nil
}

// syncResources lists remote resources and reconciles proxied resources.
func (rc *remoteClient) syncResources(ctx context.Context) (int, error) {
	if rc.session == nil {
		return 0, fmt.Errorf("not connected")
	}
	// List resources
	res, err := rc.session.ListResources(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("list resources: %w", err)
	}
	current := append([]*mcp.Resource{}, res.Resources...)
	cursor := res.NextCursor
	for cursor != "" {
		res, err = rc.session.ListResources(ctx, &mcp.ListResourcesParams{Cursor: cursor})
		if err != nil {
			return 0, fmt.Errorf("list resources (page): %w", err)
		}
		current = append(current, res.Resources...)
		cursor = res.NextCursor
	}

	desired := make(map[string]*mcp.Resource) // by original URI
	for _, r := range current {
		if r == nil || r.URI == "" {
			continue
		}
		desired[r.URI] = r
	}

	if rc.resourcesByProxy == nil {
		rc.resourcesByProxy = make(map[string]string)
	}
	if rc.proxyByResource == nil {
		rc.proxyByResource = make(map[string]string)
	}

	// Remove missing
	var toRemove []string
	for orig, prox := range rc.proxyByResource {
		if _, ok := desired[orig]; !ok {
			toRemove = append(toRemove, prox)
		}
	}
	if len(toRemove) > 0 {
		rc.server.RemoveResources(toRemove...)
		for _, pu := range toRemove {
			orig := rc.resourcesByProxy[pu]
			delete(rc.resourcesByProxy, pu)
			if orig != "" {
				delete(rc.proxyByResource, orig)
			}
		}
	}

	// Add/update resources using proxied URI
	for origURI, rr := range desired {
		proxURI := rc.proxiedURI(origURI)
		rcopy := *rr
		rcopy.URI = proxURI
		handler := rc.forwardResourceHandler()
		rc.server.AddResource(&rcopy, handler)
		rc.resourcesByProxy[proxURI] = origURI
		rc.proxyByResource[origURI] = proxURI
	}
	return len(rc.resourcesByProxy), nil
}

// installResourceTemplate installs a catch-all template for this remote to support ad-hoc URIs.
func (rc *remoteClient) installResourceTemplate() {
	// URITemplate to match any proxied URI: proxy://<name>/{orig}
	tmpl := &mcp.ResourceTemplate{
		URITemplate: "proxy://" + rc.name + "/{orig}",
	}
	rc.server.AddResourceTemplate(tmpl, rc.forwardResourceHandler())
}

// proxiedURI builds a proxy URI for a remote URI.
func (rc *remoteClient) proxiedURI(orig string) string {
	// Percent-encode full original URI into path
	return "proxy://" + rc.name + "/" + url.PathEscape(orig)
}

// decodeProxiedURI returns (serverName, original) from a proxied URI, if it matches.
func decodeProxiedURI(uri string) (string, string, bool) {
	u, err := url.Parse(uri)
	if err != nil {
		return "", "", false
	}
	if u.Scheme != "proxy" {
		return "", "", false
	}
	serverName := u.Host
	raw := strings.TrimPrefix(u.Path, "/")
	orig, err := url.PathUnescape(raw)
	if err != nil {
		return "", "", false
	}
	return serverName, orig, true
}

// removeAll removes all proxied tools for this remote.
func (rc *remoteClient) removeAll() int {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	removed := 0
	if len(rc.toolsByProxy) > 0 {
		var names []string
		for name := range rc.toolsByProxy {
			names = append(names, name)
		}
		rc.server.RemoveTools(names...)
		removed += len(names)
		rc.toolsByProxy = make(map[string]*mcp.Tool)
		rc.proxyByTool = make(map[string]string)
	}
	if len(rc.promptsByProxy) > 0 {
		var names []string
		for name := range rc.promptsByProxy {
			names = append(names, name)
		}
		rc.server.RemovePrompts(names...)
		removed += len(names)
		rc.promptsByProxy = make(map[string]*mcp.Prompt)
		rc.proxyByPrompt = make(map[string]string)
	}
	if len(rc.resourcesByProxy) > 0 {
		var uris []string
		for uri := range rc.resourcesByProxy {
			uris = append(uris, uri)
		}
		rc.server.RemoveResources(uris...)
		removed += len(uris)
		rc.resourcesByProxy = make(map[string]string)
		rc.proxyByResource = make(map[string]string)
	}
	return removed
}

func (rc *remoteClient) forwardHandler(remoteToolName string) mcp.ToolHandler {
	return func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		if rc.session == nil {
			return nil, fmt.Errorf("remote session not connected")
		}
		params := &mcp.CallToolParams{Name: remoteToolName}
		// Preserve arguments as raw JSON if present.
		if req != nil && req.Params != nil && req.Params.Arguments != nil {
			params.Arguments = req.Params.Arguments
		} else {
			params.Arguments = map[string]any{}
		}
		return rc.session.CallTool(ctx, params)
	}
}

func (rc *remoteClient) forwardPromptHandler(remotePrompt string) mcp.PromptHandler {
	return func(ctx context.Context, req *mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
		if rc.session == nil {
			return nil, fmt.Errorf("remote session not connected")
		}
		args := &mcp.GetPromptParams{Name: remotePrompt}
		if req != nil && req.Params != nil {
			// forward arguments verbatim
			args.Arguments = req.Params.Arguments
		}
		return rc.session.GetPrompt(ctx, args)
	}
}

func (rc *remoteClient) forwardResourceHandler() mcp.ResourceHandler {
	return func(ctx context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
		if rc.session == nil {
			return nil, fmt.Errorf("remote session not connected")
		}
		if req == nil || req.Params == nil {
			return nil, fmt.Errorf("invalid request")
		}
		// Map proxied URI back to original
		_, orig, ok := decodeProxiedURI(req.Params.URI)
		if !ok {
			return nil, mcp.ResourceNotFoundError(req.Params.URI)
		}
		return rc.session.ReadResource(ctx, &mcp.ReadResourceParams{URI: orig})
	}
}

// Propagate local client roots to the remote server by setting client roots on our remote client.
func (rc *remoteClient) setRemoteRoots(newRoots []*mcp.Root) {
	// Convert to set
	newSet := make(map[string]*mcp.Root, len(newRoots))
	for _, r := range newRoots {
		if r != nil && r.URI != "" {
			newSet[r.URI] = r
		}
	}
	if rc.remoteRoots == nil {
		rc.remoteRoots = make(map[string]struct{})
	}

	// Remove missing
	var toRemove []string
	for uri := range rc.remoteRoots {
		if _, ok := newSet[uri]; !ok {
			toRemove = append(toRemove, uri)
		}
	}
	if len(toRemove) > 0 {
		rc.client.RemoveRoots(toRemove...)
	}

	// Add new
	var toAdd []*mcp.Root
	for uri, root := range newSet {
		if _, ok := rc.remoteRoots[uri]; !ok {
			toAdd = append(toAdd, root)
		}
	}
	if len(toAdd) > 0 {
		rc.client.AddRoots(toAdd...)
	}

	// Update snapshot
	rc.remoteRoots = make(map[string]struct{}, len(newSet))
	for uri := range newSet {
		rc.remoteRoots[uri] = struct{}{}
	}
}

// HandleLocalRootsChanged propagates current client roots to all remotes.
func (pm *ProxyManager) HandleLocalRootsChanged(ctx context.Context, ss *mcp.ServerSession) error {
	// Fetch roots from this client session
	res, err := ss.ListRoots(ctx, nil)
	if err != nil {
		return err
	}
	pm.mu.Lock()
	remotes := make([]*remoteClient, 0, len(pm.remotes))
	for _, rc := range pm.remotes {
		remotes = append(remotes, rc)
	}
	pm.mu.Unlock()
	for _, rc := range remotes {
		rc.setRemoteRoots(res.Roots)
	}
	return nil
}

// --- helpers ---

// listRemoteToolNames returns the list of tool names available on the remote server.
func (rc *remoteClient) listRemoteToolNames(ctx context.Context) ([]string, error) {
	if rc.session == nil {
		return nil, fmt.Errorf("not connected")
	}
	res, err := rc.session.ListTools(ctx, nil)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(res.Tools))
	for _, t := range res.Tools {
		if t != nil && t.Name != "" {
			names = append(names, t.Name)
		}
	}
	cursor := res.NextCursor
	for cursor != "" {
		res, err = rc.session.ListTools(ctx, &mcp.ListToolsParams{Cursor: cursor})
		if err != nil {
			return nil, err
		}
		for _, t := range res.Tools {
			if t != nil && t.Name != "" {
				names = append(names, t.Name)
			}
		}
		cursor = res.NextCursor
	}
	return names, nil
}

func (rc *remoteClient) listRemotePromptNames(ctx context.Context) ([]string, error) {
	if rc.session == nil {
		return nil, fmt.Errorf("not connected")
	}
	res, err := rc.session.ListPrompts(ctx, nil)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(res.Prompts))
	for _, p := range res.Prompts {
		if p != nil && p.Name != "" {
			names = append(names, p.Name)
		}
	}
	cursor := res.NextCursor
	for cursor != "" {
		res, err = rc.session.ListPrompts(ctx, &mcp.ListPromptsParams{Cursor: cursor})
		if err != nil {
			return nil, err
		}
		for _, p := range res.Prompts {
			if p != nil && p.Name != "" {
				names = append(names, p.Name)
			}
		}
		cursor = res.NextCursor
	}
	return names, nil
}

// listRemotePrompts returns the full set of prompts available from the remote.
func (rc *remoteClient) listRemotePrompts(ctx context.Context) ([]*mcp.Prompt, error) {
	if rc.session == nil {
		return nil, fmt.Errorf("not connected")
	}
	res, err := rc.session.ListPrompts(ctx, nil)
	if err != nil {
		return nil, err
	}
	prompts := append([]*mcp.Prompt{}, res.Prompts...)
	cursor := res.NextCursor
	for cursor != "" {
		res, err = rc.session.ListPrompts(ctx, &mcp.ListPromptsParams{Cursor: cursor})
		if err != nil {
			return nil, err
		}
		prompts = append(prompts, res.Prompts...)
		cursor = res.NextCursor
	}
	return prompts, nil
}

// listRemoteResources returns the full set of resources available from the remote.
func (rc *remoteClient) listRemoteResources(ctx context.Context) ([]*mcp.Resource, error) {
	if rc.session == nil {
		return nil, fmt.Errorf("not connected")
	}
	res, err := rc.session.ListResources(ctx, nil)
	if err != nil {
		return nil, err
	}
	resources := append([]*mcp.Resource{}, res.Resources...)
	cursor := res.NextCursor
	for cursor != "" {
		res, err = rc.session.ListResources(ctx, &mcp.ListResourcesParams{Cursor: cursor})
		if err != nil {
			return nil, err
		}
		resources = append(resources, res.Resources...)
		cursor = res.NextCursor
	}
	return resources, nil
}

// listRemoteResourceTemplates returns the full set of resource templates available from the remote.
func (rc *remoteClient) listRemoteResourceTemplates(ctx context.Context) ([]*mcp.ResourceTemplate, error) {
	if rc.session == nil {
		return nil, fmt.Errorf("not connected")
	}
	res, err := rc.session.ListResourceTemplates(ctx, nil)
	if err != nil {
		return nil, err
	}
	rts := append([]*mcp.ResourceTemplate{}, res.ResourceTemplates...)
	cursor := res.NextCursor
	for cursor != "" {
		res, err = rc.session.ListResourceTemplates(ctx, &mcp.ListResourceTemplatesParams{Cursor: cursor})
		if err != nil {
			return nil, err
		}
		rts = append(rts, res.ResourceTemplates...)
		cursor = res.NextCursor
	}
	return rts, nil
}

// listRemoteTools returns the full set of tools available from the remote.
func (rc *remoteClient) listRemoteTools(ctx context.Context) ([]*mcp.Tool, error) {
	if rc.session == nil {
		return nil, fmt.Errorf("not connected")
	}
	res, err := rc.session.ListTools(ctx, nil)
	if err != nil {
		return nil, err
	}
	tools := append([]*mcp.Tool{}, res.Tools...)
	cursor := res.NextCursor
	for cursor != "" {
		res, err = rc.session.ListTools(ctx, &mcp.ListToolsParams{Cursor: cursor})
		if err != nil {
			return nil, err
		}
		tools = append(tools, res.Tools...)
		cursor = res.NextCursor
	}
	return tools, nil
}

// serverToolNames returns the current tool names on the primary server by connecting via in-memory transport.
func (pm *ProxyManager) serverToolNames(ctx context.Context) (map[string]struct{}, error) {
	tServer, tClient := mcp.NewInMemoryTransports()
	ss, err := pm.server.Connect(ctx, tServer, nil)
	if err != nil {
		return nil, err
	}
	defer ss.Close()
	client := mcp.NewClient(&mcp.Implementation{Name: "proxy-introspect", Version: "v1.0.0"}, nil)
	cs, err := client.Connect(ctx, tClient, nil)
	if err != nil {
		return nil, err
	}
	defer cs.Close()
	res, err := cs.ListTools(ctx, nil)
	if err != nil {
		return nil, err
	}
	names := map[string]struct{}{}
	for _, t := range res.Tools {
		if t != nil && t.Name != "" {
			names[t.Name] = struct{}{}
		}
	}
	cursor := res.NextCursor
	for cursor != "" {
		res, err = cs.ListTools(ctx, &mcp.ListToolsParams{Cursor: cursor})
		if err != nil {
			return nil, err
		}
		for _, t := range res.Tools {
			if t != nil && t.Name != "" {
				names[t.Name] = struct{}{}
			}
		}
		cursor = res.NextCursor
	}
	return names, nil
}

// serverPromptNames returns the current prompt names on the primary server.
func (pm *ProxyManager) serverPromptNames(ctx context.Context) (map[string]struct{}, error) {
	tServer, tClient := mcp.NewInMemoryTransports()
	ss, err := pm.server.Connect(ctx, tServer, nil)
	if err != nil {
		return nil, err
	}
	defer ss.Close()
	client := mcp.NewClient(&mcp.Implementation{Name: "proxy-introspect", Version: "v1.0.0"}, nil)
	cs, err := client.Connect(ctx, tClient, nil)
	if err != nil {
		return nil, err
	}
	defer cs.Close()
	res, err := cs.ListPrompts(ctx, nil)
	if err != nil {
		return nil, err
	}
	names := map[string]struct{}{}
	for _, p := range res.Prompts {
		if p != nil && p.Name != "" {
			names[p.Name] = struct{}{}
		}
	}
	cursor := res.NextCursor
	for cursor != "" {
		res, err = cs.ListPrompts(ctx, &mcp.ListPromptsParams{Cursor: cursor})
		if err != nil {
			return nil, err
		}
		for _, p := range res.Prompts {
			if p != nil && p.Name != "" {
				names[p.Name] = struct{}{}
			}
		}
		cursor = res.NextCursor
	}
	return names, nil
}

// checkPromptCollisions validates that prompts don't collide.
func (pm *ProxyManager) checkPromptCollisions(ctx context.Context, proposed []string, exclude map[string]struct{}) error {
	existing, err := pm.serverPromptNames(ctx)
	if err != nil {
		return err
	}
	var conflicts []string
	for _, name := range proposed {
		if _, ok := existing[name]; ok {
			if exclude != nil {
				if _, ex := exclude[name]; ex {
					continue
				}
			}
			conflicts = append(conflicts, name)
		}
	}
	if len(conflicts) > 0 {
		return fmt.Errorf("prompt collision: the following prompt names already exist: %s", strings.Join(conflicts, ", "))
	}
	return nil
}

// checkCollisions validates that none of proposed names are present in the server tool set,
// excluding names present in exclude.
func (pm *ProxyManager) checkCollisions(ctx context.Context, proposed []string, exclude map[string]struct{}) error {
	existing, err := pm.serverToolNames(ctx)
	if err != nil {
		return err
	}
	var conflicts []string
	for _, name := range proposed {
		if _, ok := existing[name]; ok {
			if exclude != nil {
				if _, ex := exclude[name]; ex {
					continue
				}
			}
			conflicts = append(conflicts, name)
		}
	}
	if len(conflicts) > 0 {
		return fmt.Errorf("prefix collision: the following tool names already exist: %s", strings.Join(conflicts, ", "))
	}
	return nil
}

// UpdateServerRequest provides fields for updating an existing remote server configuration.
type UpdateServerRequest struct {
	Name    string             `json:"name"`
	Prefix  *string            `json:"prefix,omitempty"`
	Include *[]string          `json:"include,omitempty"`
	Exclude *[]string          `json:"exclude,omitempty"`
	Command *string            `json:"command,omitempty"`
	Args    *[]string          `json:"args,omitempty"`
	Env     *map[string]string `json:"env,omitempty"`
	Dir     *string            `json:"dir,omitempty"`
}

// UpdateServer updates an existing remote config and resyncs tools. May restart the child process if needed.
func (pm *ProxyManager) UpdateServer(ctx context.Context, req *UpdateServerRequest) (*ServerInfo, error) {
	if req == nil || strings.TrimSpace(req.Name) == "" {
		return nil, fmt.Errorf("name is required")
	}
	pm.mu.Lock()
	rc := pm.remotes[req.Name]
	pm.mu.Unlock()
	if rc == nil {
		return nil, fmt.Errorf("server not found: %s", req.Name)
	}

	// Build new config based on existing rc
	newPrefix := rc.prefix
	if req.Prefix != nil {
		newPrefix = *req.Prefix
	}
	newInclude := rc.include
	if req.Include != nil {
		newInclude = setFromSlice(*req.Include)
	}
	newExclude := rc.exclude
	if req.Exclude != nil {
		newExclude = setFromSlice(*req.Exclude)
	}
	newCommand := rc.command
	if req.Command != nil {
		newCommand = *req.Command
	}
	newArgs := rc.args
	if req.Args != nil {
		newArgs = append([]string(nil), (*req.Args)...)
	}
	newDir := rc.dir
	if req.Dir != nil {
		newDir = *req.Dir
	}
	newEnv := rc.env
	if req.Env != nil {
		newEnv = *req.Env
	}

	// Determine if a restart is required.
	restart := newCommand != rc.command || !slices.Equal(newArgs, rc.args) || newDir != rc.dir || !envEqual(newEnv, rc.env)
	prefixChanged := newPrefix != rc.prefix

	// Obtain remote tool names using the appropriate session.
	var remoteNames []string
	var newRC *remoteClient
	if restart {
		tmp := &remoteClient{
			name:         rc.name,
			command:      newCommand,
			args:         newArgs,
			dir:          newDir,
			env:          newEnv,
			include:      newInclude,
			exclude:      newExclude,
			prefix:       newPrefix,
			server:       pm.server,
			toolsByProxy: make(map[string]*mcp.Tool),
			proxyByTool:  make(map[string]string),
		}
		if err := tmp.connect(ctx); err != nil {
			return nil, fmt.Errorf("connect new config: %w", err)
		}
		defer func() {
			if newRC == nil { // if we didn't adopt tmp, close it
				_ = tmp.close()
			}
		}()
		names, err := tmp.listRemoteToolNames(ctx)
		if err != nil {
			return nil, fmt.Errorf("list remote tools: %w", err)
		}
		remoteNames = names
		newRC = tmp
	} else {
		names, err := rc.listRemoteToolNames(ctx)
		if err != nil {
			return nil, fmt.Errorf("list remote tools: %w", err)
		}
		remoteNames = names
	}

	// Validate collisions for new prefix against current server tools/prompts, excluding this rc's current proxied names.
	exclude := make(map[string]struct{}, len(rc.toolsByProxy))
	for name := range rc.toolsByProxy {
		exclude[name] = struct{}{}
	}
	proposed := make([]string, 0, len(remoteNames))
	pfx := newPrefix
	for _, n := range remoteNames {
		proposed = append(proposed, pfx+n)
	}
	if err := pm.checkCollisions(ctx, proposed, exclude); err != nil {
		return nil, err
	}

	// Validate prompt collisions
	var promptNames []string
	if restart && newRC != nil {
		if names, err := newRC.listRemotePromptNames(ctx); err == nil {
			promptNames = names
		} else {
			return nil, err
		}
	} else {
		if names, err := rc.listRemotePromptNames(ctx); err == nil {
			promptNames = names
		} else {
			return nil, err
		}
	}
	excludePrompts := make(map[string]struct{}, len(rc.promptsByProxy))
	for name := range rc.promptsByProxy {
		excludePrompts[name] = struct{}{}
	}
	proposedPrompts := make([]string, 0, len(promptNames))
	for _, n := range promptNames {
		proposedPrompts = append(proposedPrompts, pfx+n)
	}
	if err := pm.checkPromptCollisions(ctx, proposedPrompts, excludePrompts); err != nil {
		return nil, err
	}

	// Apply the update
	if restart {
		// Add new items first (will replace if same names), then remove old ones and close old session.
		if _, err := newRC.syncTools(ctx); err != nil {
			return nil, err
		}
		if _, err := newRC.syncPrompts(ctx); err != nil {
			return nil, err
		}
		if _, err := newRC.syncResources(ctx); err != nil {
			return nil, err
		}
		oldRemoved := rc.removeAll()
		_ = rc.close()

		// Replace reference
		pm.mu.Lock()
		pm.remotes[rc.name] = newRC
		pm.mu.Unlock()
		rc = newRC
		log.Printf("<%s> updated server (restarted); removed %d old tools", rc.name, oldRemoved)
	} else {
		// Update filters
		rc.include = newInclude
		rc.exclude = newExclude

		if prefixChanged {
			// Rename prefix without downtime: add new names, then remove old names across tools/prompts/resources.
			oldToolNames := make([]string, 0, len(rc.toolsByProxy))
			for name := range rc.toolsByProxy {
				oldToolNames = append(oldToolNames, name)
			}
			oldPromptNames := make([]string, 0, len(rc.promptsByProxy))
			for name := range rc.promptsByProxy {
				oldPromptNames = append(oldPromptNames, name)
			}
			oldResourceURIs := make([]string, 0, len(rc.resourcesByProxy))
			for uri := range rc.resourcesByProxy {
				oldResourceURIs = append(oldResourceURIs, uri)
			}

			// Temporarily set prefix to newPrefix for adding
			oldPrefix := rc.prefix
			rc.prefix = newPrefix
			if _, err := rc.syncTools(ctx); err != nil {
				// Restore prefix on failure
				rc.prefix = oldPrefix
				return nil, err
			}
			if _, err := rc.syncPrompts(ctx); err != nil {
				rc.prefix = oldPrefix
				return nil, err
			}
			if _, err := rc.syncResources(ctx); err != nil {
				rc.prefix = oldPrefix
				return nil, err
			}
			// Remove old names
			if len(oldToolNames) > 0 {
				rc.server.RemoveTools(oldToolNames...)
			}
			if len(oldPromptNames) > 0 {
				rc.server.RemovePrompts(oldPromptNames...)
			}
			if len(oldResourceURIs) > 0 {
				rc.server.RemoveResources(oldResourceURIs...)
			}
			log.Printf("<%s> updated prefix from %q to %q", rc.name, oldPrefix, newPrefix)
		} else {
			if _, err := rc.syncTools(ctx); err != nil {
				return nil, err
			}
			if _, err := rc.syncPrompts(ctx); err != nil {
				return nil, err
			}
			if _, err := rc.syncResources(ctx); err != nil {
				return nil, err
			}
		}
	}

	return rc.info(), nil
}

// envEqual compares maps treating nil as empty.
func envEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// SetEnabledToolsRequest updates the enabled set for a remote server.
// If Enabled contains all remote tools, the include/exclude filters are cleared (all enabled).
type SetEnabledToolsRequest struct {
	Name    string   `json:"name"`
	Enabled []string `json:"enabled"`
}

// HandleSetEnabledTools handles POST /set-enabled-tools.
func (pm *ProxyManager) HandleSetEnabledTools(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	var req SetEnabledToolsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("invalid JSON: %v", err), http.StatusBadRequest)
		return
	}
	info, err := pm.SetEnabledTools(r.Context(), &req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(info)
}

// SetEnabledTools updates the enabled set for a remote and resyncs.
func (pm *ProxyManager) SetEnabledTools(ctx context.Context, req *SetEnabledToolsRequest) (*ServerInfo, error) {
	if req == nil || strings.TrimSpace(req.Name) == "" {
		return nil, fmt.Errorf("name is required")
	}
	pm.mu.Lock()
	rc := pm.remotes[req.Name]
	pm.mu.Unlock()
	if rc == nil {
		return nil, fmt.Errorf("server not found: %s", req.Name)
	}

	// Validate requested names against actual remote tools and compute collisions
	remoteNames, err := rc.listRemoteToolNames(ctx)
	if err != nil {
		return nil, err
	}
	remoteSet := setFromSlice(remoteNames)
	// Ensure all requested names exist remotely
	for _, n := range req.Enabled {
		if _, ok := remoteSet[n]; !ok {
			return nil, fmt.Errorf("unknown remote tool: %s", n)
		}
	}

	// Compute proposed proxied names for enabled set and check collisions (excluding our current proxied names)
	exclude := make(map[string]struct{}, len(rc.toolsByProxy))
	rc.mu.Lock()
	for name := range rc.toolsByProxy {
		exclude[name] = struct{}{}
	}
	prefix := rc.prefix
	rc.mu.Unlock()
	proposed := make([]string, 0, len(req.Enabled))
	for _, n := range req.Enabled {
		proposed = append(proposed, prefix+n)
	}
	if err := pm.checkCollisions(ctx, proposed, exclude); err != nil {
		return nil, err
	}

	// Apply filters: if enabling all remote tools, clear include/exclude (default all-enabled)
	if len(req.Enabled) == len(remoteNames) {
		rc.include = nil
		rc.exclude = nil
	} else {
		rc.include = setFromSlice(req.Enabled)
		rc.exclude = nil
	}

	if _, err := rc.syncTools(ctx); err != nil {
		return nil, err
	}
	return rc.info(), nil
}

func setFromSlice(v []string) map[string]struct{} {
	if len(v) == 0 {
		return nil
	}
	m := make(map[string]struct{}, len(v))
	for _, s := range v {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		m[s] = struct{}{}
	}
	return m
}
