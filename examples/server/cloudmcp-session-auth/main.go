// Copyright 2025 The Go MCP SDK Authors. All rights reserved.
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// cloudMCPSession mirrors the response schema from
// https://cloudmcp.run/api/auth/mcp/get-session
type cloudMCPSession struct {
	ID                    string    `json:"id"`
	UserID                string    `json:"userId,omitempty"`
	AccessToken           string    `json:"accessToken"`
	RefreshToken          string    `json:"refreshToken"`
	AccessTokenExpiresAt  time.Time `json:"accessTokenExpiresAt"`
	RefreshTokenExpiresAt time.Time `json:"refreshTokenExpiresAt"`
	ClientID              string    `json:"clientId"`
	Scopes                string    `json:"scopes"`
	CreatedAt             time.Time `json:"createdAt,omitempty"`
	UpdatedAt             time.Time `json:"updatedAt,omitempty"`
}

var (
	httpAddr = flag.String("http", ":8080", "HTTP address to listen on (overrides ADDR)")
)

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// computeBaseURL builds the public base URL for this server.
// Prefers Fly.io + router domain if ACCOUNT_ID and FLY_ALLOC_ID are present,
// otherwise falls back to localhost for development.
func computeBaseURL() string {
	routerDomain := os.Getenv("ROUTER_DOMAIN")
	if routerDomain == "" {
		routerDomain = "router.cloudmcp.run"
	}
	accountID := os.Getenv("ACCOUNT_ID")
	flyMachineID := os.Getenv("FLY_ALLOC_ID")
	if flyMachineID != "" {
		parts := strings.Split(flyMachineID, "-")
		if len(parts) > 0 {
			flyMachineID = parts[0]
		}
	}
	if accountID != "" && flyMachineID != "" && routerDomain != "" {
		return fmt.Sprintf("https://%s-%s.%s", accountID, flyMachineID, routerDomain)
	}
	return "http://localhost:8080"
}

// parseAuthServers returns the list of authorization servers for metadata.
// Fixed to CloudMCP per requirements.
func parseAuthServers() []string { return []string{"https://cloudmcp.run"} }

// NewCloudMCPSessionVerifier returns a TokenVerifier that calls the CloudMCP
// get-session endpoint using the presented access token, verifies the user and
// expiry, and maps into auth.TokenInfo.
func NewCloudMCPSessionVerifier(expectedUserID, endpoint string) auth.TokenVerifier {
	hc := &http.Client{Timeout: 5 * time.Second}

	parseScopes := func(s string) []string {
		// Accept comma or space-separated scopes.
		s = strings.ReplaceAll(s, ",", " ")
		return strings.Fields(s)
	}

	return func(ctx context.Context, accessToken string, _ *http.Request) (*auth.TokenInfo, error) {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		req.Header.Set("Authorization", "Bearer "+accessToken)

		res, err := hc.Do(req)
		if err != nil {
			// Upstream or network failure: server error
			return nil, fmt.Errorf("get-session request failed: %w", err)
		}
		defer res.Body.Close()

		if res.StatusCode == http.StatusUnauthorized || res.StatusCode == http.StatusForbidden {
			// Invalid token
			return nil, fmt.Errorf("%w: unauthorized", auth.ErrInvalidToken)
		}
		if res.StatusCode/100 != 2 {
			// Treat non-2xx as provider/OAuth failure
			return nil, fmt.Errorf("%w: get-session status %s", auth.ErrOAuth, res.Status)
		}

		var s cloudMCPSession
		if err := json.NewDecoder(res.Body).Decode(&s); err != nil {
			return nil, fmt.Errorf("%w: %v", auth.ErrOAuth, err)
		}

		if expectedUserID != "" && s.UserID != expectedUserID {
			return nil, fmt.Errorf("%w: user mismatch", auth.ErrInvalidToken)
		}

		if s.AccessTokenExpiresAt.IsZero() || time.Now().After(s.AccessTokenExpiresAt) {
			return nil, fmt.Errorf("%w: token expired", auth.ErrInvalidToken)
		}

		// Optionally ensure the returned access token corresponds to the one presented.
		if s.AccessToken != "" && s.AccessToken != accessToken {
			return nil, fmt.Errorf("%w: token mismatch", auth.ErrInvalidToken)
		}

		return &auth.TokenInfo{
			Scopes:     parseScopes(s.Scopes),
			Expiration: s.AccessTokenExpiresAt,
			Extra: map[string]any{
				"userId":    s.UserID,
				"clientId":  s.ClientID,
				"sessionId": s.ID,
			},
		}, nil
	}
}

// whoAmI returns selected info from the verified token/session.
func whoAmI(ctx context.Context, req *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, any, error) {
	ti := req.Extra.TokenInfo
	info := map[string]any{
		"userId":    ti.Extra["userId"],
		"clientId":  ti.Extra["clientId"],
		"sessionId": ti.Extra["sessionId"],
		"scopes":    ti.Scopes,
		"expiresAt": ti.Expiration.Format(time.RFC3339),
	}
	b, _ := json.Marshal(info)
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(b)}}}, nil, nil
}

func main() {
    flag.Parse()

    addr := envOrDefault("ADDR", *httpAddr)
    expectedUserID := envOrDefault("USER_ID", "")
    getSessionURL := envOrDefault("CLOUDMCP_GET_SESSION_URL", "https://cloudmcp.run/api/auth/mcp/get-session")

    verifier := NewCloudMCPSessionVerifier(expectedUserID, getSessionURL)

    // Build MCP server
    // Install a RootsListChanged handler to propagate client roots to remotes.
    var (
        serverOpts mcp.ServerOptions
        proxy      *ProxyManager
    )
	proxyRootsFn := func(ctx context.Context, req *mcp.RootsListChangedRequest) {
		if proxy != nil {
			if err := proxy.HandleLocalRootsChanged(ctx, req.Session); err != nil {
				log.Printf("syncing remote roots failed: %v", err)
			}
		}
	}
	serverOpts.RootsListChangedHandler = proxyRootsFn
    server := mcp.NewServer(&mcp.Implementation{Name: "cloudmcp-session-auth", Version: "v1.0.0"}, &serverOpts)

    // Initialize Polar client for usage tracking (optional; no-op if not configured)
    polarClient := NewPolarClient()

    // Add a receiving middleware to enforce credits BEFORE tool execution
    server.AddReceivingMiddleware(func(next mcp.MethodHandler) mcp.MethodHandler {
        return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
            if method == "tools/call" {
                var userID string
                if extra := req.GetExtra(); extra != nil && extra.TokenInfo != nil {
                    if uid, _ := extra.TokenInfo.Extra["userId"].(string); uid != "" {
                        userID = uid
                    }
                }
                if err := polarClient.CheckMeterBalance(ctx, userID); err != nil {
                    // Deny the call with a tool-style error result to the client
                    return &mcp.CallToolResult{
                        Content: []mcp.Content{&mcp.TextContent{Text: err.Error()}},
                        IsError: true,
                    }, nil
                }
            }
            return next(ctx, method, req)
        }
    })

    // Add a receiving middleware to track successful tool calls
    // This runs after the tool handler completes successfully.
    server.AddReceivingMiddleware(func(next mcp.MethodHandler) mcp.MethodHandler {
        return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
            // Invoke the underlying handler first
            res, err := next(ctx, method, req)

            // After a successful tools/call, record usage for the authenticated user
            if method == "tools/call" && err == nil {
                if ctr, ok := res.(*mcp.CallToolResult); ok && ctr != nil && !ctr.IsError {
                    if extra := req.GetExtra(); extra != nil && extra.TokenInfo != nil {
                        // userId is provided by our CloudMCP session verifier in TokenInfo.Extra
                        if uid, _ := extra.TokenInfo.Extra["userId"].(string); uid != "" {
                            // Track asynchronously to avoid adding latency to tool calls
                            go polarClient.TrackUsage(context.Background(), uid)
                        }
                    }
                }
            }

            return res, err
        }
    })
	mcp.AddTool(server, &mcp.Tool{Name: "whoami", Description: "Return info from verified token/session"}, whoAmI)

	// Create proxy manager for dynamic tool aggregation from other MCP servers.
	proxy = NewProxyManager(server)

	// Wrap the streamable handler with auth middleware
	handler := mcp.NewStreamableHTTPHandler(func(r *http.Request) *mcp.Server { return server }, nil)
	// Build base URL per environment (Fly router or localhost)
	baseURL := computeBaseURL()
	// MCP endpoint path (resource path). Keep this consistent with your http.Handle route.
	mcpPath := "/mcp"

	// Resource ID (the identifier of the protected resource) is typically the
	// absolute URL to your MCP endpoint.
	resourceID := baseURL + mcpPath

	// Per RFC 9728, the protected resource metadata is served by the resource
	// server at: /.well-known/oauth-protected-resource{resource path}
	// The WWW-Authenticate header should point to this metadata URL, not to the
	// authorization server metadata.
	resourceMetadataURL := baseURL + "/.well-known/oauth-protected-resource" + mcpPath

	authn := auth.RequireBearerToken(verifier, &auth.RequireBearerTokenOptions{
		// Optionally enforce scopes centrally, e.g.:
		// Scopes: []string{"openid"},
		ResourceMetadataURL: resourceMetadataURL,
	})

	// Serve the protected resource metadata so compliant clients can discover
	// how to authorize for this resource.
	metaPath := "/.well-known/oauth-protected-resource" + mcpPath
	http.HandleFunc(metaPath, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"resource":                 resourceID,
			"authorization_servers":    parseAuthServers(),
			"scopes_supported":         []string{"openid", "profile", "email", "offline_access"},
			"bearer_methods_supported": []string{"header"},
		})
	})

	// Register the MCP endpoint.
	http.Handle(mcpPath, authn(handler))

	// Register management endpoints (protected by the same auth middleware):
	// - POST /add-server: connect to a remote MCP server (stdio) and add its tools
	// - POST /remove-server: disconnect and remove proxied tools
	// - POST /update-server: update config (filters/prefix/command/env/args) and resync
	// - POST /set-enabled-tools: set enabled remote tools for a server
	// - GET  /servers: list connected proxy servers and tools (with enabled states)
	http.Handle("/add-server", authn(http.HandlerFunc(proxy.HandleAddServer)))
	http.Handle("/remove-server", authn(http.HandlerFunc(proxy.HandleRemoveServer)))
	http.Handle("/update-server", authn(http.HandlerFunc(proxy.HandleUpdateServer)))
	http.Handle("/set-enabled-tools", authn(http.HandlerFunc(proxy.HandleSetEnabledTools)))
	http.Handle("/servers", authn(http.HandlerFunc(proxy.HandleListServers)))

	log.Printf("CloudMCP session-auth MCP server listening on %s", addr)
	log.Printf("Use Authorization: Bearer <token> and Accept: application/json, text/event-stream")
	if resourceMetadataURL != "" {
		log.Printf("Protected Resource Metadata: %s", resourceMetadataURL)
	}
	log.Fatal(http.ListenAndServe(addr, nil))
}
