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
	"github.com/rs/cors"
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

// Minimal session shape returned by Better Auth cookie session endpoint.
// We only need the userId to authorize the request.
type betterAuthSession struct {
	Session struct {
		ID             string `json:"id"`
		ExpiresAt      string `json:"expiresAt"`
		Token          string `json:"token"`
		CreatedAt      string `json:"createdAt"`
		UpdatedAt      string `json:"updatedAt"`
		IPAddress      string `json:"ipAddress"`
		UserAgent      string `json:"userAgent"`
		UserID         string `json:"userId"`
		ImpersonatedBy string `json:"impersonatedBy"`
	} `json:"session"`
	User struct {
		ID            string `json:"id"`
		Name          string `json:"name"`
		Email         string `json:"email"`
		EmailVerified bool   `json:"emailVerified"`
		Image         string `json:"image"`
		CreatedAt     string `json:"createdAt"`
		UpdatedAt     string `json:"updatedAt"`
		Role          string `json:"role"`
		Banned        bool   `json:"banned"`
		BanReason     string `json:"banReason"`
		BanExpires    string `json:"banExpires"`
		HasUsedTrial  bool   `json:"hasUsedTrial"`
	} `json:"user"`
}

var (
	httpAddr = flag.String("http", ":8080", "HTTP address to listen on (overrides ADDR; PORT takes precedence if set)")
)

// Middleware is the standard Go HTTP middleware shape.
type Middleware func(http.Handler) http.Handler

// debugAuthEnabled returns true by default. Set DEBUG_AUTH to 0/false/off to disable.
func debugAuthEnabled() bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("DEBUG_AUTH")))
	if v == "0" || v == "false" || v == "off" {
		return false
	}
	return true
}

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

func main() {
	flag.Parse()

	// Determine listen address. Prefer PORT if set (Fly/Heroku convention),
	// otherwise fall back to ADDR flag/env (":8080").
	addr := ""
	if p := strings.TrimSpace(os.Getenv("PORT")); p != "" {
		if strings.HasPrefix(p, ":") {
			addr = p
		} else {
			addr = ":" + p
		}
	} else {
		addr = envOrDefault("ADDR", *httpAddr)
	}
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
				// Default to configured USER_ID to support cookie-auth paths
				// where TokenInfo may be absent.
				userID := expectedUserID
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
					// Default to configured USER_ID, override with TokenInfo if present
					userID := expectedUserID
					if extra := req.GetExtra(); extra != nil && extra.TokenInfo != nil {
						if uid, _ := extra.TokenInfo.Extra["userId"].(string); uid != "" {
							userID = uid
						}
					}
					if userID != "" {
						// Track asynchronously to avoid adding latency to tool calls
						go polarClient.TrackUsage(context.Background(), userID)
					}
				}
			}

			return res, err
		}
	})
	// mcp.AddTool(server, &mcp.Tool{Name: "whoami", Description: "Return info from verified token/session"}, whoAmI)

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

	if debugAuthEnabled() {
		log.Println("DEBUG_AUTH: enabled (set DEBUG_AUTH=0 to disable)")
	}

	// Conditionally wrap auth: allow skipping on localhost when SKIP_AUTH_LAYER is set
	skipAuth := baseURL == "http://localhost:8080" && strings.TrimSpace(os.Getenv("SKIP_AUTH_LAYER")) != ""

	// Build the two auth middlewares we may choose between.
	bearerMW := auth.RequireBearerToken(verifier, &auth.RequireBearerTokenOptions{
		// Optionally enforce scopes centrally, e.g.:
		// Scopes: []string{"openid"},
		ResourceMetadataURL: resourceMetadataURL,
	})

	// Cookie middleware: if Better Auth cookies verify, pass through; otherwise fall back to bearer
	cookieMW := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if betterAuthCookieOK(r, baseURL, expectedUserID) {
				next.ServeHTTP(w, r)
				return
			}
			// Fallback to bearer for proper 401 challenge when cookie is absent/invalid
			bearerMW(next).ServeHTTP(w, r)
		})
	}

	// Decide per-request based on presented credentials.
	chooseAuth := func(r *http.Request) string {
		if hasBetterAuthCookie(r) {
			return "cookie"
		}
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(r.Header.Get("Authorization"))), "bearer ") {
			return "bearer"
		}
		// Default to bearer so clients receive a WWW-Authenticate challenge
		return "bearer"
	}

	// Switcher that applies exactly one branch per request.
	authSwitcher := EitherAuth(bearerMW, cookieMW, chooseAuth)

	// Compose the final auth wrapper respecting SKIP_AUTH_LAYER.
	authn := func(h http.Handler) http.Handler {
		if skipAuth {
			log.Println("SKIP_AUTH_LAYER set with localhost base URL; skipping auth middleware")
			return h
		}
		return authSwitcher(h)
	}

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
	http.Handle("/add-server", cookieMW(http.HandlerFunc(proxy.HandleAddServer)))
	http.Handle("/remove-server", cookieMW(http.HandlerFunc(proxy.HandleRemoveServer)))
	http.Handle("/update-server", cookieMW(http.HandlerFunc(proxy.HandleUpdateServer)))
	http.Handle("/set-enabled-tools", cookieMW(http.HandlerFunc(proxy.HandleSetEnabledTools)))
	http.Handle("/servers", cookieMW(http.HandlerFunc(proxy.HandleListServers)))
	// Health check: pings each connected remote server and reports status
	http.Handle("/health", cookieMW(http.HandlerFunc(proxy.HandleHealth)))

	// Unprotected healthcheck endpoint for container platform probes
	http.HandleFunc("/healthcheck", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ok":true}`))
	})

	log.Printf("CloudMCP session-auth MCP server listening on %s", addr)
	log.Printf("Use Authorization: Bearer <token> and Accept: application/json, text/event-stream")
	if resourceMetadataURL != "" {
		log.Printf("Protected Resource Metadata: %s", resourceMetadataURL)
	}
	// Wrap DefaultServeMux so preflight is handled before auth middleware.
	log.Fatal(http.ListenAndServe(addr, cors.Default().Handler(http.DefaultServeMux)))
}

// betterAuthCookieOK checks incoming request cookies for any name containing
// "better-auth". If present, it forwards those cookies to baseURL+"/api/auth/get-session".
// If the response is 2xx and contains a userId that matches expectedUserID, it
// returns true to allow the request through.
func betterAuthCookieOK(r *http.Request, baseURL, expectedUserID string) bool {
	// Collect only cookies relevant to Better Auth.
	var betterAuthCookies []*http.Cookie
	for _, c := range r.Cookies() {
		if strings.Contains(strings.ToLower(c.Name), "better-auth") {
			betterAuthCookies = append(betterAuthCookies, c)
		}
	}
	if len(betterAuthCookies) == 0 {
		if debugAuthEnabled() {
			log.Println("betterAuthCookieOK: no better-auth cookies on request")
		}
		return false
	}

	if strings.TrimSpace(expectedUserID) == "" {
		if debugAuthEnabled() {
			log.Println("betterAuthCookieOK: USER_ID not set; strict mode requires it")
		}
		return false
	}

	// If USER_ID is not configured, we still allow any valid Better Auth user.
	// Resolve Better Auth session endpoint (supports override and fallback paths).
	url := resolveBetterAuthSessionURL()
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, url, nil)
	if err != nil {
		if debugAuthEnabled() {
			log.Printf("betterAuthCookieOK: build request error: %v", err)
		}
		return false
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	// Attach cookies using the helper to ensure proper formatting/quoting.
	for _, c := range betterAuthCookies {
		req.AddCookie(c)
	}
	if debugAuthEnabled() {
		names := make([]string, 0, len(betterAuthCookies))
		for _, c := range betterAuthCookies {
			names = append(names, c.Name)
		}
		log.Printf("betterAuthCookieOK: forwarding cookies to %s: %v", url, names)
	}

	client := &http.Client{Timeout: 5 * time.Second}
	res, err := client.Do(req)
	if err != nil {
		if debugAuthEnabled() {
			log.Printf("betterAuthCookieOK: upstream error: %v", err)
		}
		return false
	}
	defer res.Body.Close()
	if res.StatusCode/100 != 2 {
		if debugAuthEnabled() {
			log.Printf("betterAuthCookieOK: upstream status %s", res.Status)
		}
		return false
	}

	var sess betterAuthSession
	if err := json.NewDecoder(res.Body).Decode(&sess); err != nil {
		if debugAuthEnabled() {
			log.Printf("betterAuthCookieOK: decode error: %v", err)
		}
		return false
	}
	if sess.User.ID == "" {
		if debugAuthEnabled() {
			log.Printf("betterAuthCookieOK: empty userId in session")
		}
		return false
	}
	if sess.User.ID != expectedUserID {
		if debugAuthEnabled() {
			log.Printf("betterAuthCookieOK: userId mismatch: got %q want %q", sess.User.ID, expectedUserID)
		}
		return false
	}
	return true
}

// resolveBetterAuthSessionURL chooses the session endpoint.
// Order: BETTER_AUTH_SESSION_URL override > CLOUDMCP_BASE_URL + /api/auth/get-session.
func resolveBetterAuthSessionURL() string {
	if v := strings.TrimSpace(os.Getenv("BETTER_AUTH_SESSION_URL")); v != "" {
		return strings.TrimRight(v, "/")
	}
	cloudMcpBaseURL := envOrDefault("CLOUDMCP_BASE_URL", "https://cloudmcp.run")
	return strings.TrimRight(cloudMcpBaseURL, "/") + "/api/auth/get-session"
}

// hasBetterAuthCookie is a cheap predicate to detect Better Auth cookies on the request.
func hasBetterAuthCookie(r *http.Request) bool {
	for _, c := range r.Cookies() {
		if strings.Contains(strings.ToLower(c.Name), "better-auth") {
			return true
		}
	}
	return false
}

// EitherAuth chooses between two middlewares per request using a predicate.
// pred should return "bearer" or "cookie" (any other value defaults to bearer).
func EitherAuth(bearer, cookie Middleware, pred func(*http.Request) string) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch pred(r) {
			case "cookie":
				cookie(next).ServeHTTP(w, r)
			case "bearer":
				fallthrough
			default:
				bearer(next).ServeHTTP(w, r)
			}
		})
	}
}
