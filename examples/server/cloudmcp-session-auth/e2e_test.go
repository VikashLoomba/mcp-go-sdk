package main

import (
    "bytes"
    "context"
    "encoding/json"
    "io"
    "net"
    "net/http"
    "os"
    "os/exec"
    "strconv"
    "testing"
    "time"
)

type listServersResponse struct {
    Servers []struct {
        Name string `json:"name"`
    } `json:"servers"`
}

type testLogWriter struct{ t *testing.T; prefix string }

func (w testLogWriter) Write(p []byte) (int, error) {
    // Trim trailing newline for nicer t.Log output
    if len(p) > 0 && p[len(p)-1] == '\n' {
        w.t.Logf("%s%s", w.prefix, string(p[:len(p)-1]))
    } else {
        w.t.Logf("%s%s", w.prefix, string(p))
    }
    return len(p), nil
}

func waitForServer(t *testing.T, base string, timeout time.Duration) {
    t.Helper()
    deadline := time.Now().Add(timeout)
    client := &http.Client{Timeout: 2 * time.Second}
    url := base + "/servers"
    attempt := 0
    for time.Now().Before(deadline) {
        attempt++
        t.Logf("waiting for server readiness (attempt %d): GET %s", attempt, url)
        resp, err := client.Get(url)
        if err == nil && resp.StatusCode == http.StatusOK {
            _ = resp.Body.Close()
            t.Log("server is ready")
            return
        }
        if resp != nil {
            _ = resp.Body.Close()
        }
        time.Sleep(200 * time.Millisecond)
    }
    t.Fatalf("server did not become ready: GET %s timed out", url)
}

func postJSON(t *testing.T, client *http.Client, url string, payload any) *http.Response {
    t.Helper()
    b, err := json.Marshal(payload)
    if err != nil {
        t.Fatalf("marshal payload: %v", err)
    }
    t.Logf("POST %s payload=%s", url, string(b))
    req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(b))
    if err != nil {
        t.Fatalf("new request: %v", err)
    }
    req.Header.Set("Content-Type", "application/json")
    start := time.Now()
    resp, err := client.Do(req)
    if err != nil {
        t.Fatalf("POST %s failed: %v", url, err)
    }
    t.Logf("POST %s -> %s in %s", url, resp.Status, time.Since(start))
    return resp
}

func decodeJSON(t *testing.T, r io.ReadCloser, v any) {
    t.Helper()
    defer r.Close()
    dec := json.NewDecoder(r)
    if err := dec.Decode(v); err != nil {
        t.Fatalf("decode json: %v", err)
    }
}

func TestAddListRemoveServers(t *testing.T) {
    // Choose an available port dynamically to avoid conflicts
    ln, err := net.Listen("tcp", "127.0.0.1:0")
    if err != nil {
        t.Fatalf("reserve port: %v", err)
    }
    port := ln.Addr().(*net.TCPAddr).Port
    _ = ln.Close()
    addr := ":" + strconv.Itoa(port)
    base := "http://127.0.0.1:" + strconv.Itoa(port)

    // Start the example server as a subprocess
    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()

    cmd := exec.CommandContext(ctx, "go", "run", ".")
    cmd.Env = append(os.Environ(),
        "ADDR="+addr,
        "SKIP_AUTH_LAYER=1",
    )

    // Pipe server logs to test output in real time
    stdoutPipe, err := cmd.StdoutPipe()
    if err != nil { t.Fatalf("stdout pipe: %v", err) }
    stderrPipe, err := cmd.StderrPipe()
    if err != nil { t.Fatalf("stderr pipe: %v", err) }

    if err := cmd.Start(); err != nil {
        t.Fatalf("failed to start server: %v", err)
    }
    go func() { _, _ = io.Copy(testLogWriter{t, "[srv stdout] "}, stdoutPipe) }()
    go func() { _, _ = io.Copy(testLogWriter{t, "[srv stderr] "}, stderrPipe) }()

    t.Logf("started server on %s (base %s)", addr, base)
    defer func() {
        _ = cmd.Process.Kill()
        _ = cmd.Wait()
    }()

    // Wait for the server to become ready
    waitForServer(t, base, 30*time.Second)

    // Allow generous timeout to accommodate first-time npx installs
    client := &http.Client{Timeout: 5 * time.Minute}

    // 1) Add context7 server
    addURL := base + "/add-server"
    resp := postJSON(t, client, addURL, map[string]any{
        "name":    "context7",
        "command": "npx",
        "args":    []string{"@upstash/context7-mcp"},
        "env":     map[string]string{},
    })
    if resp.StatusCode != http.StatusOK {
        b, _ := io.ReadAll(resp.Body)
        _ = resp.Body.Close()
        t.Fatalf("add context7 failed: %s: %s", resp.Status, string(b))
    }
    _ = resp.Body.Close()

    // 2) Add playwright server
    resp = postJSON(t, client, addURL, map[string]any{
        "name":    "playwright",
        "command": "npx",
        "args":    []string{"@playwright/mcp"},
    })
    if resp.StatusCode != http.StatusOK {
        b, _ := io.ReadAll(resp.Body)
        _ = resp.Body.Close()
        t.Fatalf("add playwright failed: %s: %s", resp.Status, string(b))
    }
    _ = resp.Body.Close()

    // 3) GET /servers and verify both present
    t.Log("fetching server list after adds")
    resp, err = client.Get(base + "/servers")
    if err != nil {
        t.Fatalf("GET /servers: %v", err)
    }
    if resp.StatusCode != http.StatusOK {
        b, _ := io.ReadAll(resp.Body)
        _ = resp.Body.Close()
        t.Fatalf("GET /servers failed: %s: %s", resp.Status, string(b))
    }
    var list listServersResponse
    decodeJSON(t, resp.Body, &list)
    if len(list.Servers) < 2 {
        t.Fatalf("expected at least 2 servers, got %d", len(list.Servers))
    }
    found := map[string]bool{}
    for _, s := range list.Servers {
        found[s.Name] = true
    }
    if !found["context7"] || !found["playwright"] {
        t.Fatalf("expected servers 'context7' and 'playwright' present; got %+v", list)
    }

    // 4) Remove the playwright server
    t.Log("removing 'playwright' server")
    resp = postJSON(t, client, base+"/remove-server", map[string]any{
        "name": "playwright",
    })
    if resp.StatusCode != http.StatusOK {
        b, _ := io.ReadAll(resp.Body)
        _ = resp.Body.Close()
        t.Fatalf("remove playwright failed: %s: %s", resp.Status, string(b))
    }
    _ = resp.Body.Close()

    // 5) GET /servers again and verify only context7 remains
    t.Log("fetching server list after remove")
    resp, err = client.Get(base + "/servers")
    if err != nil {
        t.Fatalf("GET /servers (after remove): %v", err)
    }
    if resp.StatusCode != http.StatusOK {
        b, _ := io.ReadAll(resp.Body)
        _ = resp.Body.Close()
        t.Fatalf("GET /servers (after remove) failed: %s: %s", resp.Status, string(b))
    }
    list = listServersResponse{}
    decodeJSON(t, resp.Body, &list)
    // Only check for presence/absence; server count might include others if running locally
    found = map[string]bool{}
    for _, s := range list.Servers {
        found[s.Name] = true
    }
    if found["playwright"] {
        t.Fatalf("expected 'playwright' to be removed; still present")
    }
    if !found["context7"] {
        t.Fatalf("expected 'context7' to remain; not found")
    }
}
