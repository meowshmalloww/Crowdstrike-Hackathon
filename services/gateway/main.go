package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/corazawaf/coraza/v3"
)

const (
	maxRequestBody    = 1 << 20
	maxResponseSample = 1 << 19
	maxEventQueue     = 4096
)

type config struct {
	listenAddr    string
	originURL     *url.URL
	honeypotURL   *url.URL
	controlAPIURL *url.URL
	gatewayToken  string
	policyKey     string
	sourceSalt    string
	siteID        string
	labMode       string
}

type eventPayload struct {
	EventID         string          `json:"event_id"`
	OccurredAt      string          `json:"occurred_at"`
	SiteID          string          `json:"site_id"`
	RequestID       string          `json:"request_id"`
	SourceHash      string          `json:"source_ip_pseudonym"`
	SessionHash     string          `json:"session_key_hash,omitempty"`
	Route           string          `json:"route"`
	Method          string          `json:"method"`
	Status          int             `json:"status"`
	DurationMS      float64         `json:"duration_ms"`
	Destination     string          `json:"route_destination"`
	Action          string          `json:"action"`
	WAFRuleIDs      []int           `json:"waf_rule_ids"`
	WAFAnomalyScore *int            `json:"waf_anomaly_score"`
	Signals         map[string]bool `json:"signals"`
	PayloadHash     string          `json:"payload_hash,omitempty"`
}

type requestState struct {
	mu          sync.Mutex
	requestID   string
	sourceHash  string
	sessionHash string
	route       string
	destination string
	action      string
	ruleIDs     map[int]struct{}
	interrupted bool
	started     time.Time
}

func newID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 36)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func env(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func loadConfig() (config, error) {
	origin, err := url.Parse(env("ORIGIN_URL", "http://127.0.0.1:8000"))
	if err != nil || origin.Scheme == "" || origin.Host == "" || origin.User != nil || (origin.Scheme != "http" && origin.Scheme != "https") {
		return config{}, errors.New("ORIGIN_URL must be an absolute HTTP(S) URL without embedded credentials")
	}
	honeypot, err := url.Parse(env("HONEYPOT_URL", "http://127.0.0.1:8001"))
	if err != nil || honeypot.Scheme == "" || honeypot.Host == "" {
		return config{}, errors.New("HONEYPOT_URL must be an absolute URL")
	}
	controlAPI, err := url.Parse(env("CONTROL_API_URL", "http://127.0.0.1:8002"))
	if err != nil || controlAPI.Scheme == "" || controlAPI.Host == "" {
		return config{}, errors.New("CONTROL_API_URL must be an absolute URL")
	}
	if os.Getenv("POLICY_SIGNING_KEY") == "" || os.Getenv("SOURCE_HASH_SALT") == "" {
		return config{}, errors.New("POLICY_SIGNING_KEY and SOURCE_HASH_SALT are required")
	}
	if os.Getenv("GATEWAY_API_TOKEN") == "" {
		return config{}, errors.New("GATEWAY_API_TOKEN is required")
	}
	mode := env("LAB_MODE", "observe-only")
	if mode != "observe-only" && mode != "lab-auto" && mode != "production-review" {
		return config{}, fmt.Errorf("unsupported LAB_MODE %q", mode)
	}
	return config{
		listenAddr: env("LISTEN_ADDR", ":8080"), originURL: origin, honeypotURL: honeypot,
		controlAPIURL: controlAPI, gatewayToken: os.Getenv("GATEWAY_API_TOKEN"),
		policyKey: os.Getenv("POLICY_SIGNING_KEY"), sourceSalt: os.Getenv("SOURCE_HASH_SALT"),
		siteID: env("COUNTERFLOW_SITE_ID", "lab-site"), labMode: mode,
	}, nil
}

func main() {
	cfg, err := loadConfig()
	if err != nil {
		log.Fatal(err)
	}
	waf, err := buildWAF(cfg.labMode)
	if err != nil {
		log.Fatalf("initialize Coraza/CRS: %v", err)
	}
	originProxy := newProxy(cfg.originURL)
	honeypotProxy := newProxy(cfg.honeypotURL)
	policies := newPolicyCache(cfg)
	go policies.run()
	telemetry := make(chan []byte, maxEventQueue)
	var dropped atomic.Uint64
	go publishEvents(cfg, telemetry, &dropped)

	root := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health/live" {
			writeJSON(w, http.StatusOK, map[string]any{"status": "live"})
			return
		}
		if r.URL.Path == "/health/ready" {
			ctx, cancel := context.WithTimeout(r.Context(), 1500*time.Millisecond)
			defer cancel()
			apiErr := checkURL(ctx, cfg.controlAPIURL, "/health/ready")
			originErr := checkUpstream(ctx, cfg.originURL)
			honeypotErr := checkUpstream(ctx, cfg.honeypotURL)
			ready := apiErr == nil && originErr == nil && honeypotErr == nil
			code := http.StatusOK
			if !ready {
				code = http.StatusServiceUnavailable
			}
			writeJSON(w, code, map[string]any{
				"status": map[bool]string{true: "ready", false: "degraded"}[ready],
				"waf":    "coraza-crs", "lab_mode": cfg.labMode,
				"control_api_ready": apiErr == nil, "origin_ready": originErr == nil,
				"honeypot_ready": honeypotErr == nil, "telemetry_dropped": dropped.Load(),
			})
			return
		}
		serveRequest(w, r, cfg, waf, originProxy, honeypotProxy, policies, telemetry, &dropped)
	})

	server := &http.Server{
		Addr: cfg.listenAddr, Handler: root,
		ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 60 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}
	log.Printf("gateway_start listen=%s mode=%s site=%s", cfg.listenAddr, cfg.labMode, cfg.siteID)
	log.Fatal(server.ListenAndServe())
}

func newRequestState(r *http.Request, cfg config, route string) *requestState {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		ip = strings.TrimSpace(r.RemoteAddr)
	}
	return &requestState{
		requestID: newID(), sourceHash: keyedHash(cfg.sourceSalt, ip),
		sessionHash: sessionHash(cfg.sourceSalt, r.Header.Get("X-CounterFlow-Session")),
		route:       route, destination: "origin", action: "allow", started: time.Now(),
		ruleIDs: make(map[int]struct{}),
	}
}

func keyedHash(key, value string) string {
	mac := hmac.New(sha256.New, []byte(key))
	_, _ = mac.Write([]byte(value))
	return hex.EncodeToString(mac.Sum(nil))
}

func sessionHash(salt, token string) string {
	if token == "" {
		return ""
	}
	// Keep the same SHA-256 convention used by the authenticated policy API.
	sum := sha256.Sum256([]byte(salt + ":" + token))
	return hex.EncodeToString(sum[:])
}

func routeTemplate(path string) string {
	if path == "" {
		return "/"
	}
	parts := strings.Split(strings.Trim(path, "/"), "/")
	for i, part := range parts {
		lower := strings.ToLower(part)
		if len(part) >= 16 || isNumericSegment(part) || strings.Contains(part, "-") && len(part) >= 32 {
			parts[i] = ":id"
		} else if strings.Contains(lower, "@") {
			parts[i] = ":value"
		}
	}
	result := "/" + strings.Join(parts, "/")
	if result == "//" {
		return "/"
	}
	if len(result) > 255 {
		return result[:255]
	}
	return result
}

func isNumericSegment(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func sqliPattern(query string) bool {
	lower := strings.ToLower(query)
	patterns := []string{"union select", "union all select", " or 1=1", " or 2=2", " and 1=1", "select ", "sleep(", "benchmark(", "-- "}
	for _, pattern := range patterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}
	return false
}

func scannerPattern(value string) bool {
	lower := strings.ToLower(value)
	for _, part := range []string{"../", "/.env", "/wp-admin", "/phpmyadmin", "/cgi-bin"} {
		if strings.Contains(lower, part) {
			return true
		}
	}
	return false
}

func queryHash(r *http.Request) string {
	query := r.URL.Query().Get("q")
	if query == "" {
		return ""
	}
	return keyedHash(env("SOURCE_HASH_SALT", ""), query)
}

type captureWriter struct {
	http.ResponseWriter
	status int
	bytes  int64
	sample []byte
}

func (w *captureWriter) WriteHeader(status int) {
	if w.status != 0 {
		return
	}
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *captureWriter) Write(body []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	w.bytes += int64(len(body))
	remaining := maxResponseSample - len(w.sample)
	if remaining > 0 {
		if len(body) > remaining {
			w.sample = append(w.sample, body[:remaining]...)
		} else {
			w.sample = append(w.sample, body...)
		}
	}
	return w.ResponseWriter.Write(body)
}

func (w *captureWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func serveRequest(w http.ResponseWriter, r *http.Request, cfg config, waf coraza.WAF, originProxy, honeypotProxy *httputil.ReverseProxy, policies *policyCache, telemetry chan<- []byte, dropped *atomic.Uint64) {
	started := time.Now()
	state := newRequestState(r, cfg, routeTemplate(r.URL.Path))
	w.Header().Set("X-Request-ID", state.requestID)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Cache-Control", "no-store")
	r = sanitizeRequest(r, state.requestID)
	if r.ContentLength > maxRequestBody {
		state.action = "rejected_size"
		recordResponse(w, r, cfg, state, started, http.StatusRequestEntityTooLarge, nil, telemetry, dropped)
		return
	}
	if r.Body != nil {
		r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	}
	query := r.URL.Query().Get("q")
	features := map[string]bool{"sqli_pattern": sqliPattern(query), "scanner_probe": scannerPattern(r.URL.Path + "?" + r.URL.RawQuery)}

	if policy := policies.match(cfg.siteID, state.sessionHash, state.route); policy != nil {
		switch policy.Action {
		case "deceive":
			state.action = "deceived"
			state.destination = "honeypot"
			r.Header.Set("X-Request-ID", state.requestID)
			rec := &captureWriter{ResponseWriter: w}
			honeypotProxy.ServeHTTP(rec, r)
			status := rec.status
			if status == 0 {
				status = http.StatusOK
			}
			features["canary_exposed"] = false
			recordResponse(w, r, cfg, state, started, status, features, telemetry, dropped)
			return
		case "block":
			state.action = "policy_blocked"
			writeJSON(w, http.StatusForbidden, map[string]any{"error": "request denied by a scoped, expiring lab policy", "request_id": state.requestID})
			recordResponse(w, r, cfg, state, started, http.StatusForbidden, features, telemetry, dropped)
			return
		case "rate_limit":
			if policies.rateLimited(policy.ID, state.sessionHash) {
				state.action = "rate_limited"
				writeJSON(w, http.StatusTooManyRequests, map[string]any{"error": "request rate limited by a scoped lab policy", "request_id": state.requestID})
				recordResponse(w, r, cfg, state, started, http.StatusTooManyRequests, features, telemetry, dropped)
				return
			}
		}
	}

	response := &captureWriter{ResponseWriter: w}
	upstreamCalled := false
	protectedOrigin := http.HandlerFunc(func(inner http.ResponseWriter, req *http.Request) {
		upstreamCalled = true
		originProxy.ServeHTTP(inner, req)
	})
	serveWithWAF(response, r, waf, state, protectedOrigin)
	status := response.status
	if status == 0 {
		status = http.StatusOK
	}
	if !upstreamCalled && status >= 400 {
		state.interrupted = true
		state.action = "waf_blocked"
	}
	features["waf_interrupted"] = state.interrupted
	features["canary_exposed"] = strings.Contains(string(response.sample), "synthetic-canary-2026")
	recordResponse(w, r, cfg, state, started, status, features, telemetry, dropped)
}

func sanitizeRequest(r *http.Request, requestID string) *http.Request {
	copy := r.Clone(r.Context())
	copy.Header = r.Header.Clone()
	for _, h := range []string{"Forwarded", "X-Forwarded-For", "X-Real-IP", "X-Forwarded-Host", "X-Forwarded-Proto", "X-Request-ID"} {
		copy.Header.Del(h)
	}
	copy.Header.Set("X-Request-ID", requestID)
	return copy
}

func recordResponse(w http.ResponseWriter, r *http.Request, cfg config, state *requestState, started time.Time, status int, features map[string]bool, telemetry chan<- []byte, dropped *atomic.Uint64) {
	if features == nil {
		features = map[string]bool{"sqli_pattern": sqliPattern(r.URL.Query().Get("q")), "scanner_probe": scannerPattern(r.URL.Path + "?" + r.URL.RawQuery)}
	}
	features["waf_interrupted"] = state.interrupted
	ids := make([]int, 0, len(state.ruleIDs))
	for id := range state.ruleIDs {
		ids = append(ids, id)
	}
	// Rule IDs are sorted for stable event serialization and explainability.
	for i := 0; i < len(ids); i++ {
		for j := i + 1; j < len(ids); j++ {
			if ids[j] < ids[i] {
				ids[i], ids[j] = ids[j], ids[i]
			}
		}
	}
	event := eventPayload{
		EventID: newID(), OccurredAt: time.Now().UTC().Format(time.RFC3339Nano), SiteID: cfg.siteID,
		RequestID: state.requestID, SourceHash: state.sourceHash, SessionHash: state.sessionHash,
		Route: state.route, Method: r.Method, Status: status,
		DurationMS:  float64(time.Since(started).Microseconds()) / 1000,
		Destination: state.destination, Action: state.action,
		WAFRuleIDs: ids, WAFAnomalyScore: nil, Signals: features, PayloadHash: queryHash(r),
	}
	encoded, err := json.Marshal(event)
	if err != nil {
		log.Printf("telemetry_encode_failed request_id=%s error_type=%T", state.requestID, err)
		return
	}
	select {
	case telemetry <- encoded:
	default:
		count := dropped.Add(1)
		if count == 1 || count%100 == 0 {
			log.Printf("telemetry_queue_overflow dropped=%d", count)
		}
	}
	log.Printf("request_complete request_id=%s route=%s status=%d action=%s rules=%v", state.requestID, state.route, status, state.action, ids)
}

func publishEvents(cfg config, queue <-chan []byte, dropped *atomic.Uint64) {
	client := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{Proxy: nil}}
	endpoint := strings.TrimRight(cfg.controlAPIURL.String(), "/") + "/api/v1/internal/events"
	for payload := range queue {
		accepted := false
		for attempt := 0; attempt < 3 && !accepted; attempt++ {
			ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(string(payload)))
			if err == nil {
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("Authorization", "Bearer "+cfg.gatewayToken)
				resp, requestErr := client.Do(req)
				if requestErr == nil {
					_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
					_ = resp.Body.Close()
					accepted = resp.StatusCode >= 200 && resp.StatusCode < 300
				}
			}
			cancel()
			if !accepted && attempt < 2 {
				time.Sleep(time.Duration(attempt+1) * 100 * time.Millisecond)
			}
		}
		if !accepted {
			count := dropped.Add(1)
			if count == 1 || count%100 == 0 {
				log.Printf("telemetry_publish_failed dropped=%d", count)
			}
		}
	}
}

func newProxy(target *url.URL) *httputil.ReverseProxy {
	proxy := httputilNewSingleHostReverseProxy(target)
	proxy.Transport = &http.Transport{
		Proxy:             nil,
		DialContext:       (&net.Dialer{Timeout: 3 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2: false,
		MaxIdleConns:      100, IdleConnTimeout: 30 * time.Second,
		TLSHandshakeTimeout: 3 * time.Second, ResponseHeaderTimeout: 8 * time.Second,
		ExpectContinueTimeout: 1 * time.Second, MaxResponseHeaderBytes: 1 << 20,
	}
	proxy.FlushInterval = -1
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		log.Printf("upstream_error request_id=%s error_type=%T", r.Header.Get("X-Request-ID"), err)
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": "upstream unavailable", "request_id": r.Header.Get("X-Request-ID")})
	}
	return proxy
}

func httputilNewSingleHostReverseProxy(target *url.URL) *httputil.ReverseProxy {
	return &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			pr.Out.Host = target.Host
			for _, header := range []string{
				"Forwarded", "X-Forwarded-For", "X-Real-IP", "X-Forwarded-Host", "X-Forwarded-Proto",
				"X-CounterFlow-Session", "Authorization", "Proxy-Authorization", "Cookie",
			} {
				pr.Out.Header.Del(header)
			}
			pr.Out.Header.Set("X-Request-ID", pr.In.Header.Get("X-Request-ID"))
		},
	}
}

func checkUpstream(ctx context.Context, target *url.URL) error {
	return checkURL(ctx, target, "/health/live")
}

func checkURL(ctx context.Context, target *url.URL, path string) error {
	client := &http.Client{Timeout: 1 * time.Second, Transport: &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 500 * time.Millisecond}).DialContext}}
	probe, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(probe, http.MethodGet, strings.TrimRight(target.String(), "/")+path, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
	if resp.StatusCode >= 500 {
		return fmt.Errorf("upstream status %d", resp.StatusCode)
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
