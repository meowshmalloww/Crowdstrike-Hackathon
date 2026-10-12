package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"
)

func newTestRequest(target string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, target, nil)
	r.RemoteAddr = "192.0.2.20:50123"
	r.Header.Set("User-Agent", "CounterFlow authorized lab test")
	return r
}

func TestActiveWAFBlocksControlledSQLInjectionAndReturnsActualRuleIDs(t *testing.T) {
	waf, err := buildWAF("lab-auto")
	if err != nil {
		t.Fatal(err)
	}
	r := newTestRequest("/api/search?q=%25%27+OR+1%3D1+--")
	state := &requestState{requestID: "test-request", ruleIDs: map[int]struct{}{}, started: time.Now()}
	forwarded := int32(0)
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&forwarded, 1)
		w.WriteHeader(http.StatusOK)
	})
	response := httptest.NewRecorder()
	serveWithWAF(response, r, waf, state, inner)
	if response.Code < 400 || atomic.LoadInt32(&forwarded) != 0 {
		t.Fatalf("expected WAF denial before origin, status=%d forwarded=%d body=%s", response.Code, forwarded, response.Body.String())
	}
	if !state.interrupted {
		t.Fatal("expected transaction to be marked as interrupted")
	}
	if len(state.ruleIDs) == 0 {
		t.Fatal("expected rule IDs captured from Coraza's matched rule metadata")
	}
}

func TestObserveOnlyWAFRecordsMatchAndLetsOriginRespond(t *testing.T) {
	waf, err := buildWAF("observe-only")
	if err != nil {
		t.Fatal(err)
	}
	r := newTestRequest("/api/search?q=%25%27+OR+1%3D1+--")
	state := &requestState{requestID: "test-request", ruleIDs: map[int]struct{}{}, started: time.Now()}
	response := httptest.NewRecorder()
	serveWithWAF(response, r, waf, state, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	if response.Code != http.StatusOK {
		t.Fatalf("observe-only should pass to the origin, got status=%d body=%s", response.Code, response.Body.String())
	}
	if len(state.ruleIDs) == 0 {
		t.Fatal("observe-only event should include matched Coraza rule IDs")
	}
	if state.interrupted {
		t.Fatal("observe-only request must not be reported as interrupted")
	}
}

func TestActiveWAFAllowsOrdinaryApostrophe(t *testing.T) {
	waf, err := buildWAF("lab-auto")
	if err != nil {
		t.Fatal(err)
	}
	r := newTestRequest("/api/search?q=O%27Reilly")
	state := &requestState{requestID: "test-request", ruleIDs: map[int]struct{}{}, started: time.Now()}
	response := httptest.NewRecorder()
	serveWithWAF(response, r, waf, state, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	if response.Code != http.StatusOK {
		t.Fatalf("ordinary apostrophe was blocked, status=%d body=%s rules=%v", response.Code, response.Body.String(), sortedIDs(state.ruleIDs))
	}
}

func TestSignedPolicyRequiresExactSessionAndRoute(t *testing.T) {
	key := "policy-signing-test-key"
	cache := newPolicyCache(config{policyKey: key, siteID: "lab-site"})
	policy := scopedPolicy{ID: "p1", SiteID: "lab-site", Action: "deceive", MatchSpec: map[string]string{"route": "/api/search", "session_hash": "session-hash"}, Version: 1, ExpiresAt: time.Now().UTC().Add(time.Minute).Format(time.RFC3339Nano)}
	canonical, err := json.Marshal(map[string]any{"id": policy.ID, "site_id": policy.SiteID, "action": policy.Action, "match_spec": policy.MatchSpec, "version": policy.Version, "expires_at": policy.ExpiresAt})
	if err != nil {
		t.Fatal(err)
	}
	mac := hmac.New(sha256.New, []byte(key))
	_, _ = mac.Write(canonical)
	policy.Signature = hex.EncodeToString(mac.Sum(nil))
	if !cache.valid(policy) {
		t.Fatal("expected valid signed policy")
	}
	cache.items[policy.ID] = policy
	if cache.match("lab-site", "another-session", "/api/search") != nil {
		t.Fatal("policy unexpectedly matched a different session")
	}
	if cache.match("lab-site", "session-hash", "/other") != nil {
		t.Fatal("policy unexpectedly matched a different route")
	}
	if matched := cache.match("lab-site", "session-hash", "/api/search"); matched == nil || matched.Action != "deceive" {
		t.Fatal("expected policy match for exact authorized session and route")
	}
	policy.Action = "block"
	if cache.valid(policy) {
		t.Fatal("modified action must invalidate the policy signature")
	}
}

func TestPolicyCacheLoadsSignedPoliciesFromAuthenticatedControlAPI(t *testing.T) {
	key := "policy-signing-test-key"
	policy := scopedPolicy{ID: "p1", SiteID: "lab-site", Action: "deceive", MatchSpec: map[string]string{"route": "/api/search", "session_hash": "session-hash"}, Version: 1, ExpiresAt: time.Now().UTC().Add(time.Minute).Format(time.RFC3339Nano)}
	canonical, err := json.Marshal(map[string]any{"id": policy.ID, "site_id": policy.SiteID, "action": policy.Action, "match_spec": policy.MatchSpec, "version": policy.Version, "expires_at": policy.ExpiresAt})
	if err != nil {
		t.Fatal(err)
	}
	mac := hmac.New(sha256.New, []byte(key))
	_, _ = mac.Write(canonical)
	policy.Signature = hex.EncodeToString(mac.Sum(nil))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/internal/policies" || r.Header.Get("Authorization") != "Bearer gateway-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode([]scopedPolicy{policy})
	}))
	defer server.Close()
	base, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	cache := newPolicyCache(config{policyKey: key, siteID: "lab-site", controlAPIURL: base, gatewayToken: "gateway-token"})
	cache.refresh()
	if matched := cache.match("lab-site", "session-hash", "/api/search"); matched == nil || matched.Action != "deceive" {
		t.Fatal("expected authenticated control API policy to load into the cache")
	}
}

func TestPublisherPostsTelemetryToAuthenticatedControlAPI(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/internal/events" || r.Header.Get("Authorization") != "Bearer gateway-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		var event map[string]any
		if err := json.NewDecoder(r.Body).Decode(&event); err != nil || event["event_id"] != "event-1" {
			http.Error(w, "invalid event", http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()
	base, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	queue := make(chan []byte, 1)
	queue <- []byte(`{"event_id":"event-1"}`)
	close(queue)
	var dropped atomic.Uint64
	publishEvents(config{controlAPIURL: base, gatewayToken: "gateway-token"}, queue, &dropped)
	if dropped.Load() != 0 {
		t.Fatalf("expected event to be accepted; dropped=%d", dropped.Load())
	}
}

func TestQueryFeatureDetectionDoesNotTreatApostropheAsSQLInjection(t *testing.T) {
	if sqliPattern("O'Reilly's mug") {
		t.Fatal("a quote alone must not match the bounded injection heuristic")
	}
	if !sqliPattern("%' OR 1=1 --") {
		t.Fatal("controlled injection fixture should match")
	}
}

func sortedIDs(values map[int]struct{}) []int {
	ids := make([]int, 0, len(values))
	for id := range values {
		ids = append(ids, id)
	}
	return ids
}
