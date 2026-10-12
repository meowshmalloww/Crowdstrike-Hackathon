package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"sort"
	"sync"
	"time"
)

type scopedPolicy struct {
	ID        string            `json:"id"`
	SiteID    string            `json:"site_id"`
	Action    string            `json:"action"`
	MatchSpec map[string]string `json:"match_spec"`
	Version   int               `json:"version"`
	ExpiresAt string            `json:"expires_at"`
	Signature string            `json:"signature"`
}

type policyCache struct {
	client *http.Client
	cfg    config
	mu     sync.RWMutex
	items  map[string]scopedPolicy
	rate   map[string][]time.Time
}

func newPolicyCache(cfg config) *policyCache {
	return &policyCache{
		client: &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{Proxy: nil}},
		cfg: cfg, items: make(map[string]scopedPolicy), rate: make(map[string][]time.Time),
	}
}

func (p *policyCache) run() {
	p.refresh()
	ticker := time.NewTicker(750 * time.Millisecond)
	defer ticker.Stop()
	for {
		<-ticker.C
		p.refresh()
	}
}

func (p *policyCache) refresh() {
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	endpoint := p.cfg.controlAPIURL.String() + "/api/v1/internal/policies"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		log.Printf("policy_refresh_failed error_type=%T; retaining cached unexpired policies", err)
		p.prune()
		return
	}
	req.Header.Set("Authorization", "Bearer "+p.cfg.gatewayToken)
	response, err := p.client.Do(req)
	if err != nil {
		log.Printf("policy_refresh_failed error_type=%T; retaining cached unexpired policies", err)
		p.prune()
		return
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		log.Printf("policy_refresh_failed status=%d; retaining cached unexpired policies", response.StatusCode)
		p.prune()
		return
	}
	var policies []scopedPolicy
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&policies); err != nil {
		log.Printf("policy_refresh_failed error_type=%T; retaining cached unexpired policies", err)
		p.prune()
		return
	}
	updated := make(map[string]scopedPolicy, len(policies))
	for _, policy := range policies {
		if !p.valid(policy) {
			log.Printf("policy_rejected policy_id=%s reason=invalid_signature_or_fields", policy.ID)
			continue
		}
		updated[policy.ID] = policy
	}
	p.mu.Lock()
	p.items = updated
	p.mu.Unlock()
}

func (p *policyCache) valid(policy scopedPolicy) bool {
	if policy.SiteID != p.cfg.siteID || policy.ID == "" || policy.Version < 1 || policy.ExpiresAt == "" {
		return false
	}
	if policy.Action != "block" && policy.Action != "rate_limit" && policy.Action != "deceive" {
		return false
	}
	if policy.MatchSpec["session_hash"] == "" || policy.MatchSpec["route"] != "/api/search" {
		return false
	}
	expires, err := time.Parse(time.RFC3339Nano, policy.ExpiresAt)
	if err != nil || !expires.After(time.Now()) {
		return false
	}
	canonical := map[string]any{
		"id": policy.ID, "site_id": policy.SiteID, "action": policy.Action,
		"match_spec": policy.MatchSpec, "version": policy.Version, "expires_at": policy.ExpiresAt,
	}
	encoded, err := json.Marshal(canonical)
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, []byte(p.cfg.policyKey))
	_, _ = mac.Write(encoded)
	want := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(want), []byte(policy.Signature))
}

func (p *policyCache) prune() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for id, item := range p.items {
		if expires, err := time.Parse(time.RFC3339Nano, item.ExpiresAt); err != nil || !expires.After(time.Now()) {
			delete(p.items, id)
		}
	}
}

func (p *policyCache) match(siteID, session, route string) *scopedPolicy {
	if session == "" || siteID != p.cfg.siteID {
		return nil
	}
	p.prune()
	p.mu.RLock()
	defer p.mu.RUnlock()
	items := make([]scopedPolicy, 0, len(p.items))
	for _, item := range p.items {
		if item.MatchSpec["session_hash"] == session && item.MatchSpec["route"] == route {
			items = append(items, item)
		}
	}
	sort.Slice(items, func(i, j int) bool {
		priority := map[string]int{"block": 0, "rate_limit": 1, "deceive": 2}
		return priority[items[i].Action] < priority[items[j].Action]
	})
	if len(items) == 0 {
		return nil
	}
	result := items[0]
	return &result
}

func (p *policyCache) rateLimited(policyID, session string) bool {
	now := time.Now()
	key := policyID + ":" + session
	p.mu.Lock()
	defer p.mu.Unlock()
	window := now.Add(-30 * time.Second)
	kept := p.rate[key][:0]
	for _, t := range p.rate[key] {
		if t.After(window) {
			kept = append(kept, t)
		}
	}
	if len(kept) >= 20 {
		p.rate[key] = kept
		return true
	}
	p.rate[key] = append(kept, now)
	return false
}
