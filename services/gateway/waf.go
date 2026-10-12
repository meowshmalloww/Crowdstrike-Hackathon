package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sort"
	"strings"

	coreruleset "github.com/corazawaf/coraza-coreruleset/v4"
	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/debuglog"
	"github.com/corazawaf/coraza/v3/types"
)

func buildWAF(mode string) (coraza.WAF, error) {
	engine := "On"
	if mode == "observe-only" {
		engine = "DetectionOnly"
	}
	directives := strings.Join([]string{
		"SecRequestBodyAccess On",
		"SecRequestBodyLimit 1048576",
		"SecResponseBodyAccess Off",
		"SecAuditEngine Off",
		"SecRuleEngine " + engine,
	}, "\n")
	return coraza.NewWAF(
		coraza.NewWAFConfig().
			WithRootFS(coreruleset.FS).
			WithDebugLogger(debuglog.Default().WithLevel(debuglog.LevelNoLog)).
			WithDirectivesFromFile("@coraza.conf-recommended").
			WithDirectivesFromFile("@crs-setup.conf.example").
			WithDirectivesFromFile("@owasp_crs/*.conf").
			WithDirectives(directives),
	)
}

func serveWithWAF(w http.ResponseWriter, r *http.Request, waf coraza.WAF, state *requestState, next http.Handler) {
	tx := waf.NewTransaction()
	defer func() {
		tx.ProcessLogging()
		if err := tx.Close(); err != nil {
			logWAFError(state.requestID, err)
		}
	}()

	client, clientPort := clientAddress(r.RemoteAddr)
	tx.ProcessConnection(client, clientPort, "", 0)
	tx.ProcessURI(r.URL.String(), r.Method, r.Proto)
	for key, values := range r.Header {
		for _, value := range values {
			tx.AddRequestHeader(key, value)
		}
	}
	if r.Host != "" {
		tx.AddRequestHeader("Host", r.Host)
		tx.SetServerName(r.Host)
	}
	for _, transferEncoding := range r.TransferEncoding {
		tx.AddRequestHeader("Transfer-Encoding", transferEncoding)
	}
	for key, values := range r.URL.Query() {
		for _, value := range values {
			tx.AddGetRequestArgument(key, value)
		}
	}

	interruption := tx.ProcessRequestHeaders()
	if interruption == nil && tx.IsRequestBodyAccessible() && r.Body != nil && r.Body != http.NoBody {
		var err error
		interruption, _, err = tx.ReadRequestBodyFrom(r.Body)
		if err != nil {
			logWAFError(state.requestID, err)
			writeJSON(w, http.StatusRequestEntityTooLarge, map[string]any{"error": "request body exceeded the inspection limit", "request_id": state.requestID})
			return
		}
		if interruption == nil {
			bodyReader, err := tx.RequestBodyReader()
			if err != nil {
				logWAFError(state.requestID, err)
				writeJSON(w, http.StatusBadRequest, map[string]any{"error": "request body could not be inspected", "request_id": state.requestID})
				return
			}
			r.Body = io.NopCloser(io.MultiReader(bodyReader, r.Body))
		}
	}
	if interruption == nil {
		var err error
		interruption, err = tx.ProcessRequestBody()
		if err != nil {
			logWAFError(state.requestID, err)
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "request body could not be inspected", "request_id": state.requestID})
			return
		}
	}
	collectRuleIDs(tx, state)
	if interruption != nil {
		state.interrupted = interruption.Action == "deny" || interruption.Action == "drop" || interruption.Action == "redirect"
		status := interruption.Status
		if status < 400 || status > 599 {
			status = http.StatusForbidden
		}
		writeJSON(w, status, map[string]any{"error": "request blocked by CounterFlow WAF", "request_id": state.requestID})
		return
	}
	next.ServeHTTP(w, r)
}

func collectRuleIDs(tx types.Transaction, state *requestState) {
	state.mu.Lock()
	defer state.mu.Unlock()
	for _, matched := range tx.MatchedRules() {
		if matched == nil || matched.Rule() == nil {
			continue
		}
		id := matched.Rule().ID()
		if id > 0 {
			state.ruleIDs[id] = struct{}{}
		}
	}
}

func clientAddress(remote string) (string, int) {
	host, portText, err := net.SplitHostPort(remote)
	if err != nil {
		return remote, 0
	}
	var port int
	_, _ = fmt.Sscanf(portText, "%d", &port)
	return host, port
}

func sortedMatchedRules(tx types.Transaction) []int {
	set := make(map[int]struct{})
	for _, matched := range tx.MatchedRules() {
		if matched != nil && matched.Rule() != nil {
			set[matched.Rule().ID()] = struct{}{}
		}
	}
	ids := make([]int, 0, len(set))
	for id := range set {
		ids = append(ids, id)
	}
	sort.Ints(ids)
	return ids
}

func logWAFError(requestID string, err error) {
	log.Printf("waf_processing_error request_id=%s error_type=%T", requestID, err)
}
