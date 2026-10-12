"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import type { DashboardData, EventRecord, Incident, Policy, Repair } from "@/lib/types";

type Props = { data: DashboardData };

function time(value?: string | null) {
  if (!value) return "—";
  return new Date(value).toLocaleString();
}

function value(value: number | null | undefined, suffix = "") {
  return value == null ? "—" : `${value}${suffix}`;
}

async function control(path: string, body?: unknown) {
  const response = await fetch(`/api/control/api/v1/${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body ?? {}),
  });
  const result = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(result.detail ?? `Request failed (${response.status})`);
  return result;
}

function SectionTitle({ title, detail }: { title: string; detail: string }) {
  return (
    <div className="section-heading">
      <h2>{title}</h2>
      <p className="section-detail">{detail}</p>
    </div>
  );
}

function LiveTraffic({ initial }: { initial: EventRecord[] }) {
  const router = useRouter();
  const [events, setEvents] = useState(initial);
  const [connected, setConnected] = useState(false);
  useEffect(() => {
    const source = new EventSource("/api/stream");
    source.onopen = () => setConnected(true);
    source.onerror = () => setConnected(false);
    source.addEventListener("request", (message) => {
      const event = JSON.parse((message as MessageEvent<string>).data) as EventRecord;
      setEvents((current) => [event, ...current.filter((item) => item.event_id !== event.event_id)].slice(0, 50));
    });
    source.addEventListener("incident", () => router.refresh());
    return () => source.close();
  }, [router]);
  return (
    <>
      <div className="stream-state">{connected ? "Event stream connected" : "Reconnecting to event stream"}</div>
      {events.length === 0 ? <div className="empty-state">No gateway events have been persisted yet. Send a request through port 8080 to populate this feed.</div> : (
        <div className="table-wrap">
          <table>
            <thead><tr><th>Time</th><th>Request</th><th>Route</th><th>Outcome</th><th>Signals</th><th>WAF rules</th><th>Latency</th></tr></thead>
            <tbody>{events.slice(0, 12).map((event) => (
              <tr key={event.event_id}>
                <td className="mono">{new Date(event.occurred_at).toLocaleTimeString()}</td>
                <td><span className="method">{event.method}</span><span className="mono muted"> {event.request_id.slice(0, 8)}</span></td>
                <td className="mono">{event.route}</td>
                <td><span className={`status status-${event.action}`}>{event.status} · {event.action.replaceAll("_", " ")}</span></td>
                <td>{Object.entries(event.signals ?? {}).filter(([, active]) => active).map(([name]) => <span className="tag" key={name}>{name.replaceAll("_", " ")}</span>)}</td>
                <td>{event.waf_rule_ids?.length ? <details className="rule-details"><summary>{event.waf_rule_ids.length} CRS rules</summary><span className="mono">{event.waf_rule_ids.join(", ")}</span></details> : "—"}</td>
                <td className="mono">{event.duration_ms.toFixed(1)} ms</td>
              </tr>
            ))}</tbody>
          </table>
        </div>
      )}
    </>
  );
}

function IncidentCard({ incident, onAction }: { incident: Incident; onAction: (message: string) => void }) {
  const router = useRouter();
  const [busy, setBusy] = useState(false);
  const [evidence, setEvidence] = useState<Array<{ event_id: string; request_id: string; occurred_at: string; route: string; method: string; status: number; action: string; waf_rule_ids: number[]; signals: Record<string, boolean> }> | null>(null);
  async function run(path: string, body?: unknown) {
    setBusy(true);
    try {
      await control(path, body);
      onAction("Action recorded by the control API.");
      router.refresh();
    } catch (error) {
      onAction(error instanceof Error ? error.message : "Action failed.");
    } finally {
      setBusy(false);
    }
  }
  async function loadEvidence() {
    const response = await fetch(`/api/control/api/v1/incidents/${incident.id}`);
    const result = await response.json().catch(() => ({}));
    if (!response.ok) { onAction(result.detail ?? "Evidence could not be loaded."); return; }
    setEvidence(result.evidence ?? []);
  }
  return (
    <article className="incident-card">
      <div className="incident-topline">
        <span className={`severity severity-${incident.severity}`}>{incident.severity}</span>
        <span className="score">{incident.risk_score}<small> / 100 heuristic · {incident.score_version}</small></span>
        <span className="incident-state">{incident.status}</span>
      </div>
      <div className="incident-title-row"><div><h3>{incident.classification.replaceAll("_", " ")}</h3><p className="mono muted">{incident.id}</p></div><time>{time(incident.last_seen_at)}</time></div>
      <p className="incident-explanation">{incident.explanation}</p>
      <p className="impact-note">{incident.estimated_impact}</p>
      <details className="incident-details">
        <summary>Technical details</summary>
        <div className="contribution-list" aria-label="Rule score contributions">
          {Object.entries(incident.score_contributions).map(([key, amount]) => <span key={key}>{key.replaceAll("_", " ")} <b>+{amount}</b></span>)}
        </div>
        <div className="evidence-row"><span>{incident.evidence_event_ids.length} evidence events</span><span>Jev: {incident.model_status}{incident.jev_choice ? ` · ${incident.jev_choice} (${Math.round((incident.jev_confidence ?? 0) * 100)}%)` : ""}</span><span>Local model: {incident.local_ai_status}</span><span>Detect {value(incident.request_to_alert_latency_ms, " ms")}</span></div>
        {incident.local_ai_summary && <p className="impact-note"><b>Local model advisory:</b> {incident.local_ai_summary}</p>}
      </details>
      <div className="action-row">
        <button className="button button-secondary" onClick={() => void loadEvidence()}>{evidence ? "Refresh evidence" : "Show evidence timeline"}</button>
        {incident.status !== "resolved" && <button className="button button-secondary" disabled={busy} onClick={() => run(`incidents/${incident.id}/${incident.status === "open" ? "acknowledge" : "resolve"}`)}>{incident.status === "open" ? "Acknowledge" : "Resolve"}</button>}
        <button className="button button-secondary" disabled={busy} onClick={() => run(`incidents/${incident.id}/repair`)}>Create repair job</button>
      </div>
      {evidence && <div className="evidence-timeline">{evidence.length === 0 ? <p className="muted small">No linked events were returned.</p> : evidence.map((event) => <div key={event.event_id}><time>{time(event.occurred_at)}</time><span className="mono">{event.method} {event.route}</span><span>{event.status} · {event.action}</span><span className="mono muted">{event.waf_rule_ids.length ? `${event.waf_rule_ids.length} CRS rules` : "No WAF rule ID"}</span><span>{Object.entries(event.signals).filter(([, yes]) => yes).map(([name]) => name.replaceAll("_", " ")).join(" · ") || "No positive features"}</span></div>)}</div>}
    </article>
  );
}

function PolicyPanel({ policies, onAction }: { policies: Policy[]; onAction: (message: string) => void }) {
  const router = useRouter();
  const [session, setSession] = useState("");
  const [action, setAction] = useState("deceive");
  const [busy, setBusy] = useState(false);
  async function propose(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    try {
      await control("policies/proposals", { action, reason: "Scoped response for an authorized CounterFlow lab session.", ttl_seconds: 180, session_token: session, route: "/api/search" });
      setSession("");
      onAction("Policy proposal saved. Review and approve it below to activate its signed TTL.");
      router.refresh();
    } catch (error) {
      onAction(error instanceof Error ? error.message : "Policy proposal failed.");
    } finally { setBusy(false); }
  }
  async function change(id: string, verb: "approve" | "revoke") {
    setBusy(true);
    try {
      await control(`policies/${id}/${verb}`);
      onAction(`Policy ${verb} request recorded.`);
      router.refresh();
    } catch (error) {
      onAction(error instanceof Error ? error.message : "Policy update failed.");
    } finally { setBusy(false); }
  }
  return (
    <div className="policy-layout">
      <form className="policy-form" onSubmit={propose}>
        <label htmlFor="session-token">Exact lab session marker</label>
        <input id="session-token" minLength={8} maxLength={128} required value={session} onChange={(e) => setSession(e.target.value)} placeholder="Use the X-CounterFlow-Session value from the tester" />
        <div className="form-row"><label htmlFor="policy-action">Action</label><select id="policy-action" value={action} onChange={(e) => setAction(e.target.value)}><option value="deceive">Divert to isolated decoy</option><option value="block">Block exact session</option><option value="rate_limit">Rate limit exact session</option></select></div>
        <button className="button button-primary" disabled={busy || session.length < 8}>Propose 3-minute policy</button>
        <p className="muted small">Manual policy scope is one session hash plus <code>/api/search</code>; it expires automatically and requires operator approval. In <code>lab-auto</code>, the detector may directly activate a short-lived deception after repeated correlated SQL injection attempts.</p>
      </form>
      <div className="policy-list">
        {policies.length === 0 ? <div className="empty-state">No containment policies are active or proposed.</div> : policies.map((policy) => (
          <article className="policy-item" key={policy.id}>
            <div><span className={`status status-${policy.status}`}>{policy.status}</span> <b>{policy.action.replaceAll("_", " ")}</b><p className="muted small">{policy.reason}</p><small>Session …{policy.match_spec.session_hash?.slice(-8)} · {policy.match_spec.route} · expires {time(policy.expires_at)}</small></div>
            <div className="action-row compact">{policy.status === "proposed" && <button className="button button-primary" disabled={busy} onClick={() => change(policy.id, "approve")}>Approve</button>}{policy.status === "active" && <button className="button button-danger" disabled={busy} onClick={() => change(policy.id, "revoke")}>Revoke</button>}</div>
          </article>
        ))}
      </div>
    </div>
  );
}

function RepairPanel({ repairs, onAction }: { repairs: Repair[]; onAction: (message: string) => void }) {
  const router = useRouter();
  const [logs, setLogs] = useState<Record<string, string>>({});
  const [busyId, setBusyId] = useState<string | null>(null);
  async function loadLogs(id: string) {
    const response = await fetch(`/api/control/api/v1/repairs/${id}/logs`);
    const result = await response.json().catch(() => ({}));
    if (response.ok) setLogs((current) => ({ ...current, [id]: result.log }));
    else onAction(result.detail ?? "Could not load repair log.");
  }
  async function approve(id: string) {
    setBusyId(id);
    try {
      await control(`repairs/${id}/approve-lab-promotion`);
      onAction("Approval is recorded. No container was changed; the reviewed lab promotion script is the next step.");
      router.refresh();
    } catch (error) { onAction(error instanceof Error ? error.message : "Approval failed."); }
    finally { setBusyId(null); }
  }
  async function runBaseline(id: string) {
    setBusyId(id);
    try {
      await control(`repairs/${id}/run-baseline`);
      onAction("The deterministic baseline finished. Review its saved diff and regression log.");
      router.refresh();
    } catch (error) { onAction(error instanceof Error ? error.message : "Baseline run failed."); }
    finally { setBusyId(null); }
  }
  return repairs.length === 0 ? <div className="empty-state">No repair jobs have been requested. Repair jobs are tied to a persisted incident.</div> : (
    <div className="repair-list">{repairs.map((repair) => (
      <article className="repair-card" key={repair.id}>
        <div className="repair-heading"><div><span className={`status status-${repair.status}`}>{repair.status.replaceAll("_", " ")}</span><h3>{repair.model_provider === "deterministic-baseline" ? "Deterministic remediation candidate" : "Coding-model repair"}</h3></div><span className="mono muted">{repair.id.slice(0, 12)}</span></div>
        <p>{repair.diff_summary || "Waiting for an explicitly configured coding model. No patch has been generated."}</p>
        <div className="repair-meta"><span>Repo: <code>{repair.repository}</code></span><span>Branch: <code>{repair.branch ?? "not created"}</code></span><span>Base: <code>{repair.commit_base}</code></span></div>
        {repair.checks.length > 0 && <div className="check-list">{repair.checks.map((check) => <div key={check.test_name}><span className={check.exit_code === 0 ? "check-pass" : "check-fail"}>{check.outcome}</span><span>{check.test_name}</span><code>exit {check.exit_code}</code></div>)}</div>}
        {repair.diff && <details className="diff-details"><summary>Review generated Git diff</summary><pre>{repair.diff}</pre></details>}
        {(repair.status === "waiting_for_model" || repair.status === "failed") && <div className="action-row"><button className="button button-primary" disabled={busyId !== null} onClick={() => void runBaseline(repair.id)}>Run deterministic baseline</button><span className="muted small">Uses the reviewed local SQL parameterization candidate; this is not AI-generated.</span></div>}
        {repair.status === "awaiting_approval" && <div className="action-row"><button className="button button-secondary" disabled={busyId !== null} onClick={() => void loadLogs(repair.id)}>Load test log</button><button className="button button-primary" disabled={busyId !== null} onClick={() => void approve(repair.id)}>Approve manual lab promotion</button></div>}
        {repair.status !== "awaiting_approval" && repair.checks.length > 0 && <button className="button button-secondary" onClick={() => void loadLogs(repair.id)}>Load test log</button>}
        {logs[repair.id] && <pre className="log-view">{logs[repair.id]}</pre>}
        {repair.status === "approved_for_manual_lab_promotion" && <p className="notice-line">Approval recorded. Deployment remains pending until the operator runs the promotion script.</p>}
      </article>
    ))}</div>
  );
}

function EvaluationPanel({ evaluation, onAction }: { evaluation: DashboardData["evaluation"]; onAction: (message: string) => void }) {
  const router = useRouter();
  const [busy, setBusy] = useState(false);
  async function run() {
    setBusy(true);
    try { await control("evaluations/run"); onAction("Evaluation completed against the labeled synthetic fixture."); router.refresh(); }
    catch (error) { onAction(error instanceof Error ? error.message : "Evaluation failed."); }
    finally { setBusy(false); }
  }
  const metrics = evaluation?.latest?.metrics;
  const matrix = metrics?.confusion_matrix as Record<string, number> | undefined;
  return (
    <div className="evaluation-grid">
      <div className="metric-card"><span>Dataset</span><strong>{evaluation?.latest ? evaluation.latest.dataset : "Not run"}</strong><small>Only labeled synthetic records</small></div>
      <div className="metric-card"><span>Precision</span><strong>{metrics?.precision == null ? "—" : `${(Number(metrics.precision) * 100).toFixed(1)}%`}</strong><small>Measured on current fixture</small></div>
      <div className="metric-card"><span>Recall</span><strong>{metrics?.recall == null ? "—" : `${(Number(metrics.recall) * 100).toFixed(1)}%`}</strong><small>Measured on current fixture</small></div>
      <div className="metric-card"><span>False-positive rate</span><strong>{metrics?.false_positive_rate == null ? "—" : `${(Number(metrics.false_positive_rate) * 100).toFixed(1)}%`}</strong><small>Benign apostrophes and punctuation included</small></div>
      {matrix && <div className="matrix"><span>Confusion matrix</span><div>TP <b>{matrix.true_positive}</b></div><div>FP <b>{matrix.false_positive}</b></div><div>TN <b>{matrix.true_negative}</b></div><div>FN <b>{matrix.false_negative}</b></div></div>}
      <div className="evaluation-action"><p className="muted small">{String(metrics?.limitation ?? "No evaluation has been run yet. The UI will not invent benchmark values.")}</p><button className="button button-primary" disabled={busy} onClick={() => void run()}>{busy ? "Running…" : "Run synthetic evaluation"}</button></div>
    </div>
  );
}

export function ControlCenter({ data }: Props) {
  const [notice, setNotice] = useState("");
  const metrics = data.metrics;
  const activePolicies = data.policies.filter((policy) => policy.status === "active").length;
  const navGroups = [
    { label: "Monitor", links: [["#overview", "Overview"], ["#traffic", "Live traffic"], ["#incidents", "Incidents"]] },
    { label: "Respond", links: [["#defenses", "Defenses"], ["#deception", "Deception"], ["#repairs", "Repairs"]] },
    { label: "System", links: [["#evaluation", "Evaluation"], ["#settings", "Settings"]] },
  ];
  return (
    <div className="app-shell">
      <aside className="sidebar">
        <a className="brand" href="#overview"><span>CounterFlow<small>Site protection</small></span></a>
        <nav aria-label="Primary navigation">{navGroups.map((group) => <div className="nav-group" key={group.label}><p>{group.label}</p>{group.links.map(([href, label]) => <a key={href} href={href}>{label}</a>)}</div>)}</nav>
        <div className="sidebar-bottom"><span>Lab environment</span><p>Single site. Synthetic data. Local operator.</p></div>
      </aside>

      <main className="main-content">
        <header className="topbar"><h1>Control center</h1><div className="connection-chip"><span>{data.connected ? "Connected" : "Disconnected"}</span><span>Mode: {metrics?.lab_mode ?? "unknown"}</span></div></header>

        {!data.connected && <div className="connection-banner" role="status"><b>Control plane unavailable.</b> Live values are not available. Start CounterFlow with <code>scripts/start-local.ps1</code> and check service health.</div>}
        {notice && <div className="notice" role="status"><span>{notice}</span><button aria-label="Dismiss message" onClick={() => setNotice("")}>×</button></div>}

        <section id="overview" className="overview-block">
          <div className="overview-intro"><div><h2>Overview</h2><p>Traffic, incidents, and actions recorded by the gateway.</p></div><div className={`freshness freshness-${metrics?.telemetry_freshness ?? "unknown"}`}>Telemetry: {metrics?.telemetry_freshness ?? "unavailable"}<small>Last event {time(metrics?.last_event_at)}</small></div></div>
          <div className="metric-grid">
            <div className="metric-card"><span>Requests / min</span><strong>{value(metrics?.events_last_minute)}</strong><small>{value(metrics?.events_per_second)} per second · persisted</small></div>
            <div className="metric-card"><span>Open incidents</span><strong>{value(metrics?.open_incidents)}</strong><small>Ranked from observed evidence</small></div>
            <div className="metric-card"><span>Active defenses</span><strong>{value(activePolicies)}</strong><small>Signed, scoped, expiring policies</small></div>
            <div className="metric-card"><span>Decoy requests</span><strong>{value(metrics?.honeypot_interactions)}</strong><small>Received by isolated fictional API</small></div>
          </div>
          <div className="latency-strip"><span>Origin response average <b>{value(metrics?.average_response_latency_ms, " ms")}</b></span><span>Request-to-alert average <b>{value(metrics?.average_request_to_alert_latency_ms, " ms")}</b></span><span>Total persisted events <b>{value(metrics?.total_events)}</b></span></div>
        </section>

        <section id="traffic" className="panel">
          <SectionTitle title="Live traffic" detail="Request outcomes, WAF matches, and response time." />
          <LiveTraffic initial={data.events} />
        </section>

        <section id="incidents" className="panel">
          <SectionTitle title="Incidents" detail="Ranked from observed request evidence. Jev triage is shown separately when configured." />
          {data.incidents.length === 0 ? <div className="empty-state">No incidents have been created from the captured traffic yet. Benign requests remain visible in Live Traffic without raising an incident.</div> : <div className="incident-list">{data.incidents.map((incident) => <IncidentCard key={incident.id} incident={incident} onAction={setNotice} />)}</div>}
        </section>

        <section id="defenses" className="panel">
          <SectionTitle title="Defenses" detail="Manual actions need approval and target one session. Lab-auto can activate a short-lived decoy policy after repeated SQL injection attempts." />
          <PolicyPanel policies={data.policies} onAction={setNotice} />
        </section>

        <section id="deception" className="panel">
          <SectionTitle title="Deception" detail="Requests sent to the isolated decoy service. It uses fictional data and has no connection to the origin database." />
          {data.honeypot.length === 0 ? <div className="empty-state">The decoy has not received a request. A session is diverted only after a narrow policy is active.</div> : <div className="table-wrap"><table><thead><tr><th>Time</th><th>Request ID</th><th>Decoy service</th><th>Route</th><th>HTTP</th></tr></thead><tbody>{data.honeypot.map((item) => <tr key={item.id}><td>{time(item.occurred_at)}</td><td className="mono">{item.request_id.slice(0, 12)}</td><td><span className="tag">fictional decoy</span></td><td className="mono">{item.route}</td><td>{item.result_status}</td></tr>)}</tbody></table></div>}
        </section>

        <section id="repairs" className="panel">
          <SectionTitle title="Repair jobs" detail="Review proposed changes and their checks. Nothing is promoted without operator approval." />
          <RepairPanel repairs={data.repairs} onAction={setNotice} />
        </section>

        <section id="evaluation" className="panel">
          <SectionTitle title="Detection quality" detail="Results from the labeled synthetic fixture. These are not production performance estimates." />
          <EvaluationPanel evaluation={data.evaluation} onAction={setNotice} />
        </section>

        <section id="settings" className="panel">
          <SectionTitle title="Settings" detail="Site configuration and connected service status. Credentials are never displayed." />
          <div className="settings-grid">
            <div className="settings-card"><h3>Protected website</h3><dl><dt>Site</dt><dd>{data.settings?.site_id ?? "Unavailable"}</dd><dt>Mode</dt><dd>{data.settings?.lab_mode ?? "Unavailable"}</dd><dt>Upstream origin</dt><dd className="mono">{String(data.settings?.origin_url ?? "Unavailable")}</dd><dt>Origin profile</dt><dd>{String(data.settings?.origin_profile ?? "Unavailable")} · vulnerable lab fixture {data.settings?.lab_vulnerable_origin ? "enabled" : "disabled"}</dd><dt>Management auth</dt><dd>{String(data.settings?.management_authentication ?? "Unavailable")}</dd><dt>Session pseudonymization</dt><dd>{String(data.settings?.source_ip_pseudonymization ?? "Unavailable")}</dd></dl><p className="muted small">Change ORIGIN_URL in the local .env file and restart CounterFlow.</p><div className="routing-guide"><h4>Route website traffic through CounterFlow</h4><ol><li>Set ORIGIN_URL to your website’s private IP or hostname and port.</li><li>Point your domain or HTTPS reverse proxy to the CounterFlow gateway.</li><li>Block direct public access to the origin so visitors cannot bypass protection.</li></ol><p className="muted small">Keep the Control Center and management API private. Terminate public HTTPS at a trusted reverse proxy.</p></div></div>
            <div className="settings-card"><h3>Connected services</h3>{Object.entries(data.integrations).length === 0 ? <p className="muted">Integration status unavailable.</p> : Object.entries(data.integrations).map(([name, integration]) => <div className="integration-row" key={name}><div><b>{name.replaceAll("_", " ")}</b><small>{integration.role}{integration.model ? ` · ${integration.model}` : ""}</small>{integration.note && <small>{integration.note}</small>}</div><span className={`status status-${integration.status}`}>{integration.status.replaceAll("_", " ")}</span></div>)}</div>
          </div>
          <details className="audit-history"><summary>Recent audit history</summary>{data.audit.length === 0 ? <p className="empty-state">No management actions have been recorded yet.</p> : <div className="table-wrap"><table><thead><tr><th>Time</th><th>Principal</th><th>Action</th><th>Target</th><th>Outcome</th></tr></thead><tbody>{data.audit.map((entry) => <tr key={entry.id}><td>{time(entry.created_at)}</td><td>{entry.principal_id}</td><td className="mono">{entry.action}</td><td className="mono">{entry.target.slice(0, 18)}</td><td>{entry.outcome}</td></tr>)}</tbody></table></div>}</details>
        </section>
        <footer className="footer"><span>COUNTERFLOW · WORKING LAB</span><span>No customer data · No external engagement · Not production reviewed</span></footer>
      </main>
    </div>
  );
}
