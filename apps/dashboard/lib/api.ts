import "server-only";
import type { DashboardData } from "@/lib/types";

const base = process.env.CONTROL_API_URL ?? "http://127.0.0.1:8000";
const token = process.env.CONTROL_API_TOKEN ?? "";

export async function controlGet<T>(path: string): Promise<T | null> {
  if (!token) return null;
  try {
    const response = await fetch(`${base}${path}`, {
      headers: { Authorization: `Bearer ${token}` },
      cache: "no-store",
      signal: AbortSignal.timeout(2500),
    });
    if (!response.ok) return null;
    return (await response.json()) as T;
  } catch {
    return null;
  }
}

export async function loadDashboard(): Promise<DashboardData> {
  const [metrics, events, incidents, policies, honeypot, repairs, integrations, evaluation, settings, audit] = await Promise.all([
    controlGet<DashboardData["metrics"]>("/api/v1/metrics"),
    controlGet<DashboardData["events"]>("/api/v1/events?limit=50"),
    controlGet<DashboardData["incidents"]>("/api/v1/incidents?limit=50"),
    controlGet<DashboardData["policies"]>("/api/v1/policies"),
    controlGet<DashboardData["honeypot"]>("/api/v1/honeypot/interactions?limit=50"),
    controlGet<DashboardData["repairs"]>("/api/v1/repairs?limit=50"),
    controlGet<DashboardData["integrations"]>("/api/v1/integrations"),
    controlGet<DashboardData["evaluation"]>("/api/v1/evaluations"),
    controlGet<DashboardData["settings"]>("/api/v1/settings"),
    controlGet<DashboardData["audit"]>("/api/v1/audit?limit=50"),
  ]);
  return {
    connected: metrics !== null,
    metrics,
    events: events ?? [],
    incidents: incidents ?? [],
    policies: policies ?? [],
    honeypot: honeypot ?? [],
    repairs: repairs ?? [],
    integrations: integrations ?? {},
    evaluation,
    settings,
    audit: audit ?? [],
  };
}
