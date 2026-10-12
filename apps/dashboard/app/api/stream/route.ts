import { NextRequest } from "next/server";

export const dynamic = "force-dynamic";

export async function GET(request: NextRequest) {
  const token = process.env.CONTROL_API_TOKEN;
  const base = process.env.CONTROL_API_URL;
  if (!token || !base) return new Response("Control plane credentials are not configured", { status: 503 });
  const origin = request.headers.get("origin");
  if (origin && origin !== request.nextUrl.origin) return new Response("Cross-origin event streams are not allowed", { status: 403 });
  try {
    const headers = new Headers({ Authorization: `Bearer ${token}` });
    const lastEventId = request.headers.get("last-event-id");
    if (lastEventId) headers.set("Last-Event-ID", lastEventId);
    const upstream = await fetch(`${base}/api/v1/stream`, { headers, cache: "no-store", signal: request.signal });
    return new Response(upstream.body, {
      status: upstream.status,
      headers: { "Content-Type": "text/event-stream", "Cache-Control": "no-cache", "X-Accel-Buffering": "no" },
    });
  } catch {
    return new Response("Control plane is unavailable", { status: 503 });
  }
}
