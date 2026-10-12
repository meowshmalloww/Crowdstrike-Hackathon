import { NextRequest } from "next/server";

export const dynamic = "force-dynamic";

async function proxy(request: NextRequest, context: { params: Promise<{ path: string[] }> }) {
  const token = process.env.CONTROL_API_TOKEN;
  const base = process.env.CONTROL_API_URL;
  if (!token || !base) return Response.json({ detail: "Control plane credentials are not configured" }, { status: 503 });
  const origin = request.headers.get("origin");
  if ((origin && origin !== request.nextUrl.origin) || (request.method === "POST" && !origin)) {
    return Response.json({ detail: "Cross-origin management requests are not allowed" }, { status: 403 });
  }
  const { path } = await context.params;
  if (path[0] !== "api" || path[1] !== "v1") return Response.json({ detail: "Unknown management path" }, { status: 404 });
  const target = `${base}/${path.map(encodeURIComponent).join("/")}${request.nextUrl.search}`;
  const headers = new Headers({ Authorization: `Bearer ${token}` });
  const contentType = request.headers.get("content-type");
  if (contentType) headers.set("Content-Type", contentType);
  if (request.method === "POST") headers.set("X-Request-ID", crypto.randomUUID());
  const body = request.method === "POST" ? await request.arrayBuffer() : undefined;
  try {
    const upstream = await fetch(target, { method: request.method, headers, body, cache: "no-store", signal: AbortSignal.timeout(60000) });
    return new Response(upstream.body, {
      status: upstream.status,
      headers: {
        "Content-Type": upstream.headers.get("content-type") ?? "application/json",
        "Cache-Control": "no-store",
      },
    });
  } catch {
    return Response.json({ detail: "Control plane is unavailable" }, { status: 503 });
  }
}

export const GET = proxy;
export const POST = proxy;
