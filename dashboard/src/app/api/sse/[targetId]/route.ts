export const runtime = "nodejs";
export const dynamic = "force-dynamic";

// Use runtime env vars (not NEXT_PUBLIC_ which are inlined at build time).
// In Docker, API_URL resolves to http://orchestrator:8001 at runtime.
function getApiUrl() {
  return process.env.API_URL ?? process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8001";
}
function getApiKey() {
  return process.env.API_KEY ?? process.env.NEXT_PUBLIC_API_KEY ?? "";
}

export async function GET(
  _request: Request,
  { params }: { params: Promise<{ targetId: string }> },
) {
  const { targetId } = await params;
  const abort = new AbortController();

  const upstream = await fetch(`${getApiUrl()}/api/v1/stream/${targetId}`, {
    headers: { "X-API-KEY": getApiKey() },
    signal: abort.signal,
  });

  if (!upstream.ok || !upstream.body) {
    return new Response("Upstream SSE unavailable", { status: 502 });
  }

  const stream = new ReadableStream({
    async start(controller) {
      const reader = upstream.body!.getReader();
      try {
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          controller.enqueue(value);
        }
      } catch {
        // client disconnected or upstream closed
      } finally {
        controller.close();
        abort.abort();
      }
    },
    cancel() {
      abort.abort();
    },
  });

  return new Response(stream, {
    headers: {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache",
      Connection: "keep-alive",
    },
  });
}
