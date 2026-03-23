export const runtime = "nodejs";
export const dynamic = "force-dynamic";

import http from "node:http";

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
  const url = `${getApiUrl()}/api/v1/stream/${targetId}`;
  const encoder = new TextEncoder();

  const stream = new ReadableStream({
    start(controller) {
      // Send an SSE comment immediately to flush headers to the client.
      // The upstream orchestrator doesn't send a heartbeat, so without this
      // the Next.js dev server buffers until the first real event arrives.
      controller.enqueue(encoder.encode(": connected\n\n"));

      const parsed = new URL(url);
      const req = http.get(
        {
          hostname: parsed.hostname,
          port: parsed.port,
          path: parsed.pathname,
          headers: {
            "X-API-KEY": getApiKey(),
            Accept: "text/event-stream",
          },
        },
        (res) => {
          if (res.statusCode !== 200) {
            controller.enqueue(encoder.encode("event: error\ndata: upstream unavailable\n\n"));
            controller.close();
            return;
          }
          res.on("data", (chunk: Buffer) => {
            controller.enqueue(new Uint8Array(chunk));
          });
          res.on("end", () => controller.close());
          res.on("error", () => controller.close());
        },
      );

      req.on("error", () => {
        controller.enqueue(encoder.encode("event: error\ndata: connection failed\n\n"));
        controller.close();
      });
    },
  });

  return new Response(stream, {
    headers: {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache, no-store",
      Connection: "keep-alive",
      "X-Accel-Buffering": "no",
    },
  });
}
