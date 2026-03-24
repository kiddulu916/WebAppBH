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

  let upstream: ReturnType<typeof http.get> | null = null;

  const stream = new ReadableStream({
    start(controller) {
      let closed = false;
      function close() {
        if (!closed) { closed = true; controller.close(); }
      }
      function enqueue(data: Uint8Array) {
        if (!closed) { controller.enqueue(data); }
      }

      enqueue(encoder.encode(": connected\n\n"));

      const parsed = new URL(url);
      upstream = http.get(
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
            enqueue(encoder.encode("event: error\ndata: upstream unavailable\n\n"));
            close();
            return;
          }
          res.on("data", (chunk: Buffer) => {
            enqueue(new Uint8Array(chunk));
          });
          res.on("end", () => close());
          res.on("error", () => close());
        },
      );

      upstream.on("error", () => {
        enqueue(encoder.encode("event: error\ndata: connection failed\n\n"));
        close();
      });
    },
    cancel() {
      upstream?.destroy();
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
