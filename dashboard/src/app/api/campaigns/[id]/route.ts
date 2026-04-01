import { NextRequest, NextResponse } from "next/server";

const ORCHESTRATOR_URL = process.env.ORCHESTRATOR_URL || "http://orchestrator:8001";
const API_KEY = process.env.WEB_APP_BH_API_KEY || "";

export async function GET(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> },
) {
  const { id } = await params;
  const url = new URL(req.url);
  const search = url.search;
  const target = `${ORCHESTRATOR_URL}/api/v1/campaigns/${id}${search}`;

  const headers: Record<string, string> = {
    "Content-Type": "application/json",
  };
  if (API_KEY) headers["X-API-KEY"] = API_KEY;

  const res = await fetch(target, { headers });
  const data = await res.json();
  return NextResponse.json(data, { status: res.status });
}
