import { execFileSync } from "child_process";
import path from "path";
import { waitForService } from "./helpers/wait-for-services";

const REPO_ROOT = path.resolve(__dirname, "../..");
const STARTUP_TIMEOUT = 120_000;

export default async function globalSetup() {
  console.log("\n[e2e] Starting Docker stack...");

  execFileSync("docker", [
    "compose",
    "-f", "docker-compose.yml",
    "-f", "docker-compose.test.yml",
    "up", "-d", "--build",
    "postgres", "redis", "orchestrator", "dashboard",
  ], { cwd: REPO_ROOT, stdio: "inherit" });

  console.log("[e2e] Waiting for services...");
  await waitForService("http://localhost:8001/health", STARTUP_TIMEOUT, "Orchestrator");
  await waitForService("http://localhost:3000", STARTUP_TIMEOUT, "Dashboard");
  console.log("[e2e] All services ready.\n");
}
