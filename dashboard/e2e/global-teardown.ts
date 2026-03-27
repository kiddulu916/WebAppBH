import { execFileSync } from "child_process";
import path from "path";

const REPO_ROOT = path.resolve(__dirname, "../..");

export default async function globalTeardown() {
  console.log("\n[e2e] Tearing down Docker stack...");
  execFileSync("docker", [
    "compose",
    "-f", "docker-compose.yml",
    "-f", "docker-compose.test.yml",
    "down", "-v",
  ], { cwd: REPO_ROOT, stdio: "inherit" });
  console.log("[e2e] Done.\n");
}
