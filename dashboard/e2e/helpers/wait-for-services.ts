export async function waitForService(
  url: string,
  timeout: number,
  label: string,
): Promise<void> {
  const start = Date.now();
  while (Date.now() - start < timeout) {
    try {
      const res = await fetch(url);
      if (res.ok) {
        console.log(`  [ok] ${label} ready`);
        return;
      }
    } catch {
      // Not ready yet
    }
    await new Promise((r) => setTimeout(r, 2000));
  }
  throw new Error(`${label} not ready after ${timeout}ms (${url})`);
}
