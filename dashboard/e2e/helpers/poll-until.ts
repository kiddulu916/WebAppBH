export async function pollUntil<T>(
  fn: () => Promise<T>,
  predicate: (val: T) => boolean,
  timeout: number,
  interval = 1000,
): Promise<T> {
  const start = Date.now();
  while (Date.now() - start < timeout) {
    const val = await fn();
    if (predicate(val)) return val;
    await new Promise((r) => setTimeout(r, interval));
  }
  throw new Error(`pollUntil timed out after ${timeout}ms`);
}
