# workers/cryptography/concurrency.py
import asyncio
import os

HEAVY_LIMIT = 2
LIGHT_LIMIT = int(os.environ.get("LIGHT_CONCURRENCY", str(os.cpu_count() or 4)))

TOOL_WEIGHTS = {
    # Filled in by each worker plan
    "TlsAuditor": "LIGHT",
    "PaddingOracleTester": "LIGHT",
    "PlaintextLeakScanner": "LIGHT",
    "AlgorithmAuditor": "LIGHT",
}


def get_semaphores() -> tuple[asyncio.Semaphore, asyncio.Semaphore]:
    return asyncio.Semaphore(HEAVY_LIMIT), asyncio.Semaphore(LIGHT_LIMIT)