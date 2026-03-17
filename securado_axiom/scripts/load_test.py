from __future__ import annotations

import statistics
import time
import urllib.request



def run(url: str = "http://localhost:8080/health", requests: int = 100) -> None:
    latencies = []
    ok = 0
    for _ in range(requests):
        start = time.perf_counter()
        try:
            with urllib.request.urlopen(url, timeout=5) as resp:
                if resp.status == 200:
                    ok += 1
        except Exception:
            pass
        latencies.append((time.perf_counter() - start) * 1000)

    p95 = statistics.quantiles(latencies, n=20)[18] if len(latencies) >= 20 else max(latencies)
    avg = statistics.mean(latencies)
    print(f"requests={requests} ok={ok} avg_ms={avg:.2f} p95_ms={p95:.2f}")


if __name__ == "__main__":
    run()
