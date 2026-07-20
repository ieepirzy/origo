import asyncio
import time
from origo.endpoints import _is_public_host

async def test_is_public_host(hostnames):
    start = time.perf_counter()
    for host in hostnames:
        _is_public_host(host)
    end = time.perf_counter()
    return end - start

async def main():
    hostnames = ["example.com", "google.com", "github.com", "microsoft.com", "apple.com"] * 5
    elapsed = await test_is_public_host(hostnames)
    print(f"Elapsed time (sync): {elapsed:.4f} seconds")

if __name__ == "__main__":
    asyncio.run(main())
