import asyncio
import time
from origo.endpoints import _is_public_host

async def _is_public_host_async(hostname: str) -> bool:
    loop = asyncio.get_running_loop()
    try:
        addrinfo = await loop.getaddrinfo(hostname, None)
    except OSError:
        return False

    import ipaddress
    for *_rest, sockaddr in addrinfo:
        ip = ipaddress.ip_address(sockaddr[0])
        if getattr(ip, 'ipv4_mapped', None):
            ip = ip.ipv4_mapped
        if not ip.is_global or ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast or ip.is_unspecified:
            return False
    return True

async def test_is_public_host_async(hostnames):
    start = time.perf_counter()
    tasks = [_is_public_host_async(host) for host in hostnames]
    await asyncio.gather(*tasks)
    end = time.perf_counter()
    return end - start

async def main():
    hostnames = ["example.com", "google.com", "github.com", "microsoft.com", "apple.com"] * 5
    elapsed = await test_is_public_host_async(hostnames)
    print(f"Elapsed time (async): {elapsed:.4f} seconds")

if __name__ == "__main__":
    asyncio.run(main())
