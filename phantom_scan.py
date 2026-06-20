import asyncio, httpx, json, sys, time

TARGETS = {
    "webkit_jit": [
        "https://raw.githubusercontent.com/WebKit/WebKit/main/Source/JavaScriptCore/jit/JIT.cpp",
        "https://raw.githubusercontent.com/WebKit/WebKit/main/Source/JavaScriptCore/heap/Heap.cpp",
        "https://raw.githubusercontent.com/WebKit/WebKit/main/Source/JavaScriptCore/parser/Parser.cpp",
        "https://raw.githubusercontent.com/WebKit/WebKit/main/Source/JavaScriptCore/runtime/JSObject.cpp",
    ],
    "v8_core": [
        "https://raw.githubusercontent.com/v8/v8/main/src/codegen/compiler.cc",
        "https://raw.githubusercontent.com/v8/v8/main/src/heap/heap.cc",
        "https://raw.githubusercontent.com/v8/v8/main/src/compiler/pipeline.cc",
    ],
    "android_media": [
        "https://android.googlesource.com/platform/frameworks/av/+/refs/heads/main/media/codec2/components/avc/C2SoftAvcDec.cpp?format=TEXT",
    ]
}

async def scan_file(client, url, idx, total):
    print(f"[{idx}/{total}] Scanning: {url.split('/')[-1]}")
    try:
        r = await client.post(
            "http://localhost:8000/scan/start",
            json={
                "target": url,
                "target_type": "hardware",
                "scope": ["RCE","Memory","Logic","Crypto","Auth"]
            },
            timeout=30
        )
        scan_id = r.json()["scan_id"]
        print(f"  → scan_id: {scan_id}")

        # Wait for completion
        for _ in range(30):
            await asyncio.sleep(5)
            status = await client.get(f"http://localhost:8000/scan/{scan_id}/status")
            s = status.json()
            if s["status"] == "complete":
                result = await client.get(f"http://localhost:8000/scan/{scan_id}/result")
                return result.json()
            elif s["status"] == "error":
                return None
        return None
    except Exception as e:
        print(f"  ✗ Error: {e}")
        return None

async def main():
    target = sys.argv[1] if len(sys.argv) > 1 else "webkit_jit"
    urls = TARGETS.get(target, TARGETS["webkit_jit"])

    print(f"\n{'='*60}")
    print(f"PHANTOM — Scanning: {target.upper()}")
    print(f"Files: {len(urls)}")
    print(f"{'='*60}\n")

    all_vulns = []
    total_bounty = 0

    async with httpx.AsyncClient() as client:
        for i, url in enumerate(urls, 1):
            result = await scan_file(client, url, i, len(urls))
            if result and result.get("vulnerabilities"):
                vulns = result["vulnerabilities"]
                bounty = result.get("estimated_bounty", {}).get("most_likely", 0)
                all_vulns.extend(vulns)
                total_bounty += bounty
                print(f"  ✅ Found {len(vulns)} vulns | Bounty: ${bounty:,}")
            else:
                print(f"  ○ No findings")
            time.sleep(2)  # Rate limit

    print(f"\n{'='*60}")
    print(f"SCAN COMPLETE")
    print(f"Total Vulnerabilities: {len(all_vulns)}")
    print(f"Total Estimated Bounty: ${total_bounty:,}")
    print(f"{'='*60}")

    # Summary
    for v in all_vulns:
        print(f"\n[{v['severity'].upper()}] {v['title']}")
        print(f"  CVSS: {v['cvss_score']} | {v['cwe']}")
        print(f"  {v['description'][:100]}...")

asyncio.run(main())
