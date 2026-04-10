import requests
import json
import time
import datetime
import os

ENDPOINTS = [
    "https://rpc.testnet.arc.network",
    "https://rpc.drpc.testnet.arc.network",
    "https://rpc.quicknode.testnet.arc.network",
    "https://rpc.blockdaemon.testnet.arc.network",
]

os.makedirs("findings", exist_ok=True)
timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
log_file = f"findings/forwarder_{timestamp}.log"

def log(msg):
    line = f"[{datetime.datetime.now().strftime('%H:%M:%S')}] {msg}"
    print(line)
    with open(log_file, "a") as f:
        f.write(line + "\n")

def flag(endpoint, test, detail):
    log(f"  ⚠️  FINDING [{test}] on {endpoint}")
    log(f"     {detail}")
    with open(log_file, "a") as f:
        f.write(f"\n{'='*60}\n")
        f.write(f"FINDING: {test}\n")
        f.write(f"ENDPOINT: {endpoint}\n")
        f.write(f"DETAIL: {detail}\n")
        f.write(f"{'='*60}\n\n")

def rpc(endpoint, method, params=[], headers=None, id=1):
    h = {"Content-Type": "application/json"}
    if headers:
        h.update(headers)
    payload = {"jsonrpc": "2.0", "method": method, "params": params, "id": id}
    try:
        r = requests.post(endpoint, headers=h, json=payload, timeout=10)
        return r.status_code, r.headers, r.json()
    except Exception as e:
        return None, {}, {"error": str(e)}

def raw_post(endpoint, data, headers=None):
    h = {"Content-Type": "application/json"}
    if headers:
        h.update(headers)
    try:
        r = requests.post(endpoint, headers=h, data=data, timeout=10)
        return r.status_code, r.headers, r.text
    except Exception as e:
        return None, {}, str(e)

# ── Test 1: Response header analysis ─────────────────────────────────────────
def test_response_headers(ep):
    log(f"  [1] Response header analysis...")
    status, headers, resp = rpc(ep, "eth_blockNumber")

    interesting = {}
    for k, v in headers.items():
        kl = k.lower()
        if any(word in kl for word in [
            "server", "via", "x-", "forwarded", "upstream",
            "backend", "proxy", "powered", "version", "node"
        ]):
            interesting[k] = v

    if interesting:
        log(f"      Interesting headers found: {json.dumps(interesting)}")
        # Check for internal IP addresses in headers
        import re
        header_str = json.dumps(interesting)
        internal_ips = re.findall(
            r'(10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)',
            header_str
        )
        if internal_ips:
            flag(ep, "INTERNAL_IP_IN_HEADERS",
                 f"Internal IP addresses found in response headers: {internal_ips}. "
                 f"Full headers: {json.dumps(interesting)}")
        # Check for upstream URL disclosure
        upstream_hints = [v for k,v in interesting.items()
                         if any(word in v.lower() for word in
                                ["arc.network", "quicknode", "drpc", "blockdaemon",
                                 "localhost", "127.0.0.1", "internal"])]
        if upstream_hints:
            flag(ep, "UPSTREAM_DISCLOSURE_IN_HEADERS",
                 f"Upstream/internal info in headers: {upstream_hints}")
    else:
        log(f"      No interesting headers found — OK")

    return headers

# ── Test 2: X-Forwarded-For injection ────────────────────────────────────────
def test_header_injection(ep):
    log(f"  [2] Header injection tests...")

    # Test if injected headers affect response or get reflected
    injected_headers = {
        "X-Forwarded-For": "127.0.0.1",
        "X-Real-IP": "127.0.0.1",
        "X-Forwarded-Host": "localhost",
        "X-Original-URL": "/admin",
        "X-Rewrite-URL": "/admin",
    }

    status, headers, resp = rpc(ep, "eth_blockNumber", headers=injected_headers)

    # Check if any injected values appear in response
    resp_str = json.dumps(resp)
    for k, v in injected_headers.items():
        if v in resp_str:
            flag(ep, "HEADER_INJECTION_REFLECTED",
                 f"Injected header value '{v}' from '{k}' appeared in response: {resp_str[:300]}")

    # Check if X-Forwarded-For changes behavior
    status2, headers2, resp2 = rpc(ep, "eth_blockNumber")
    if resp.get("result") != resp2.get("result"):
        flag(ep, "HEADER_AFFECTS_RESPONSE",
             f"Response differs with injected headers. "
             f"Normal: {resp2.get('result')} | Injected: {resp.get('result')}")
    else:
        log(f"      Header injection had no effect on response — OK")

# ── Test 3: Forwarder behavior with unknown methods ───────────────────────────
def test_forwarder_unknown_methods(ep):
    log(f"  [3] Unknown method forwarding behavior...")

    # These are methods that exist in standard Ethereum but
    # may not be handled locally — should be forwarded
    forward_candidates = [
        ("eth_getProof", ["0x0000000000000000000000000000000000000000", [], "latest"]),
        ("eth_createAccessList", [{"to": "0x0000000000000000000000000000000000000000"}, "latest"]),
        ("debug_traceBlockByNumber", ["latest", {}]),
        ("trace_block", ["latest"]),
        ("arc_getCertificate", []),  # Arc-specific custom method
        ("arc_version", []),          # Arc-specific custom method
        ("arc_nodeInfo", []),          # Arc-specific custom method
    ]

    for method, params in forward_candidates:
        status, headers, resp = rpc(ep, method, params)
        err = resp.get("error", {})
        err_msg = json.dumps(resp).lower()

        # Look for internal info in error messages
        suspicious = any(word in err_msg for word in [
            "127.0.0.1", "localhost", "internal", "upstream",
            "forwarder", "10.", "192.168", "172.",
            "panic", "unwrap", "thread", ".rs:", "src/"
        ])

        if suspicious:
            flag(ep, "FORWARDER_INTERNAL_DISCLOSURE",
                 f"Method '{method}' triggered internal info in response: {json.dumps(resp)[:400]}")
        elif "result" in resp:
            log(f"      '{method}' returned result — method is active: {str(resp.get('result', ''))[:100]}")
        else:
            log(f"      '{method}' error code {err.get('code','?')}: {err.get('message','?')[:80]}")

        time.sleep(0.3)

# ── Test 4: Request smuggling via content-type confusion ─────────────────────
def test_content_type_confusion(ep):
    log(f"  [4] Content-type confusion tests...")

    valid_payload = json.dumps({
        "jsonrpc": "2.0", "method": "eth_blockNumber", "params": [], "id": 1
    })

    # Try different content types
    content_types = [
        "text/plain",
        "application/x-www-form-urlencoded",
        "application/xml",
        "text/html",
        "application/json; charset=utf-8",
        "",
    ]

    for ct in content_types:
        h = {"Content-Type": ct} if ct else {}
        try:
            r = requests.post(ep, headers=h, data=valid_payload, timeout=10)
            try:
                resp = r.json()
                if "result" in resp:
                    if ct not in ["application/json", "application/json; charset=utf-8"]:
                        flag(ep, "CONTENT_TYPE_CONFUSION",
                             f"Valid RPC response returned for Content-Type: '{ct}'. "
                             f"Server should reject non-JSON content types. "
                             f"Response: {json.dumps(resp)[:200]}")
                    else:
                        log(f"      Content-Type '{ct}' — handled correctly")
                elif "error" in resp:
                    log(f"      Content-Type '{ct}' — rejected with error (OK)")
            except Exception:
                log(f"      Content-Type '{ct}' — non-JSON response (OK)")
        except Exception as e:
            log(f"      Content-Type '{ct}' — connection error: {str(e)[:80]}")
        time.sleep(0.2)

# ── Test 5: Oversized request handling ───────────────────────────────────────
def test_oversized_requests(ep):
    log(f"  [5] Oversized request handling...")

    # Send progressively larger requests
    sizes = [10_000, 100_000, 500_000]

    for size in sizes:
        big_data = "A" * size
        payload = json.dumps({
            "jsonrpc": "2.0",
            "method": "eth_getBlockByHash",
            "params": [big_data, False],
            "id": 1
        })
        try:
            r = requests.post(ep,
                            headers={"Content-Type": "application/json"},
                            data=payload,
                            timeout=15)
            resp_text = r.text[:300]
            if r.status_code == 200:
                try:
                    resp = r.json()
                    err_msg = json.dumps(resp).lower()
                    suspicious = any(word in err_msg for word in [
                        "panic", "unwrap", "thread", ".rs:", "overflow", "stack"
                    ])
                    if suspicious:
                        flag(ep, "OVERSIZED_REQUEST_INTERNAL_ERROR",
                             f"Oversized request ({size} bytes) triggered internal error: {resp_text}")
                    else:
                        log(f"      {size} byte request — handled gracefully (status {r.status_code})")
                except Exception:
                    log(f"      {size} byte request — non-JSON response (status {r.status_code})")
            else:
                log(f"      {size} byte request — rejected with HTTP {r.status_code} (OK)")
        except requests.exceptions.Timeout:
            flag(ep, "OVERSIZED_REQUEST_TIMEOUT",
                 f"Request of {size} bytes caused timeout — potential DoS vector")
        except Exception as e:
            log(f"      {size} byte request — error: {str(e)[:100]}")
        time.sleep(0.5)

# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    log(f"{'='*60}")
    log(f"arc-forwarder-probe — Consensus/Forwarder Boundary Probe")
    log(f"Started: {datetime.datetime.now().isoformat()}")
    log(f"Endpoints: {len(ENDPOINTS)}")
    log(f"Log file: {log_file}")
    log(f"{'='*60}\n")

    for ep in ENDPOINTS:
        log(f"\n{'─'*60}")
        log(f"Probing: {ep}")
        log(f"{'─'*60}")

        test_response_headers(ep)
        time.sleep(0.5)

        test_header_injection(ep)
        time.sleep(0.5)

        test_forwarder_unknown_methods(ep)
        time.sleep(0.5)

        test_content_type_confusion(ep)
        time.sleep(0.5)

        test_oversized_requests(ep)
        time.sleep(1)

    log(f"\n{'='*60}")
    log(f"Probe complete. Results saved to: {log_file}")
    log(f"{'='*60}")

if __name__ == "__main__":
    main()
