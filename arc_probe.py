import requests
import json
import time
import datetime
import os

# ── Arc testnet RPC endpoints (all 4 in scope) ──────────────────────────────
ENDPOINTS = [
    "https://rpc.testnet.arc.network",
    "https://rpc.drpc.testnet.arc.network",
    "https://rpc.quicknode.testnet.arc.network",
    "https://rpc.blockdaemon.testnet.arc.network",
]

HEADERS = {"Content-Type": "application/json"}

# ── Logging setup ────────────────────────────────────────────────────────────
os.makedirs("findings", exist_ok=True)
timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
log_file = f"findings/probe_{timestamp}.log"

def log(msg):
    line = f"[{datetime.datetime.now().strftime('%H:%M:%S')}] {msg}"
    print(line)
    with open(log_file, "a") as f:
        f.write(line + "\n")

def rpc(endpoint, method, params=[], id=1):
    payload = {"jsonrpc": "2.0", "method": method, "params": params, "id": id}
    try:
        r = requests.post(endpoint, headers=HEADERS, json=payload, timeout=10)
        return r.status_code, r.json()
    except Exception as e:
        return None, {"error": str(e)}

def flag(endpoint, test, detail):
    log(f"  ⚠️  FINDING [{test}] on {endpoint}")
    log(f"     {detail}")
    with open(log_file, "a") as f:
        f.write(f"\n{'='*60}\n")
        f.write(f"FINDING: {test}\n")
        f.write(f"ENDPOINT: {endpoint}\n")
        f.write(f"DETAIL: {detail}\n")
        f.write(f"{'='*60}\n\n")

# ── Test 1: Baseline — confirm endpoint is alive ─────────────────────────────
def test_baseline(ep):
    log(f"  [1] Baseline block number check...")
    status, resp = rpc(ep, "eth_blockNumber")
    if status is None:
        flag(ep, "ENDPOINT_UNREACHABLE", str(resp))
        return False
    if "result" in resp:
        block = int(resp["result"], 16)
        log(f"      OK — current block: {block}")
        return True
    flag(ep, "BASELINE_NO_RESULT", json.dumps(resp))
    return False

# ── Test 2: Pending tx filter bypass ─────────────────────────────────────────
def test_pending_tx_filter(ep):
    log(f"  [2] Pending tx filter bypass...")

    # Method A — should be blocked on public nodes
    status, resp = rpc(ep, "eth_newPendingTransactionFilter")
    if "result" in resp:
        flag(ep, "PENDING_TX_FILTER_BYPASS",
             f"eth_newPendingTransactionFilter returned a filter ID: {resp['result']} — "
             f"public nodes should block this per --arc.hide-pending-txs design")

    # Method B — should return null not real data
    status, resp = rpc(ep, "eth_getBlockByNumber", ["pending", True])
    if resp.get("result") is not None:
        txcount = len(resp["result"].get("transactions", []))
        if txcount > 0:
            flag(ep, "PENDING_BLOCK_DATA_LEAK",
                 f"eth_getBlockByNumber('pending') returned {txcount} real transactions. "
                 f"Public nodes should return null or empty pending block.")
        else:
            log(f"      eth_getBlockByNumber(pending) returned block with 0 txs — OK")
    else:
        log(f"      eth_getBlockByNumber(pending) returned null — OK")

    # Method C — subscribe attempt via POST (should error)
    status, resp = rpc(ep, "eth_subscribe", ["newPendingTransactions"])
    if "result" in resp:
        flag(ep, "PENDING_SUBSCRIBE_BYPASS",
             f"eth_subscribe newPendingTransactions returned result over HTTP: {resp['result']}")
    else:
        log(f"      eth_subscribe via HTTP correctly rejected — OK")

# ── Test 3: Malformed input handling ─────────────────────────────────────────
def test_malformed_inputs(ep):
    log(f"  [3] Malformed input handling...")

    cases = [
        ("empty params",        "eth_getBlockByNumber", []),
        ("null method",         None,                   []),
        ("invalid block hex",   "eth_getBlockByNumber", ["0xZZZZ", False]),
        ("huge block number",   "eth_getBlockByNumber", ["0x" + "f"*64, False]),
        ("wrong param type",    "eth_getBalance",       [12345, "latest"]),
        ("negative block",      "eth_getBlockByNumber", ["-0x1", False]),
        ("empty string method", "",                     []),
    ]

    for name, method, params in cases:
        payload = {"jsonrpc": "2.0", "method": method, "params": params, "id": 1}
        try:
            r = requests.post(ep, headers=HEADERS, json=payload, timeout=10)
            resp = r.json()
            # Check for stack traces or internal paths in error messages
            err_msg = json.dumps(resp).lower()
            suspicious = any(word in err_msg for word in [
                "stack", "traceback", "panic", "thread", "src/", ".rs:",
                "unwrap", "called `option", "index out of", "overflow"
            ])
            if suspicious:
                flag(ep, "INTERNAL_ERROR_DISCLOSURE",
                     f"Case '{name}' triggered internal detail in error: {json.dumps(resp)[:300]}")
            elif "error" not in resp and "result" not in resp:
                flag(ep, "MALFORMED_RESPONSE_STRUCTURE",
                     f"Case '{name}' returned response with neither result nor error: {json.dumps(resp)[:300]}")
            else:
                log(f"      '{name}' — handled correctly")
        except Exception as e:
            flag(ep, "MALFORMED_REQUEST_CRASH", f"Case '{name}' caused exception: {str(e)}")

# ── Test 4: Response consistency across endpoints ─────────────────────────────
def test_consistency(results):
    log(f"\n{'='*60}")
    log(f"[4] Cross-endpoint consistency check...")
    if len(results) < 2:
        log("     Not enough endpoints responded to compare.")
        return

    block_numbers = {ep: bn for ep, bn in results.items() if bn is not None}
    if len(block_numbers) < 2:
        return

    values = list(block_numbers.values())
    min_block = min(values)
    max_block = max(values)
    drift = max_block - min_block

    log(f"     Block numbers: {block_numbers}")
    log(f"     Max drift between endpoints: {drift} blocks")

    if drift > 10:
        flag("CROSS_ENDPOINT", "BLOCK_HEIGHT_INCONSISTENCY",
             f"Endpoints disagree on block height by {drift} blocks. "
             f"Min: {min_block}, Max: {max_block}. "
             f"Details: {block_numbers}. This may indicate a node is serving stale state.")

# ── Test 5: USDC gas edge cases ───────────────────────────────────────────────
def test_usdc_gas_edge_cases(ep):
    log(f"  [5] USDC-as-gas edge case probes...")

    # Check what the chain reports as gas price
    status, resp = rpc(ep, "eth_gasPrice")
    if "result" in resp:
        gas_price = int(resp["result"], 16)
        log(f"      Gas price: {gas_price} wei")
        if gas_price == 0:
            flag(ep, "ZERO_GAS_PRICE",
                 f"eth_gasPrice returned 0. On Arc, USDC is the gas token — "
                 f"a zero gas price may allow zero-cost transaction spam.")

    # Check fee history for anomalies
    status, resp = rpc(ep, "eth_feeHistory", [4, "latest", [25, 75]])
    if "result" in resp:
        base_fees = resp["result"].get("baseFeePerGas", [])
        if base_fees:
            zero_fees = [f for f in base_fees if int(f, 16) == 0]
            if zero_fees:
                flag(ep, "ZERO_BASE_FEE_IN_HISTORY",
                     f"eth_feeHistory contains {len(zero_fees)} blocks with zero base fee. "
                     f"Full baseFeePerGas: {base_fees}")
            else:
                log(f"      Fee history looks normal — {len(base_fees)} entries")

    # Check chain ID matches expected Arc testnet
    status, resp = rpc(ep, "eth_chainId")
    if "result" in resp:
        chain_id = int(resp["result"], 16)
        log(f"      Chain ID: {chain_id}")
        # Store for cross-check — all endpoints must agree
        return chain_id
    return None

# ── Main runner ───────────────────────────────────────────────────────────────
def main():
    log(f"{'='*60}")
    log(f"arc-probe — Arc Network Testnet Security Probe")
    log(f"Started: {datetime.datetime.now().isoformat()}")
    log(f"Endpoints: {len(ENDPOINTS)}")
    log(f"Log file: {log_file}")
    log(f"{'='*60}\n")

    block_results = {}
    chain_ids = {}

    for ep in ENDPOINTS:
        log(f"\n{'─'*60}")
        log(f"Probing: {ep}")
        log(f"{'─'*60}")

        alive = test_baseline(ep)
        if not alive:
            log(f"  Endpoint unreachable — skipping remaining tests")
            block_results[ep] = None
            continue

        # Store block number for consistency check
        _, resp = rpc(ep, "eth_blockNumber")
        if "result" in resp:
            block_results[ep] = int(resp["result"], 16)

        time.sleep(0.5)
        test_pending_tx_filter(ep)

        time.sleep(0.5)
        test_malformed_inputs(ep)

        time.sleep(0.5)
        chain_id = test_usdc_gas_edge_cases(ep)
        if chain_id:
            chain_ids[ep] = chain_id

        time.sleep(1)

    # Cross-endpoint checks
    test_consistency(block_results)

    # Chain ID consistency
    if len(set(chain_ids.values())) > 1:
        flag("CROSS_ENDPOINT", "CHAIN_ID_MISMATCH",
             f"Endpoints returned different chain IDs: {chain_ids}")
    else:
        log(f"     Chain IDs consistent across endpoints: {chain_ids}")

    log(f"\n{'='*60}")
    log(f"Probe complete. Results saved to: {log_file}")
    log(f"{'='*60}")

if __name__ == "__main__":
    main()
