import requests
import json
import time
import datetime
import os

ENDPOINTS = {
    "drpc":        "https://rpc.drpc.testnet.arc.network",
    "blockdaemon": "https://rpc.blockdaemon.testnet.arc.network",
    "quicknode":   "https://rpc.quicknode.testnet.arc.network",
    "testnet":     "https://rpc.testnet.arc.network",
}

USDC_CONTRACT = "0x3600000000000000000000000000000000000000"
HEADERS = {"Content-Type": "application/json"}

os.makedirs("findings", exist_ok=True)
timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
log_file = f"findings/mempool_{timestamp}.log"

def log(msg):
    line = f"[{datetime.datetime.now().strftime('%H:%M:%S')}] {msg}"
    print(line)
    with open(log_file, "a") as f:
        f.write(line + "\n")

def flag(test, detail):
    log(f"  FINDING [{test}]")
    log(f"     {detail}")
    with open(log_file, "a") as f:
        f.write(f"\n{'='*60}\n")
        f.write(f"FINDING: {test}\n")
        f.write(f"DETAIL: {detail}\n")
        f.write(f"{'='*60}\n\n")

def rpc(endpoint, method, params=[], id=1):
    payload = {"jsonrpc": "2.0", "method": method, "params": params, "id": id}
    try:
        r = requests.post(endpoint, headers=HEADERS, json=payload, timeout=15)
        return r.json()
    except Exception as e:
        return {"error": str(e)}

def decode_input(input_data):
    if not input_data or len(input_data) < 10:
        return None
    try:
        selector = input_data[:10]
        data = input_data[10:]
        if selector == "0xa9059cbb" and len(data) >= 128:
            to_addr = "0x" + data[24:64]
            amount = int(data[64:128], 16) / 1_000_000
            return {"type": "USDC Transfer", "to": to_addr, "amount_usdc": amount}
        elif selector == "0x23b872dd" and len(data) >= 192:
            from_addr = "0x" + data[24:64]
            to_addr = "0x" + data[88:128]
            amount = int(data[128:192], 16) / 1_000_000
            return {"type": "USDC TransferFrom", "from": from_addr, "to": to_addr, "amount_usdc": amount}
        elif selector == "0x095ea7b3" and len(data) >= 128:
            spender = "0x" + data[24:64]
            amount = int(data[64:128], 16) / 1_000_000
            return {"type": "USDC Approve", "spender": spender, "amount_usdc": amount}
        else:
            return {"type": "Unknown", "selector": selector}
    except Exception:
        return {"type": "DecodeError"}

def analyze_tx(tx):
    if not isinstance(tx, dict):
        return None
    try:
        result = {
            "hash": tx.get("hash", "?"),
            "from": tx.get("from", "?"),
            "to": tx.get("to", "?"),
            "value": int(tx.get("value", "0x0"), 16) / 1e18,
            "gas": int(tx.get("gas", "0x0"), 16),
            "input_length": len(tx.get("input", "0x")) // 2,
            "decoded": None,
            "is_usdc": False,
        }
        input_data = tx.get("input", "0x")
        if input_data and input_data != "0x":
            result["decoded"] = decode_input(input_data)
        if tx.get("to", "").lower() == USDC_CONTRACT.lower():
            result["is_usdc"] = True
        return result
    except Exception:
        return None

def analyze_mempool(name, endpoint):
    log(f"\n{'─'*60}")
    log(f"Analyzing: {name} ({endpoint})")
    log(f"{'─'*60}")

    resp = rpc(endpoint, "eth_getBlockByNumber", ["pending", True])
    if "error" in resp:
        log(f"  Error: {resp['error']}")
        return None

    result = resp.get("result")
    if not result:
        log(f"  No pending block returned")
        return None

    txs = result.get("transactions", [])
    log(f"  Total pending transactions: {len(txs)}")
    if not txs:
        return None

    usdc_txs = []
    native_transfers = []
    contract_calls = []
    high_value = []

    for tx in txs:
        a = analyze_tx(tx)
        if not a:
            continue
        if a["is_usdc"] and a["decoded"]:
            usdc_txs.append(a)
        elif a["value"] > 0:
            native_transfers.append(a)
        elif a["input_length"] > 2:
            contract_calls.append(a)
        if a["decoded"] and a["decoded"].get("amount_usdc", 0) > 100:
            high_value.append(a)

    log(f"  USDC contract calls:  {len(usdc_txs)}")
    log(f"  Native transfers:     {len(native_transfers)}")
    log(f"  Other contract calls: {len(contract_calls)}")
    log(f"  High value >$100:     {len(high_value)}")

    if usdc_txs:
        log(f"\n  USDC Transactions exposed:")
        total_usdc = 0
        for tx in usdc_txs[:10]:
            d = tx["decoded"]
            if d and d.get("type") == "USDC Transfer":
                amt = d.get("amount_usdc", 0)
                total_usdc += amt
                log(f"    FROM: {tx['from']}")
                log(f"    TO:   {d.get('to','?')}")
                log(f"    AMT:  ${amt:.2f} USDC")
                log(f"    TX:   {tx['hash'][:40]}...")
                log(f"    ---")

        total_usdc = sum(
            tx["decoded"].get("amount_usdc", 0)
            for tx in usdc_txs
            if tx["decoded"] and tx["decoded"].get("amount_usdc")
        )
        log(f"\n  Total USDC value visible in mempool: ${total_usdc:,.2f}")

        flag("MEMPOOL_FINANCIAL_DATA_EXPOSURE",
             f"Endpoint '{name}' exposes {len(usdc_txs)} pending USDC transactions "
             f"with full details: sender, recipient, amounts totaling ${total_usdc:,.2f} USDC. "
             f"Total pending txs: {len(txs)}. Enables front-running on USDC transfers.")

    if high_value:
        log(f"\n  HIGH VALUE transactions (>$100 USDC):")
        for tx in high_value:
            d = tx["decoded"]
            log(f"    ${d.get('amount_usdc',0):,.2f} USDC | from {tx['from'][:20]}...")

    if native_transfers:
        log(f"\n  Native transfers exposed:")
        for tx in native_transfers[:5]:
            log(f"    {tx['value']:.6f} native | from {tx['from'][:20]}...")

    return {
        "endpoint": name,
        "total_txs": len(txs),
        "usdc_txs": len(usdc_txs),
        "high_value": len(high_value),
    }

def main():
    log(f"{'='*60}")
    log(f"Arc Mempool Financial Data Exposure Analyzer")
    log(f"Started: {datetime.datetime.now().isoformat()}")
    log(f"Log file: {log_file}")
    log(f"USDC contract: {USDC_CONTRACT}")
    log(f"{'='*60}")

    results = []
    for name, endpoint in ENDPOINTS.items():
        result = analyze_mempool(name, endpoint)
        if result:
            results.append(result)
        time.sleep(2)

    log(f"\n{'='*60}")
    log(f"SUMMARY")
    log(f"{'='*60}")
    log(f"Total pending txs exposed:   {sum(r['total_txs'] for r in results)}")
    log(f"Total USDC txs exposed:      {sum(r['usdc_txs'] for r in results)}")
    log(f"Total high value exposed:    {sum(r['high_value'] for r in results)}")
    log(f"Probe complete: {log_file}")
    log(f"{'='*60}")

if __name__ == "__main__":
    main()
