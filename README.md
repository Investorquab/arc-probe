# arc-probe

A security research tool for probing the Arc Network testnet RPC endpoints.
Built as part of the Circle Bug Bounty Program on HackerOne.

## What it tests
- RPC endpoint behavior with malformed inputs
- Pending transaction filter bypass paths
- USDC-as-gas edge cases
- Response consistency across all 4 testnet endpoints
- Unexpected error message / information disclosure

## Usage
```bash
python3 arc_probe.py
```

## Disclaimer
This tool is used strictly on Arc testnet for responsible security research
under the Circle Bug Bounty Program terms and conditions.
