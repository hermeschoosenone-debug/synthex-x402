# synthex-x402

**Client SDK for Synthex Forge's paid x402 services.** USDC on Base mainnet.

One call. The 402 → EIP-3009 signing → retry loop is handled for you, and
`verify()` re-checks the Ed25519 signature on the answer **locally**, with
no network call and no cost.

```python
from synthex_x402 import call, verify

result = call("/v1/preflight", {"target": "example.com"})
print(result["body"]["verdict"])        # 'go' | 'caution' | 'avoid' | 'unknown'
print(verify(result["body"])["valid"])   # True — re-checked locally
```

```ts
import { call, verify } from 'synthex-x402'

const result = await call('/v1/preflight', { target: 'example.com' })
console.log(result.body.verdict)         // 'go' | 'caution' | 'avoid' | 'unknown'
console.log(verify(result.body).valid)   // true — re-checked locally
```

## Install

```bash
pip install synthex-x402          # Python 3.9+
npm install synthex-x402          # Node 18+
```

## Try it without spending anything

```bash
python3 -m synthex_x402 --mock     # Python
cd sdk/typescript && npm install && npm run mock
```

The mock runs the entire flow — 402, instruction parsing, signing, retry,
signed result, local verification — against a local mock server with a
throwaway key. Nothing leaves your machine and nothing is charged.

## The remote MCP server

The same tools are available over the MCP streamable-HTTP transport:

```
POST https://x402.synthexforge.com/mcp
```

```bash
curl -X POST https://x402.synthexforge.com/mcp \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
```

- Manifest: `https://x402.synthexforge.com/.well-known/mcp.json`
- A2A agent card: `https://x402.synthexforge.com/.well-known/agent.json`
- Registry: `com.synthexforge.x402/paid-agent-services` on the official
  MCP Registry (`registry.modelcontextprotocol.io`)

## The services

Every tool is a thin adapter over the same paid HTTP route, so the MCP
surface and the HTTP surface can never disagree about price or behaviour.

| Tool | Route | Price | What it answers |
|---|---|---|---|
| `preflight` | `POST /v1/preflight` | $0.01 | Should I pay this counterparty? |
| `edge_prior` | `POST /v1/edge/prior` | $0.05 | What has already been tested here? |
| `x402_index` | `POST /v1/x402/index` | $0.02 | What does the agent economy offer, and does it work? |
| `data_validate` | `POST /v1/data/validate` | $0.02 | Is this payload valid against this schema? |
| `policy_check` | `POST /v1/policy/check` | $0.10 | Is this action allowed under this policy? |
| `rates_reference` | `GET /v1/rates/reference` | $0.01 | What is this amount worth, as-of stamped? |
| `verify_signature` | `POST /v1/settlement/verify` | **free** | Re-verify a signed receipt you hold. |
| `health` | `GET /health` | **free** | Is the service up, on which network? |

## Payment rail

| | |
|---|---|
| Protocol | x402 v2, `exact` scheme |
| Asset | USDC (`0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913`) |
| Network | Base mainnet (`eip155:8453`) |
| Method | EIP-3009 `transferWithAuthorization` |
| `payTo` | `0xc8fF67FAE72596478599EAAcfad8656fAe1113c8` |

## Configuration

| Variable | Meaning |
|---|---|
| `SYNTHEX_X402_PRIVATE_KEY` | Your EIP-3009 signing key. **Never logged, never returned.** |
| `SYNTHEX_X402_KEY_FILE` | Path to a file containing the key. |

With no key configured, `call()` does **not** pay — it returns the
`payment_required` instructions so you can decide.

## Documentation

Six how-to guides, served live at
`https://x402.synthexforge.com/docs`:

1. Verify a settlement receipt on Base
2. Check an endpoint before paying it
3. Validate a payload before trusting it
4. Read a reference rate with staleness
5. Buy and redeem a pass
6. Prove a verdict was ours

## Layout

```
sdk/python/          the Python package (PyPI: synthex-x402)
sdk/typescript/      the TypeScript package (npm: synthex-x402)
glama.json           Glama registry metadata
```

## Development

```bash
# Python
cd sdk/python && pip install -e . && python3 -m synthex_x402 --self-test

# TypeScript
cd sdk/typescript && npm install && npm run self-test
```

Both self-tests run offline and assert, among other things, that the
EIP-3009 digest is byte-identical to the x402 library's own.

## License

MIT
