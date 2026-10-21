# synthex-x402

**One call.** Pay for a signed, independently verifiable agent service.

```python
from synthex_x402 import call, verify

result = call("/v1/preflight", {"target": "example.com"})
print(result["body"]["verdict"])          # 'go' | 'caution' | 'avoid' | 'unknown'
print(verify(result["body"])["valid"])     # True — re-checked locally, no network
```

```ts
import { call, verify } from 'synthex-x402'

const result = await call('/v1/preflight', { target: 'example.com' })
console.log(result.body.verdict)           // 'go' | 'caution' | 'avoid' | 'unknown'
console.log(verify(result.body).valid)     // true — re-checked locally, no network
```

## What `call()` does

1. `POST` the route. The service answers `402 Payment Required` with an
   x402 v2 `PAYMENT-REQUIRED` header.
2. Parse the payment instructions: the exact atomic amount, the asset, the
   network, the `payTo` address, the scheme.
3. Sign an **EIP-3009 `transferWithAuthorization`** for that exact amount
   (EIP-712 typed data, secp256k1, Base USDC domain).
4. Retry the *identical* request with the base64 signature in the
   `PAYMENT-SIGNATURE` header.
5. Return the signed JSON.

You never construct a header, never encode typed data, and never handle a
402 by hand.

## What `verify()` does

Re-checks the **Ed25519** signature on a result you already hold, entirely
locally: it recomputes the canonical SHA-256 digest of the signed body and
verifies the signature against the published public key. No network call, no
cost, no trust in the service's own word.

It returns `{valid, signature_valid, hash_valid, recomputed_sha256}` and it
**refuses** (rather than reporting valid) when the public key is missing.

## Install

```bash
pip install synthex-x402          # Python 3.9+
npm install synthex-x402          # Node 18+
```

## Configuration

| Variable | Meaning |
|---|---|
| `SYNTHEX_X402_PRIVATE_KEY` | Your EIP-3009 signing key (hex, with or without `0x`). **Never logged, never returned.** |
| `SYNTHEX_X402_KEY_FILE` | Path to a file containing the key, instead of the env var. |

With no key configured, `call()` **does not pay**. It returns the
`payment_required` instructions so you can decide what to do:

```python
result = call("/v1/preflight", {"target": "example.com"})
if result.get("error") == "payment_required":
    print(result["paymentRequired"]["price"])   # amount, asset, network
```

## Try it without spending anything

```bash
python3 -m synthex_x402 --mock     # Python
npm run mock                       # TypeScript
```

The mock runs the entire flow — 402, instruction parsing, signing, retry,
signed result, local verification — against a local mock server with a
throwaway key. Nothing leaves your machine and nothing is charged.

## The services

Every tool below is a thin adapter over the same paid HTTP route, so the
MCP surface and the HTTP surface can never disagree about price or
behaviour.

| Tool | Route | Price | What it answers |
|---|---|---|---|
| `preflight` | `POST /v1/preflight` | $0.01 | Should I pay this counterparty? A dated, signed `go`/`caution`/`avoid`/`unknown`. |
| `edge_prior` | `POST /v1/edge/prior` | $0.05 | What has already been tested on this instrument / timeframe / strategy? |
| `x402_index` | `POST /v1/x402/index` | $0.02 | What does the agent economy offer, what does it cost, does it still work? |
| `data_validate` | `POST /v1/data/validate` | $0.02 | Is this payload valid against this schema? Mechanical repair, never fabricated data. |
| `policy_check` | `POST /v1/policy/check` | $0.10 | Is this action allowed under this policy, given this caller state? |
| `rates_reference` | `GET /v1/rates/reference` | $0.01 | What is this amount worth, as-of stamped, with honest staleness? |
| `verify_signature` | `POST /v1/settlement/verify` | **free** | Re-verify a signed receipt you already hold. |
| `health` | `GET /health` | **free** | Is the service up, and on which network? |

## Remote MCP

The same tools are exposed over the MCP streamable-HTTP transport:

```
POST https://x402.synthexforge.com/mcp
```

```bash
curl -X POST https://x402.synthexforge.com/mcp \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
```

The manifest is at `https://x402.synthexforge.com/.well-known/mcp.json`.

## Payment rail

| | |
|---|---|
| Protocol | x402 v2, `exact` scheme |
| Asset | USDC (`0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913`) |
| Network | Base mainnet (`eip155:8453`) |
| Method | EIP-3009 `transferWithAuthorization` |
| Decimals | 6 |
| `payTo` | `0xc8fF67FAE72596478599EAAcfad8656fAe1113c8` |

## Attribution

Pass a `source` tag so the service can tell which channel brought the
request:

```python
call("/v1/preflight", {"target": "example.com"}, source="smithery")
```

The tag travels as `?src=` and as the `X-Source` header.

## Self-test

```bash
python3 -m synthex_x402 --self-test
npm run self-test
```

Both run offline, spend nothing, and assert that the 402 → sign → retry
loop really retries, that the retry really carries the payment header, that
`verify()` accepts a genuine signature and **rejects** a tampered one, and
that the EIP-3009 digest is byte-identical to the x402 library's.

## License

MIT
