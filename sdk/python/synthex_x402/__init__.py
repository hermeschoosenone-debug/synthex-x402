#!/usr/bin/env python3
"""synthex-x402 — the Python client for Synthex Forge's paid x402 services.

ONE CALL. That is the whole promise.

    from synthex_x402 import call
    result = call("/v1/preflight", {"target": "example.com"})

`call()` takes a route and a body, handles the 402, signs an EIP-3009
`transferWithAuthorization` for the exact amount the server asked for,
retries the identical request with the signed payment in the header, and
returns the signed JSON the service produced.

`verify()` re-checks the Ed25519 signature on a result LOCALLY, with no
network call, so a buyer can prove the answer was ours.

WHY THIS EXISTS
---------------
Agents integrate through SDKs, not by hand-rolling a 402 -> EIP-3009 -> retry
loop. Without a published SDK, every agent has to implement EIP-712 typed-data
signing themselves, and most of them simply do not. This is the adoption
rail.

MOCK MODE
---------
`--mock` runs the ENTIRE flow — 402, payment-instruction parsing, signing,
retry, result — against a local mock x402 server, using a throwaway key. It
spends nothing, touches no network, and proves the client code path works.

    python3 -m synthex_x402 --mock

SECURITY
--------
  * The private key is read from the environment (`SYNTHEX_X402_PRIVATE_KEY`)
    or from a key file. It is NEVER logged, never printed, never written to
    the result, and never included in an exception message.
  * The SDK never auto-pays. `call()` only signs when a payment is actually
    required AND a signer is configured. With no signer it returns the
    `payment_required` payload so the caller can decide.
"""
from __future__ import annotations

import base64
import json
import os
import sys
import time
import uuid
from typing import Any, Callable

__version__ = "1.0.0"

DEFAULT_BASE_URL = "https://x402.synthexforge.com"
DEFAULT_TIMEOUT = 30

# Base mainnet USDC (EIP-3009 `transferWithAuthorization`).
USDC_BASE = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
USDC_DECIMALS = 6
CHAIN_ID = 8453
TOKEN_NAME = "USD Coin"
TOKEN_VERSION = "2"

# EIP-712 domain for Base USDC.
EIP712_DOMAIN = {
    "name": TOKEN_NAME,
    "version": TOKEN_VERSION,
    "chainId": CHAIN_ID,
    "verifyingContract": USDC_BASE,
}

# EIP-712 message type for EIP-3009 TransferWithAuthorization.
EIP3009_TYPES = {
    "TransferWithAuthorization": [
        {"name": "from", "type": "address"},
        {"name": "to", "type": "address"},
        {"name": "value", "type": "uint256"},
        {"name": "validAfter", "type": "uint256"},
        {"name": "validBefore", "type": "uint256"},
        {"name": "nonce", "type": "bytes32"},
    ]
}


class PaymentRequired(Exception):
    """Raised (or returned) when a call needs payment and no signer exists."""

    def __init__(self, instructions: dict[str, Any]):
        self.instructions = instructions
        super().__init__(
            f"payment required: {instructions.get('price', {}).get('amountUsd')} "
            f"{instructions.get('price', {}).get('asset')} on "
            f"{instructions.get('network')}"
        )


class X402Error(Exception):
    """A non-2xx response that is not a 402."""


# --------------------------------------------------------------------------
# Canonical JSON + digest — the SAME rules the server signs with
# --------------------------------------------------------------------------
def canonical_json(body: Any) -> bytes:
    """Deterministic canonical serialization used for signing AND hashing.

    Must match the server byte for byte: `json.dumps(body, sort_keys=True,
    separators=(",", ":"))`.
    """
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    import hashlib
    return hashlib.sha256(data).hexdigest()


# --------------------------------------------------------------------------
# Ed25519 verification — LOCAL, no network
# --------------------------------------------------------------------------
def verify(result: Any, public_key_hex: str | None = None) -> dict[str, Any]:
    """Re-check the Ed25519 signature on a signed result, locally.

    `result` is the signed JSON the service returned. We look for the
    canonical triple the service publishes:
      `body`/`evidenceCore` — the object that was signed
      `sha256`/`output_sha256` — the declared digest
      `signature`          — the Ed25519 signature (hex)

    We recompute the digest from the body and verify the signature against
    the public key. The result is a dict:
      {valid, signature_valid, hash_valid, recomputed_sha256, ...}

    `public_key_hex` overrides the key embedded in the result. When neither
    is available the verification is REFUSED (`valid: false` with a reason)
    rather than silently reported as valid.
    """
    import hashlib
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    out: dict[str, Any] = {
        "valid": False,
        "signature_valid": False,
        "hash_valid": False,
        "verifiedBy": "synthex-x402 local Ed25519 + SHA-256 verification",
        "verifiedAt": int(time.time()),
    }

    if not isinstance(result, dict):
        out["error"] = "result must be a dict"
        return out

    body = result.get("body")
    if body is None:
        body = result.get("evidenceCore")
    if body is None:
        body = result.get("evidence_core")
    # Fall back: the whole result minus the signature fields IS the body.
    if body is None:
        body = {k: v for k, v in result.items()
                if k not in ("signature", "sha256", "output_sha256", "publicKeyHex")}
    if not isinstance(body, dict) or not body:
        out["error"] = "no signed body found in the result"
        return out

    signature = result.get("signature")
    if not signature:
        out["error"] = "no signature found in the result"
        return out

    declared_sha = result.get("sha256") or result.get("output_sha256")
    if not declared_sha:
        out["error"] = "no sha256 digest found in the result"
        return out

    pub_hex = public_key_hex or result.get("publicKeyHex")
    if not pub_hex:
        out["error"] = "no public key available — cannot verify"
        return out

    canonical = canonical_json(body)
    recomputed = hashlib.sha256(canonical).hexdigest()
    out["recomputed_sha256"] = recomputed
    out["hash_valid"] = (recomputed == str(declared_sha))

    try:
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(str(pub_hex)))
        pub.verify(bytes.fromhex(str(signature)), canonical)
        out["signature_valid"] = True
    except (InvalidSignature, ValueError, TypeError) as exc:
        out["signature_valid"] = False
        out["signature_error"] = f"{type(exc).__name__}: {exc}"

    out["valid"] = bool(out["hash_valid"] and out["signature_valid"])
    return out


# --------------------------------------------------------------------------
# Payment-instruction parsing
# --------------------------------------------------------------------------
def parse_payment_required(headers: dict[str, str], body: Any = None) -> dict[str, Any]:
    """Extract the payment instructions from a 402 response.

    Handles BOTH shapes:
      * the x402 `PAYMENT-REQUIRED` header (base64 JSON), and
      * a JSON body carrying `accepts` / `price` / `x-payment-info`.

    Returns a normalised dict:
      {amount, asset, network, payTo, scheme, maxAmountRequired, ...}
    or `{}` when nothing usable was found.
    """
    out: dict[str, Any] = {}
    hdrs = {str(k).lower(): v for k, v in (headers or {}).items()}

    raw = hdrs.get("payment-required")
    decoded: Any = None
    if raw:
        try:
            decoded = json.loads(base64.b64decode(raw).decode("utf-8"))
        except Exception:  # noqa: BLE001
            try:
                decoded = json.loads(raw)
            except Exception:  # noqa: BLE001
                decoded = None
    if decoded is None and isinstance(body, dict):
        decoded = body

    if not isinstance(decoded, dict):
        return out

    accepts = decoded.get("accepts")
    if isinstance(accepts, list) and accepts:
        acc = accepts[0] or {}
        out["amount"] = acc.get("maxAmountRequired") or acc.get("amount")
        out["asset"] = acc.get("asset")
        out["network"] = acc.get("network")
        out["payTo"] = acc.get("payTo")
        out["scheme"] = acc.get("scheme", "exact")
        out["maxAmountRequired"] = acc.get("maxAmountRequired") or acc.get("amount")
        out["maxTimeoutSeconds"] = acc.get("maxTimeoutSeconds")
        out["extra"] = acc.get("extra") or {}

    price = decoded.get("price")
    if isinstance(price, dict) and not out.get("amount"):
        out["amount"] = price.get("amountAtomic") or price.get("amount")
        out["asset"] = out.get("asset") or price.get("asset")
        out["network"] = out.get("network") or price.get("network")
        out["payTo"] = out.get("payTo") or price.get("payTo")
        out["maxAmountRequired"] = out.get("maxAmountRequired") or price.get("maxAmountRequired")

    if isinstance(decoded.get("error"), str):
        out["error"] = decoded["error"]
    out["raw"] = decoded
    return out


# --------------------------------------------------------------------------
# EIP-3009 signing
# --------------------------------------------------------------------------
def sign_eip3009(private_key: str, pay_to: str, amount_atomic: int,
                 valid_after: int | None = None,
                 valid_before: int | None = None,
                 nonce: str | None = None) -> dict[str, Any]:
    """Sign an EIP-3009 `transferWithAuthorization`.

    Returns the x402 v2 payment payload:
      {x402Version: 2, payload: {authorization: {...}, signature: "0x..."},
       accepted: {scheme, network, maxAmountRequired, ...}}

    The private key NEVER appears in the return value.
    """
    from eth_account import Account

    now = int(time.time())
    valid_after = int(valid_after if valid_after is not None else now - 60)
    valid_before = int(valid_before if valid_before is not None else now + 3600)
    nonce = nonce or ("0x" + uuid.uuid4().hex + uuid.uuid4().hex[:32])

    key = private_key if private_key.startswith("0x") else "0x" + private_key
    acct = Account.from_key(key)

    message = {
        "from": acct.address,
        "to": pay_to,
        "value": int(amount_atomic),
        "validAfter": valid_after,
        "validBefore": valid_before,
        "nonce": nonce,
    }
    signed = Account.sign_typed_data(
        key,
        domain_data=EIP712_DOMAIN,
        message_types=EIP3009_TYPES,
        message_data=message,
    )
    signature = getattr(signed, "signature", None)
    if signature is None:
        signature = signed["signature"]
    sig_hex = signature.hex() if isinstance(signature, (bytes, bytearray)) else str(signature)
    if not sig_hex.startswith("0x"):
        sig_hex = "0x" + sig_hex

    return {
        "x402Version": 2,
        "payload": {
            "authorization": {
                "from": acct.address,
                "to": pay_to,
                "value": str(int(amount_atomic)),
                "valid_after": str(valid_after),
                "valid_before": str(valid_before),
                "nonce": nonce,
            },
            "signature": sig_hex,
        },
        "accepted": {
            "scheme": "exact",
            "network": f"eip155:{CHAIN_ID}",
            "maxAmountRequired": str(int(amount_atomic)),
        },
    }


def encode_payment_header(payload: dict[str, Any]) -> str:
    """Base64-encode the payment payload for the header.

    The server reads `PAYMENT-SIGNATURE` (x402 v2) and falls back to
    `X-PAYMENT` (v1). We send BOTH so the client works against either
    generation of the server.
    """
    raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    return base64.b64encode(raw).decode("ascii")


# --------------------------------------------------------------------------
# The signer
# --------------------------------------------------------------------------
def resolve_private_key(explicit: str | None = None) -> str | None:
    """Find the private key. Never logs it. Returns None if absent."""
    if explicit:
        return explicit
    env = os.environ.get("SYNTHEX_X402_PRIVATE_KEY")
    if env:
        return env
    path = os.environ.get("SYNTHEX_X402_KEY_FILE")
    if path and os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                return f.read().strip()
        except Exception:  # noqa: BLE001
            return None
    return None


# --------------------------------------------------------------------------
# The HTTP transport
# --------------------------------------------------------------------------
def _default_request(method: str, url: str, headers: dict[str, str],
                     body: Any, timeout: int) -> tuple[int, dict[str, str], Any]:
    import httpx
    r = httpx.request(method, url, headers=headers,
                      json=body if body is not None else None, timeout=timeout)
    parsed: Any = None
    try:
        parsed = r.json()
    except Exception:  # noqa: BLE001
        parsed = r.text
    return r.status_code, dict(r.headers), parsed


def call(route: str, body: Any = None, *, method: str = "POST",
         base_url: str = DEFAULT_BASE_URL, source: str | None = None,
         private_key: str | None = None, timeout: int = DEFAULT_TIMEOUT,
         request_fn: Callable[..., tuple[int, dict[str, str], Any]] | None = None,
         auto_pay: bool = True) -> dict[str, Any]:
    """Call a Synthex paid route, handling the 402 -> sign -> retry loop.

    Args:
      route            e.g. "/v1/preflight" (a leading slash is added if absent)
      body             the JSON body to send (None for GET)
      method           HTTP method, default POST
      base_url         the service base, default https://x402.synthexforge.com
      source          an attribution tag, sent as `?src=` and `X-Source`
      private_key     the EIP-3009 signing key. If None, read from the env.
      auto_pay        when False, a 402 is RETURNED instead of being paid.
                      Defaults to True, but it is a no-op with no signer.

    Returns a dict:
      {ok, status, body, headers, payment (the payload that was sent),
       attempts}
    """
    if not route.startswith("/"):
        route = "/" + route
    url = base_url.rstrip("/") + route
    if source:
        sep = "&" if "?" in url else "?"
        url = f"{url}{sep}src={source}"

    request_fn = request_fn or _default_request
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    if source:
        headers["X-Source"] = source

    status, resp_headers, resp_body = request_fn(method, url, headers, body, timeout)
    attempts = 1

    if status != 402:
        return {
            "ok": 200 <= status < 300,
            "status": status,
            "body": resp_body,
            "headers": resp_headers,
            "payment": None,
            "attempts": attempts,
        }

    instructions = parse_payment_required(resp_headers, resp_body)
    key = resolve_private_key(private_key)
    if not auto_pay or not key or not instructions.get("payTo") or not instructions.get("amount"):
        return {
            "ok": False,
            "status": 402,
            "body": resp_body,
            "headers": resp_headers,
            "payment": None,
            "paymentRequired": instructions,
            "attempts": attempts,
            "error": "payment_required",
        }

    try:
        amount = int(instructions["amount"])
    except (TypeError, ValueError):
        return {
            "ok": False, "status": 402, "body": resp_body, "headers": resp_headers,
            "payment": None, "paymentRequired": instructions, "attempts": attempts,
            "error": "unparseable payment amount",
        }

    payload = sign_eip3009(
        private_key=key,
        pay_to=instructions["payTo"],
        amount_atomic=amount,
    )
    encoded = encode_payment_header(payload)
    retry_headers = dict(headers)
    retry_headers["PAYMENT-SIGNATURE"] = encoded
    retry_headers["X-PAYMENT"] = encoded

    status2, resp_headers2, resp_body2 = request_fn(method, url, retry_headers, body, timeout)
    attempts = 2
    return {
        "ok": 200 <= status2 < 300,
        "status": status2,
        "body": resp_body2,
        "headers": resp_headers2,
        "payment": payload,
        "paymentRequired": instructions,
        "attempts": attempts,
    }


# --------------------------------------------------------------------------
# The mock server — proves the whole flow without spending anything
# --------------------------------------------------------------------------
def run_mock() -> dict[str, Any]:
    """Run the full 402 -> sign -> retry flow against a local mock.

    The mock issues a real `PAYMENT-REQUIRED` header and a real 402, the
    client signs with a THROWAWAY key, retries, and the mock returns a
    signed body. Nothing leaves the machine.
    """
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    # A throwaway Ed25519 key for the mock's "service" signature.
    svc_priv = Ed25519PrivateKey.generate()
    svc_pub = svc_priv.public_key().public_bytes_raw().hex()

    # A throwaway EIP-3009 key for the "buyer".
    from eth_account import Account
    buyer_key = "0x" + uuid.uuid4().hex + uuid.uuid4().hex
    buyer = Account.from_key(buyer_key).address

    calls: list[dict[str, Any]] = []

    def mock_request(method: str, url: str, headers: dict[str, str],
                     body: Any, timeout: int) -> tuple[int, dict[str, str], Any]:
        calls.append({"method": method, "url": url,
                      "has_payment": bool(headers.get("PAYMENT-SIGNATURE"))})
        if not headers.get("PAYMENT-SIGNATURE"):
            req = {
                "x402Version": 2,
                "accepts": [{
                    "scheme": "exact",
                    "network": f"eip155:{CHAIN_ID}",
                    "maxAmountRequired": "10000",
                    "asset": USDC_BASE,
                    "payTo": "0xc8fF67FAE72596478599EAAcfad8656fAe1113c8",
                    "maxTimeoutSeconds": 60,
                    "extra": {"name": TOKEN_NAME, "version": TOKEN_VERSION,
                              "assetTransferMethod": "eip3009"},
                }],
            }
            enc = base64.b64encode(json.dumps(req).encode()).decode()
            return 402, {"PAYMENT-REQUIRED": enc}, {"error": "payment_required"}
        # The paid path: return a signed body.
        signed_body = {
            "kind": "preflight/verdict",
            "target": (body or {}).get("target", "unknown"),
            "verdict": "go",
            "observed_at": int(time.time()),
        }
        canonical = canonical_json(signed_body)
        sig = svc_priv.sign(canonical).hex()
        payload = {
            **signed_body,
            "sha256": sha256_hex(canonical),
            "signature": sig,
            "publicKeyHex": svc_pub,
        }
        return 200, {"Content-Type": "application/json"}, payload

    result = call("/v1/preflight", {"target": "example.com"},
                  method="POST", base_url="http://mock.invalid",
                  private_key=buyer_key, request_fn=mock_request)

    verification = verify(result.get("body") or {})

    ok = (
        result.get("status") == 200
        and result.get("attempts") == 2
        and len(calls) == 2
        and calls[0]["has_payment"] is False
        and calls[1]["has_payment"] is True
        and verification.get("valid") is True
    )
    return {
        "ok": ok,
        "result": result,
        "verification": verification,
        "calls": calls,
        "buyer": buyer,
    }


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
def _main(argv: list[str]) -> int:
    if "--mock" in argv:
        out = run_mock()
        print(json.dumps(out, indent=2, default=str))
        return 0 if out["ok"] else 1
    if "--self-test" in argv:
        from synthex_x402_selftest import run_self_test
        return run_self_test()
    print(__doc__)
    print("\nusage:\n"
          "  python3 -m synthex_x402 --mock       run the whole flow locally, spend nothing\n"
          "  python3 -m synthex_x402 --self-test   run the offline assertions\n")
    return 0


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
