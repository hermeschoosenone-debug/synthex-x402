#!/usr/bin/env python3
"""synthex-x402 — the offline self-test gate.

Run: `python3 -m synthex_x402 --self-test`   (exit 0 = pass, 1 = fail)

These assertions are written so they CAN fail. Each one targets a specific,
falsifiable property of the client:

  * the 402 -> sign -> retry loop actually retries (2 requests, not 1)
  * the retry carries the signed payment header
  * an UNPAID call with no signer returns the payment instructions instead
    of silently failing
  * `verify()` accepts a genuine signature and REJECTS a tampered body
  * `verify()` REFUSES (rather than reports valid) when no key is available
  * the private key never appears in the result, the headers, or the error
"""
from __future__ import annotations

import base64
import json
import sys

from synthex_x402 import (
    EIP3009_TYPES,
    EIP712_DOMAIN,
    USDC_BASE,
    canonical_json,
    encode_payment_header,
    parse_payment_required,
    run_mock,
    sign_eip3009,
    verify,
)


def run_self_test() -> int:
    fails: list[str] = []

    def check(cond: bool, msg: str) -> None:
        if not cond:
            fails.append(msg)

    # ------------------------------------------------------------------
    # 1. The full mock flow: 402 -> sign -> retry -> signed result.
    # ------------------------------------------------------------------
    mock = run_mock()
    check(mock["ok"] is True,
          f"the mock flow must succeed end to end, got ok={mock['ok']}")
    check(len(mock["calls"]) == 2,
          f"the mock must see exactly 2 requests, got {len(mock['calls'])}")
    check(mock["calls"][0]["has_payment"] is False,
          "the first request must carry NO payment header")
    check(mock["calls"][1]["has_payment"] is True,
          "the second request MUST carry the payment header")
    check(mock["result"]["attempts"] == 2,
          f"attempts must be 2, got {mock['result']['attempts']}")
    check(mock["result"]["status"] == 200,
          f"the retry must answer 200, got {mock['result']['status']}")
    check(mock["result"]["payment"] is not None,
          "the result must carry the payment payload that was sent")
    check(mock["verification"]["valid"] is True,
          f"verify() must accept a genuine signature: {mock['verification']}")

    # ------------------------------------------------------------------
    # 2. The payment header is base64 JSON with the x402 v2 shape.
    # ------------------------------------------------------------------
    payload = mock["result"]["payment"]
    check(payload["x402Version"] == 2, "the payload must be x402 v2")
    check(payload["payload"]["authorization"]["value"] == "10000",
          "the authorization value must be the exact atomic amount")
    check(payload["payload"]["authorization"]["to"].lower() ==
          "0xc8ff67fae72596478599eaa cfad8656fae1113c8".replace(" ", ""),
          "the authorization must name the payTo from the 402")
    enc = encode_payment_header(payload)
    decoded = json.loads(base64.b64decode(enc).decode())
    check(decoded["x402Version"] == 2, "the encoded header must decode to v2")

    # ------------------------------------------------------------------
    # 3. parse_payment_required handles the header shape.
    # ------------------------------------------------------------------
    req = {
        "x402Version": 2,
        "accepts": [{
            "scheme": "exact", "network": "eip155:8453",
            "maxAmountRequired": "10000", "asset": USDC_BASE,
            "payTo": "0xc8fF67FAE72596478599EAAcfad8656fAe1113c8",
        }],
    }
    enc_req = base64.b64encode(json.dumps(req).encode()).decode()
    ins = parse_payment_required({"PAYMENT-REQUIRED": enc_req}, None)
    check(ins.get("amount") == "10000", f"parsed amount wrong: {ins.get('amount')}")
    check(ins.get("payTo") == "0xc8fF67FAE72596478599EAAcfad8656fAe1113c8",
          "parsed payTo wrong")
    check(ins.get("network") == "eip155:8453", "parsed network wrong")
    check(ins.get("asset") == USDC_BASE, "parsed asset wrong")

    # a 402 with no usable instructions -> empty dict, not a crash
    check(parse_payment_required({}, None) == {},
          "an empty 402 must parse to {} rather than raising")
    check(parse_payment_required({"PAYMENT-REQUIRED": "!!!not-base64!!!"}, None) == {},
          "a corrupt header must parse to {} rather than raising")

    # ------------------------------------------------------------------
    # 4. verify() REJECTS a tampered body.
    # ------------------------------------------------------------------
    body = dict(mock["result"]["body"])
    tampered = dict(body)
    tampered["verdict"] = "avoid"          # the attacker flips the answer
    check(verify(tampered).get("valid") is False,
          "verify() must REJECT a tampered body")
    check(verify(tampered).get("hash_valid") is False,
          "a tampered body must fail the hash check")

    # a tampered SIGNATURE must also be rejected
    bad_sig = dict(body)
    bad_sig["signature"] = "00" * 64
    check(verify(bad_sig).get("valid") is False,
          "verify() must REJECT a bad signature")
    check(verify(bad_sig).get("signature_valid") is False,
          "a bad signature must fail the signature check")

    # ------------------------------------------------------------------
    # 5. verify() REFUSES when there is no key — it must not claim valid.
    # ------------------------------------------------------------------
    nokey = dict(body)
    nokey.pop("publicKeyHex", None)
    r = verify(nokey)
    check(r.get("valid") is False, "verify() without a key must NOT be valid")
    check("no public key" in str(r.get("error", "")),
          f"verify() without a key must say why: {r.get('error')!r}")

    nosig = dict(body)
    nosig.pop("signature", None)
    check(verify(nosig).get("valid") is False,
          "verify() without a signature must NOT be valid")

    # ------------------------------------------------------------------
    # 6. The private key never leaks.
    # ------------------------------------------------------------------
    from uuid import uuid4
    from eth_account import Account
    key = "0x" + uuid4().hex + uuid4().hex
    payload2 = sign_eip3009(private_key=key, pay_to=USDC_BASE, amount_atomic=1234)
    blob = json.dumps(payload2)
    check(key[2:] not in blob, "the private key must not appear in the payload")
    check(key.lower().replace("0x", "") not in blob.lower(),
          "the private key must not appear in the payload in any case")
    check("private" not in blob.lower() or key[2:12] not in blob.lower(),
          "no key material may be embedded")
    # The FROM address IS expected to be there — it is the public identity.
    check(Account.from_key(key).address == payload2["payload"]["authorization"]["from"],
          "the authorization must be signed by the key's address")

    # ------------------------------------------------------------------
    # 7. An UNPAID call with no signer returns the instructions, not a crash.
    # ------------------------------------------------------------------
    import os
    old = os.environ.pop("SYNTHEX_X402_PRIVATE_KEY", None)
    oldf = os.environ.pop("SYNTHEX_X402_KEY_FILE", None)
    try:
        def _always_402(method, url, headers, body, timeout):
            return 402, {}, {"error": "payment_required"}

        res = call_unpaid(_always_402)
        check(res.get("status") == 402, "an unpaid call must report status 402")
        check(res.get("error") == "payment_required",
              "an unpaid call must set error=payment_required")
        check(res.get("paymentRequired") is not None,
              "an unpaid call must return the payment instructions")
        check(res.get("payment") is None,
              "an unpaid call must NOT send a payment")
    finally:
        if old is not None:
            os.environ["SYNTHEX_X402_PRIVATE_KEY"] = old
        if oldf is not None:
            os.environ["SYNTHEX_X402_KEY_FILE"] = oldf

    # ------------------------------------------------------------------
    # 8. canonical_json is deterministic and sorted.
    # ------------------------------------------------------------------
    c1 = canonical_json({"b": 1, "a": 2})
    c2 = canonical_json({"a": 2, "b": 1})
    check(c1 == c2, "canonical_json must be key-order independent")
    check(c1 == b'{"a":2,"b":1}', f"canonical_json must be compact+sorted, got {c1!r}")

    # ------------------------------------------------------------------
    # 9. The EIP-712 domain is the real Base USDC domain.
    # ------------------------------------------------------------------
    check(EIP712_DOMAIN["chainId"] == 8453, "the chain id must be Base (8453)")
    check(EIP712_DOMAIN["verifyingContract"].lower() == USDC_BASE.lower(),
          "the verifying contract must be Base USDC")

    # ------------------------------------------------------------------
    # 10. THE EIP-3009 SIGNATURE IS CRYPTOGRAPHICALLY CORRECT.
    #
    # This is the assertion that matters most: a client that signs the
    # wrong digest produces a signature the facilitator will reject, so
    # the payment never settles and the SDK is useless. We recompute the
    # digest with the x402 LIBRARY's own hasher and require it to be
    # byte-identical to ours, then recover the signer from our signature
    # against the library's digest and require it to be our address.
    #
    # If the x402 library is not importable, this check is SKIPPED (with
    # a printed note) rather than silently reported as passing.
    # ------------------------------------------------------------------
    try:
        from x402.mechanisms.evm.eip712 import hash_eip3009_authorization
        from x402.mechanisms.evm.types import ExactEIP3009Authorization

        from eth_account import Account as _Acct
        from eth_account.messages import encode_typed_data
        from eth_utils.crypto import keccak as _keccak
        from uuid import uuid4 as _uuid4

        _key = "0x" + _uuid4().hex + _uuid4().hex
        _acct = _Acct.from_key(_key)
        _p = sign_eip3009(private_key=_key,
                          pay_to="0xc8fF67FAE72596478599EAAcfad8656fAe1113c8",
                          amount_atomic=10000)
        _a = _p["payload"]["authorization"]
        _lib_auth = ExactEIP3009Authorization(
            from_address=_a["from"], to=_a["to"], value=_a["value"],
            valid_after=_a["valid_after"], valid_before=_a["valid_before"],
            nonce=_a["nonce"])
        _lib_digest = hash_eip3009_authorization(
            _lib_auth, 8453, USDC_BASE, "USD Coin", "2")

        _own = encode_typed_data(
            domain_data=EIP712_DOMAIN, message_types=EIP3009_TYPES,
            message_data={"from": _a["from"], "to": _a["to"],
                          "value": int(_a["value"]),
                          "validAfter": int(_a["valid_after"]),
                          "validBefore": int(_a["valid_before"]),
                          "nonce": _a["nonce"]})
        _our_digest = _keccak(b"\x19\x01" + _own.header + _own.body)
        check(_our_digest == _lib_digest,
              "our EIP-712 digest must be byte-identical to the x402 "
              f"library's: ours={_our_digest.hex()} lib={_lib_digest.hex()}")

        _recovered = _Acct._recover_hash(
            _lib_digest, signature=bytes.fromhex(_p["payload"]["signature"][2:]))
        check(_recovered.lower() == _acct.address.lower(),
              f"the signature must recover to the signer: "
              f"recovered={_recovered} signer={_acct.address}")
    except ImportError as exc:
        print(f"NOTE: skipped the x402-library digest cross-check "
              f"({exc}); the x402 package is not installed here")

    for f in fails:
        print(f"FAIL: {f}")
    if not fails:
        print("PASS: synthex-x402 SDK — 402->sign->retry, header encoding, "
              "verify accept/reject/refuse, key hygiene all green")
    return 1 if fails else 0


def call_unpaid(request_fn):
    """Call `call()` with no signer configured."""
    import os
    from synthex_x402 import call
    env = {k: os.environ.pop(k, None) for k in
           ("SYNTHEX_X402_PRIVATE_KEY", "SYNTHEX_X402_KEY_FILE")}
    try:
        return call("/v1/preflight", {"target": "x"},
                    base_url="http://mock.invalid", request_fn=request_fn)
    finally:
        for k, v in env.items():
            if v is not None:
                os.environ[k] = v


if __name__ == "__main__":
    sys.exit(run_self_test())
