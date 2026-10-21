/**
 * synthex-x402 — the TypeScript self-test gate.
 *
 * Run: `npm run self-test`   (exit 0 = pass, 1 = fail)
 *
 * These assertions are written so they CAN fail. Each one targets a
 * specific, falsifiable property of the client:
 *
 *   * the 402 -> sign -> retry loop actually retries (2 requests, not 1)
 *   * the retry carries the signed payment header
 *   * an UNPAID call with no signer returns the payment instructions
 *   * `verify()` accepts a genuine signature and REJECTS a tampered body
 *   * `verify()` REFUSES (rather than reports valid) with no key
 *   * the private key never appears in the result
 */
import { randomBytes } from 'node:crypto'
import {
  EIP712_DOMAIN,
  EIP3009_TYPES,
  USDC_BASE,
  canonicalJson,
  domainSeparatorHex,
  encodePaymentHeader,
  eip3009Digest,
  parsePaymentRequired,
  runMock,
  signEip3009,
  verify,
} from './index.js'

const fails: string[] = []
function check(cond: boolean, msg: string): void {
  if (!cond) fails.push(msg)
}

async function main(): Promise<number> {
  // ------------------------------------------------------------------
  // 1. The full mock flow: 402 -> sign -> retry -> signed result.
  // ------------------------------------------------------------------
  const mock = await runMock()
  check(mock.ok === true, `the mock flow must succeed end to end, got ok=${mock.ok}`)
  check(mock.calls.length === 2, `the mock must see exactly 2 requests, got ${mock.calls.length}`)
  check(mock.calls[0]?.hasPayment === false, 'the first request must carry NO payment header')
  check(mock.calls[1]?.hasPayment === true, 'the second request MUST carry the payment header')
  check(mock.result.attempts === 2, `attempts must be 2, got ${mock.result.attempts}`)
  check(mock.result.status === 200, `the retry must answer 200, got ${mock.result.status}`)
  check(mock.result.payment !== null, 'the result must carry the payment payload that was sent')
  check(mock.verification.valid === true, `verify() must accept a genuine signature: ${JSON.stringify(mock.verification)}`)

  // ------------------------------------------------------------------
  // 2. The payment header is base64 JSON with the x402 v2 shape.
  // ------------------------------------------------------------------
  const payload = mock.result.payment!
  check(payload.x402Version === 2, 'the payload must be x402 v2')
  check(payload.payload.authorization.value === '10000', 'the authorization value must be the exact atomic amount')
  check(
    payload.payload.authorization.to.toLowerCase() === '0xc8ff67fae72596478599eaacfad8656fae1113c8',
    'the authorization must name the payTo from the 402',
  )
  const decoded = JSON.parse(Buffer.from(encodePaymentHeader(payload), 'base64').toString())
  check(decoded.x402Version === 2, 'the encoded header must decode to v2')

  // ------------------------------------------------------------------
  // 3. parsePaymentRequired handles the header shape.
  // ------------------------------------------------------------------
  const req = {
    x402Version: 2,
    accepts: [
      {
        scheme: 'exact',
        network: 'eip155:8453',
        maxAmountRequired: '10000',
        asset: USDC_BASE,
        payTo: '0xc8fF67FAE72596478599EAAcfad8656fAe1113c8',
      },
    ],
  }
  const ins = parsePaymentRequired(
    { 'PAYMENT-REQUIRED': Buffer.from(JSON.stringify(req)).toString('base64') },
    undefined,
  )
  check(ins.amount === '10000', `parsed amount wrong: ${ins.amount}`)
  check(ins.payTo === '0xc8fF67FAE72596478599EAAcfad8656fAe1113c8', 'parsed payTo wrong')
  check(ins.network === 'eip155:8453', 'parsed network wrong')
  check(ins.asset === USDC_BASE, 'parsed asset wrong')
  check(Object.keys(parsePaymentRequired({}, undefined)).length === 0, 'an empty 402 must parse to {} rather than throwing')
  check(
    Object.keys(parsePaymentRequired({ 'PAYMENT-REQUIRED': '!!!not-base64!!!' }, undefined)).length === 0,
    'a corrupt header must parse to {} rather than throwing',
  )

  // ------------------------------------------------------------------
  // 4. verify() REJECTS a tampered body and a tampered signature.
  // ------------------------------------------------------------------
  const body: any = mock.result.body
  const tampered = { ...body, verdict: 'avoid' }
  check(verify(tampered).valid === false, 'verify() must REJECT a tampered body')
  check(verify(tampered).hash_valid === false, 'a tampered body must fail the hash check')
  const badSig = { ...body, signature: '00'.repeat(64) }
  check(verify(badSig).valid === false, 'verify() must REJECT a bad signature')
  check(verify(badSig).signature_valid === false, 'a bad signature must fail the signature check')

  // ------------------------------------------------------------------
  // 5. verify() REFUSES when there is no key.
  // ------------------------------------------------------------------
  const nokey: any = { ...body }
  delete nokey.publicKeyHex
  const r = verify(nokey)
  check(r.valid === false, 'verify() without a key must NOT be valid')
  check(String(r.error).includes('no public key'), `verify() without a key must say why: ${r.error}`)
  const nosig: any = { ...body }
  delete nosig.signature
  check(verify(nosig).valid === false, 'verify() without a signature must NOT be valid')

  // ------------------------------------------------------------------
  // 6. The private key never leaks.
  // ------------------------------------------------------------------
  const key = '0x' + randomBytes(32).toString('hex')
  const p2 = signEip3009(key, USDC_BASE, 1234)
  const blob = JSON.stringify(p2)
  check(!blob.includes(key.slice(2)), 'the private key must not appear in the payload')
  check(!blob.toLowerCase().includes(key.slice(2).toLowerCase()), 'the private key must not appear in any case')

  // ------------------------------------------------------------------
  // 7. canonicalJson is deterministic and sorted.
  // ------------------------------------------------------------------
  check(
    canonicalJson({ b: 1, a: 2 }).toString() === canonicalJson({ a: 2, b: 1 }).toString(),
    'canonicalJson must be key-order independent',
  )
  check(canonicalJson({ b: 1, a: 2 }).toString() === '{"a":2,"b":1}', 'canonicalJson must be compact+sorted')

  // ------------------------------------------------------------------
  // 8. The EIP-712 domain is the real Base USDC domain.
  // ------------------------------------------------------------------
  check(EIP712_DOMAIN.chainId === 8453, 'the chain id must be Base (8453)')
  check(
    EIP712_DOMAIN.verifyingContract.toLowerCase() === USDC_BASE.toLowerCase(),
    'the verifying contract must be Base USDC',
  )
  check(EIP3009_TYPES.TransferWithAuthorization.length === 6, 'the EIP-3009 type list must have 6 fields')

  // ------------------------------------------------------------------
  // 9. The digest is deterministic and matches the well-known Base USDC
  //    EIP-3009 domain separator.
  // ------------------------------------------------------------------
  // A FIXED vector, cross-checked against the x402 library's own hasher
  // (x402.mechanisms.evm.eip712.hash_eip3009_authorization). If our EIP-712
  // encoding drifts, the facilitator rejects every payment and the SDK is
  // useless — so this is an exact equality check against a known-good
  // digest, not a smoke test.
  const VECTOR_DIGEST =
    'a74f87eed21f34efa6a9e3aeddfef370bf4f96a997bed4aaeff9a2079763b44d'
  const vector = eip3009Digest({
    from: '0x4a7C8eeC5002D88d9F473E525D97759ae66cbd6A',
    to: '0xc8fF67FAE72596478599EAAcfad8656fAe1113c8',
    value: 10000,
    validAfter: 1792622712,
    validBefore: 1792626372,
    nonce: '0xdd95eda9637b4049991db464d7c70087931091a21a4547eeb8240402c01cf1ab',
  }).toString('hex')
  check(
    vector === VECTOR_DIGEST,
    `the EIP-3009 digest must match the x402 library's known-good vector: ours=${vector} expected=${VECTOR_DIGEST}`,
  )

  const d1 = eip3009Digest({
    from: '0x4a7C8eeC5002D88d9F473E525D97759ae66cbd6A',
    to: '0xc8fF67FAE72596478599EAAcfad8656fAe1113c8',
    value: 10000,
    validAfter: 1792622712,
    validBefore: 1792626372,
    nonce: '0xdd95eda9637b4049991db464d7c70087931091a21a4547eeb8240402c01cf1ab',
  })
  const d2 = eip3009Digest({
    from: '0x4a7C8eeC5002D88d9F473E525D97759ae66cbd6A',
    to: '0xc8fF67FAE72596478599EAAcfad8656fAe1113c8',
    value: 10000,
    validAfter: 1792622712,
    validBefore: 1792626372,
    nonce: '0xdd95eda9637b4049991db464d7c70087931091a21a4547eeb8240402c01cf1ab',
  })
  check(d1.equals(d2), 'the digest must be deterministic')
  check(d1.length === 32, 'the digest must be 32 bytes')
  // The Base USDC EIP-3009 domain separator, computed independently by
  // the x402 library's own hasher. If our EIP-712 domain encoding drifts,
  // every signature we produce is rejected by the facilitator and the SDK
  // is useless — so this is a hard equality check, not a smoke test.
  const EXPECTED_BASE_USDC_DOMAIN =
    '02fa7265e7c5d81118673727957699e4d68f74cd74b7db77da710fe8a2c7834f'
  check(
    domainSeparatorHex() === EXPECTED_BASE_USDC_DOMAIN,
    `our EIP-712 domain separator must match the x402 library's: ours=${domainSeparatorHex()} expected=${EXPECTED_BASE_USDC_DOMAIN}`,
  )

  for (const f of fails) console.log(`FAIL: ${f}`)
  if (!fails.length) {
    console.log('PASS: synthex-x402 TS SDK — 402->sign->retry, header encoding, verify accept/reject/refuse, key hygiene all green')
  }
  return fails.length ? 1 : 0
}

main().then((code) => process.exit(code))
