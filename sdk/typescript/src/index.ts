/**
 * synthex-x402 — the TypeScript client for Synthex Forge's paid x402 services.
 *
 * ONE CALL. That is the whole promise.
 *
 *     import { call, verify } from 'synthex-x402'
 *     const result = await call('/v1/preflight', { target: 'example.com' })
 *
 * `call()` takes a route and a body, handles the 402, signs an EIP-3009
 * `transferWithAuthorization` for the exact amount the server asked for,
 * retries the identical request with the signed payment in the header, and
 * returns the signed JSON the service produced.
 *
 * `verify()` re-checks the Ed25519 signature on a result LOCALLY, with no
 * network call, so a buyer can prove the answer was ours.
 *
 * MOCK MODE
 * ---------
 * `npm run mock` runs the ENTIRE flow — 402, payment-instruction parsing,
 * signing, retry, result — against a local mock x402 server, using a
 * throwaway key. It spends nothing, touches no network, and proves the
 * client code path works.
 *
 * SECURITY
 * --------
 *   * The private key is read from `SYNTHEX_X402_PRIVATE_KEY` or an explicit
 *     argument. It is NEVER logged, never returned, and never included in an
 *     error message.
 *   * The SDK never auto-pays when no signer is configured — it returns the
 *     `payment_required` payload so the caller can decide.
 */

import { createHash, verify as ed25519Verify, createPublicKey, randomBytes, generateKeyPairSync, sign as nodeSign } from 'node:crypto'
import { secp256k1 } from '@noble/curves/secp256k1'
import { keccak_256 } from '@noble/hashes/sha3'
import { existsSync, readFileSync } from 'node:fs'

export const VERSION = '1.0.0'

export const DEFAULT_BASE_URL = 'https://x402.synthexforge.com'
export const DEFAULT_TIMEOUT = 30

/** Base mainnet USDC (EIP-3009 `transferWithAuthorization`). */
export const USDC_BASE = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913'
export const USDC_DECIMALS = 6
export const CHAIN_ID = 8453
export const TOKEN_NAME = 'USD Coin'
export const TOKEN_VERSION = '2'

export const EIP712_DOMAIN = {
  name: TOKEN_NAME,
  version: TOKEN_VERSION,
  chainId: CHAIN_ID,
  verifyingContract: USDC_BASE,
} as const

export const EIP3009_TYPES = {
  TransferWithAuthorization: [
    { name: 'from', type: 'address' },
    { name: 'to', type: 'address' },
    { name: 'value', type: 'uint256' },
    { name: 'validAfter', type: 'uint256' },
    { name: 'validBefore', type: 'uint256' },
    { name: 'nonce', type: 'bytes32' },
  ],
} as const

export interface PaymentInstructions {
  amount?: string
  asset?: string
  network?: string
  payTo?: string
  scheme?: string
  maxAmountRequired?: string
  maxTimeoutSeconds?: number
  extra?: Record<string, unknown>
  raw?: unknown
}

export interface CallResult<T = unknown> {
  ok: boolean
  status: number
  body: T
  headers: Record<string, string>
  payment: PaymentPayload | null
  paymentRequired?: PaymentInstructions
  attempts: number
  error?: string
}

export interface PaymentPayload {
  x402Version: number
  payload: {
    authorization: {
      from: string
      to: string
      value: string
      valid_after: string
      valid_before: string
      nonce: string
    }
    signature: string
  }
  accepted: {
    scheme: string
    network: string
    maxAmountRequired: string
  }
}

export interface VerifyResult {
  valid: boolean
  signature_valid: boolean
  hash_valid: boolean
  recomputed_sha256?: string
  verifiedBy: string
  verifiedAt: number
  error?: string
  signature_error?: string
}

/* ------------------------------------------------------------------ */
/* Canonical JSON + digest — the SAME rules the server signs with      */
/* ------------------------------------------------------------------ */

/** Deterministic canonical serialization: sorted keys, no whitespace. */
export function canonicalJson(body: unknown): Buffer {
  return Buffer.from(
    JSON.stringify(sortKeys(body)),
    'utf-8',
  )
}

function sortKeys(value: any): any {
  if (Array.isArray(value)) return value.map(sortKeys)
  if (value && typeof value === 'object') {
    const out: Record<string, any> = {}
    for (const key of Object.keys(value).sort()) out[key] = sortKeys(value[key])
    return out
  }
  return value
}

export function sha256Hex(data: Buffer | string): string {
  return createHash('sha256').update(data).digest('hex')
}

/* ------------------------------------------------------------------ */
/* Ed25519 verification — LOCAL, no network                            */
/* ------------------------------------------------------------------ */

function hexToBytes(hex: string): Buffer {
  let h = hex.startsWith('0x') ? hex.slice(2) : hex
  if (h.length % 2 !== 0) h = '0' + h
  return Buffer.from(h, 'hex')
}

/**
 * Re-check the Ed25519 signature on a signed result, locally.
 *
 * When the result carries no public key the verification is REFUSED
 * (`valid: false` with a reason) rather than silently reported as valid.
 */
export function verify(result: any, publicKeyHex?: string): VerifyResult {
  const out: VerifyResult = {
    valid: false,
    signature_valid: false,
    hash_valid: false,
    verifiedBy: 'synthex-x402 local Ed25519 + SHA-256 verification',
    verifiedAt: Math.floor(Date.now() / 1000),
  }
  if (!result || typeof result !== 'object') {
    out.error = 'result must be an object'
    return out
  }
  let body = result.body ?? result.evidenceCore ?? result.evidence_core
  if (body === undefined) {
    const copy: Record<string, any> = { ...result }
    delete copy.signature
    delete copy.sha256
    delete copy.output_sha256
    delete copy.publicKeyHex
    body = copy
  }
  if (!body || typeof body !== 'object' || Object.keys(body).length === 0) {
    out.error = 'no signed body found in the result'
    return out
  }
  const signature = result.signature
  if (!signature) {
    out.error = 'no signature found in the result'
    return out
  }
  const declaredSha = result.sha256 ?? result.output_sha256
  if (!declaredSha) {
    out.error = 'no sha256 digest found in the result'
    return out
  }
  const pubHex = publicKeyHex ?? result.publicKeyHex
  if (!pubHex) {
    out.error = 'no public key available — cannot verify'
    return out
  }
  const canonical = canonicalJson(body)
  const recomputed = sha256Hex(canonical)
  out.recomputed_sha256 = recomputed
  out.hash_valid = recomputed === String(declaredSha)
  try {
    const key = createPublicKey({
      key: Buffer.concat([
        Buffer.from('302a300506032b6570032100', 'hex'),
        hexToBytes(pubHex),
      ]),
      format: 'der',
      type: 'spki',
    })
    out.signature_valid = ed25519Verify(
      null,
      canonical,
      key,
      hexToBytes(signature),
    )
  } catch (err: any) {
    out.signature_valid = false
    out.signature_error = `${err?.name ?? 'Error'}: ${err?.message ?? String(err)}`
  }
  out.valid = Boolean(out.hash_valid && out.signature_valid)
  return out
}

/* ------------------------------------------------------------------ */
/* Payment-instruction parsing                                         */
/* ------------------------------------------------------------------ */

/** Extract the payment instructions from a 402 response. */
export function parsePaymentRequired(
  headers: Record<string, string>,
  body?: unknown,
): PaymentInstructions {
  const out: PaymentInstructions = {}
  const lower: Record<string, string> = {}
  for (const [k, v] of Object.entries(headers ?? {})) lower[k.toLowerCase()] = v

  let decoded: any = undefined
  const raw = lower['payment-required']
  if (raw) {
    try {
      decoded = JSON.parse(Buffer.from(raw, 'base64').toString('utf-8'))
    } catch {
      try {
        decoded = JSON.parse(raw)
      } catch {
        decoded = undefined
      }
    }
  }
  if (decoded === undefined && body && typeof body === 'object') decoded = body
  if (!decoded || typeof decoded !== 'object') return out

  if (Array.isArray(decoded.accepts) && decoded.accepts.length > 0) {
    const acc = decoded.accepts[0] ?? {}
    out.amount = acc.maxAmountRequired ?? acc.amount
    out.asset = acc.asset
    out.network = acc.network
    out.payTo = acc.payTo
    out.scheme = acc.scheme ?? 'exact'
    out.maxAmountRequired = acc.maxAmountRequired ?? acc.amount
    out.maxTimeoutSeconds = acc.maxTimeoutSeconds
    out.extra = acc.extra ?? {}
  }
  if (decoded.price && typeof decoded.price === 'object' && !out.amount) {
    out.amount = decoded.price.amountAtomic ?? decoded.price.amount
    out.asset = out.asset ?? decoded.price.asset
    out.network = out.network ?? decoded.price.network
    out.payTo = out.payTo ?? decoded.price.payTo
    out.maxAmountRequired = out.maxAmountRequired ?? decoded.price.maxAmountRequired
  }
  out.raw = decoded
  return out
}

/* ------------------------------------------------------------------ */
/* EIP-712 / EIP-3009 signing                                           */
/* ------------------------------------------------------------------ */

function padAddress(addr: string): string {
  const a = addr.toLowerCase().replace(/^0x/, '')
  return a.padStart(64, '0')
}

function padUint(value: bigint | number | string): string {
  let v: bigint
  if (typeof value === 'bigint') v = value
  else if (typeof value === 'number') v = BigInt(Math.trunc(value))
  else v = BigInt(value)
  return v.toString(16).padStart(64, '0')
}

function padBytes32(hex: string): string {
  return hex.replace(/^0x/, '').padStart(64, '0')
}

function keccakHex(input: Buffer | string): string {
  const buf = typeof input === 'string' ? Buffer.from(input, 'utf-8') : input
  return Buffer.from(keccak_256(buf)).toString('hex')
}

/** keccak over BYTES that are given as a hex string. */
function keccakHexOfHex(hex: string): string {
  return Buffer.from(keccak_256(Buffer.from(hex, 'hex'))).toString('hex')
}

function typeHash(name: string, types: readonly { name: string; type: string }[]): string {
  const encoded = `${name}(${types.map((t) => `${t.type} ${t.name}`).join(',')})`
  return keccakHex(encoded)
}

function padString(value: string): string {
  // EIP-712 encodes a `string` field as keccak256 of its UTF-8 bytes
  // (the "hashed string" form). This is NOT the raw ABI dynamic-string
  // encoding — using that produces a different struct hash and every
  // signature is rejected by the facilitator.
  return keccakHex(Buffer.from(value, 'utf-8'))
}

function encodeData(types: readonly { name: string; type: string }[], data: Record<string, any>): string {
  let out = ''
  for (const t of types) {
    const v = data[t.name]
    if (t.type === 'address') out += padAddress(String(v))
    else if (t.type === 'uint256') out += padUint(v)
    else if (t.type === 'bytes32') out += padBytes32(String(v))
    else if (t.type === 'string') out += padString(String(v))
    else throw new Error(`unsupported EIP-712 type in the client: ${t.type}`)
  }
  return out
}

export function domainSeparatorHex(): string {
  return domainSeparator().toString('hex')
}

function domainSeparator(): Buffer {
  const domainTypes = [
    { name: 'name', type: 'string' },
    { name: 'version', type: 'string' },
    { name: 'chainId', type: 'uint256' },
    { name: 'verifyingContract', type: 'address' },
  ]
  const encoded = encodeData(domainTypes, {
    name: EIP712_DOMAIN.name,
    version: EIP712_DOMAIN.version,
    chainId: EIP712_DOMAIN.chainId,
    verifyingContract: EIP712_DOMAIN.verifyingContract,
  })
  return Buffer.from(keccakHexOfHex(typeHash('EIP712Domain', domainTypes) + encoded), 'hex')
}

function structHash(message: Record<string, any>): Buffer {
  const types = EIP3009_TYPES.TransferWithAuthorization
  const encoded = encodeData(types, message)
  // EIP-712 struct hash = keccak256(typeHash || encodeData).
  return Buffer.from(
    keccakHexOfHex(typeHash('TransferWithAuthorization', types) + encoded),
    'hex',
  )
}

/** The EIP-712 digest that must be signed for an EIP-3009 authorization. */
export function eip3009Digest(params: {
  from: string
  to: string
  value: bigint | number | string
  validAfter: number
  validBefore: number
  nonce: string
}): Buffer {
  const message = {
    from: params.from,
    to: params.to,
    value: params.value,
    validAfter: params.validAfter,
    validBefore: params.validBefore,
    nonce: params.nonce,
  }
  const domain = domainSeparator()
  const struct = structHash(message)
  return Buffer.from(keccakHex(Buffer.concat([Buffer.from('1901', 'hex'), domain, struct])), 'hex')
}

function randomNonce(): string {
  return '0x' + randomBytes(32).toString('hex')
}

/**
 * Sign an EIP-3009 `transferWithAuthorization`.
 *
 * The private key NEVER appears in the return value.
 */
export function signEip3009(
  privateKey: string,
  payTo: string,
  amountAtomic: bigint | number | string,
  validAfter?: number,
  validBefore?: number,
  nonce?: string,
): PaymentPayload {
  const now = Math.floor(Date.now() / 1000)
  const va = validAfter ?? now - 60
  const vb = validBefore ?? now + 3600
  const nn = nonce ?? randomNonce()

  const key = (privateKey.startsWith('0x') ? privateKey : '0x' + privateKey) as `0x${string}`
  const priv = secp256k1.utils.normPrivateKeyToScalar(hexToBytes(key))
  // Uncompressed public key: 0x04 || X(32) || Y(32). The address is the
  // last 20 bytes of keccak256(X || Y) — byte-identical to eth_account.
  const pub = secp256k1.getPublicKey(priv, false)
  const raw = pub.length === 65 ? pub.subarray(1) : pub
  const fromAddress = '0x' + Buffer.from(keccak_256(raw)).subarray(12).toString('hex')

  const digest = eip3009Digest({
    from: fromAddress,
    to: payTo,
    value: amountAtomic,
    validAfter: va,
    validBefore: vb,
    nonce: nn,
  })
  const sig = secp256k1.sign(digest, priv, { prehash: false })
  // EIP-3009 wants a 65-byte r||s||v signature. `sig.r`/`sig.s` are
  // bigints in noble-curves v1, so they are encoded as 32-byte big-endian.
  const rBytes = Buffer.from(sig.r.toString(16).padStart(64, '0'), 'hex')
  const sBytes = Buffer.from(sig.s.toString(16).padStart(64, '0'), 'hex')
  const sigBytes = Buffer.concat([
    rBytes,
    sBytes,
    Buffer.from([(sig.recovery ?? 0) & 0x01]),
  ])

  return {
    x402Version: 2,
    payload: {
      authorization: {
        from: fromAddress,
        to: payTo,
        value: String(amountAtomic),
        valid_after: String(va),
        valid_before: String(vb),
        nonce: nn,
      },
      signature: '0x' + sigBytes.toString('hex'),
    },
    accepted: {
      scheme: 'exact',
      network: `eip155:${CHAIN_ID}`,
      maxAmountRequired: String(amountAtomic),
    },
  }
}

/** Base64-encode the payment payload for the header. */
export function encodePaymentHeader(payload: PaymentPayload): string {
  return Buffer.from(JSON.stringify(payload), 'utf-8').toString('base64')
}

/* ------------------------------------------------------------------ */
/* The transport                                                       */
/* ------------------------------------------------------------------ */

export type RequestFn = (
  method: string,
  url: string,
  headers: Record<string, string>,
  body: unknown,
  timeout: number,
) => Promise<{ status: number; headers: Record<string, string>; body: unknown }>

async function defaultRequest(
  method: string,
  url: string,
  headers: Record<string, string>,
  body: unknown,
  timeout: number,
): Promise<{ status: number; headers: Record<string, string>; body: unknown }> {
  const ctrl = new AbortController()
  const timer = setTimeout(() => ctrl.abort(), timeout * 1000)
  try {
    const res = await fetch(url, {
      method,
      headers,
      body: body === undefined || body === null ? undefined : JSON.stringify(body),
      signal: ctrl.signal,
    })
    const text = await res.text()
    let parsed: unknown = text
    try {
      parsed = JSON.parse(text)
    } catch {
      /* keep the raw text */
    }
    const hdrs: Record<string, string> = {}
    res.headers.forEach((v, k) => {
      hdrs[k] = v
    })
    return { status: res.status, headers: hdrs, body: parsed }
  } finally {
    clearTimeout(timer)
  }
}

/** Find the private key. Never logs it. Returns null if absent. */
export function resolvePrivateKey(explicit?: string): string | null {
  if (explicit) return explicit
  const env = process.env.SYNTHEX_X402_PRIVATE_KEY
  if (env) return env
  const path = process.env.SYNTHEX_X402_KEY_FILE
  if (path) {
    try {
      if (existsSync(path)) return readFileSync(path, 'utf-8').trim()
    } catch {
      return null
    }
  }
  return null
}

/**
 * Call a Synthex paid route, handling the 402 -> sign -> retry loop.
 */
export async function call<T = unknown>(
  route: string,
  body?: unknown,
  opts: {
    method?: string
    baseUrl?: string
    source?: string
    privateKey?: string
    timeout?: number
    requestFn?: RequestFn
    autoPay?: boolean
  } = {},
): Promise<CallResult<T>> {
  const method = opts.method ?? 'POST'
  const baseUrl = (opts.baseUrl ?? DEFAULT_BASE_URL).replace(/\/+$/, '')
  const timeout = opts.timeout ?? DEFAULT_TIMEOUT
  const requestFn = opts.requestFn ?? defaultRequest
  let url = baseUrl + (route.startsWith('/') ? route : '/' + route)
  if (opts.source) url += `${url.includes('?') ? '&' : '?'}src=${encodeURIComponent(opts.source)}`

  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    Accept: 'application/json',
  }
  if (opts.source) headers['X-Source'] = opts.source

  let res = await requestFn(method, url, headers, body, timeout)
  let attempts = 1

  if (res.status !== 402) {
    return {
      ok: res.status >= 200 && res.status < 300,
      status: res.status,
      body: res.body as T,
      headers: res.headers,
      payment: null,
      attempts,
    }
  }

  const instructions = parsePaymentRequired(res.headers, res.body)
  const key = resolvePrivateKey(opts.privateKey)
  if (opts.autoPay === false || !key || !instructions.payTo || !instructions.amount) {
    return {
      ok: false,
      status: 402,
      body: res.body as T,
      headers: res.headers,
      payment: null,
      paymentRequired: instructions,
      attempts,
      error: 'payment_required',
    }
  }

  let amount: bigint
  try {
    amount = BigInt(instructions.amount)
  } catch {
    return {
      ok: false,
      status: 402,
      body: res.body as T,
      headers: res.headers,
      payment: null,
      paymentRequired: instructions,
      attempts,
      error: 'unparseable payment amount',
    }
  }

  const payload = signEip3009(key, instructions.payTo, amount)
  const encoded = encodePaymentHeader(payload)
  const retryHeaders = { ...headers, 'PAYMENT-SIGNATURE': encoded, 'X-PAYMENT': encoded }
  res = await requestFn(method, url, retryHeaders, body, timeout)
  attempts = 2

  return {
    ok: res.status >= 200 && res.status < 300,
    status: res.status,
    body: res.body as T,
    headers: res.headers,
    payment: payload,
    paymentRequired: instructions,
    attempts,
  }
}

/* ------------------------------------------------------------------ */
/* The mock server — proves the whole flow without spending anything   */
/* ------------------------------------------------------------------ */

export async function runMock(): Promise<{
  ok: boolean
  result: CallResult
  verification: VerifyResult
  calls: { method: string; url: string; hasPayment: boolean }[]
}> {
  // A throwaway Ed25519 key for the mock's "service" signature.
  const svc = generateKeyPairSync('ed25519')
  const svcPubRaw = svc.publicKey.export({ format: 'der', type: 'spki' }).subarray(-32)
  const svcPubHex = Buffer.from(svcPubRaw).toString('hex')

  // A throwaway EIP-3009 key for the "buyer".
  const buyerPriv = '0x' + randomBytes(32).toString('hex')

  const calls: { method: string; url: string; hasPayment: boolean }[] = []

  const mockRequest: RequestFn = async (
    method: string,
    url: string,
    h: Record<string, string>,
    body: unknown,
  ): Promise<{ status: number; headers: Record<string, string>; body: unknown }> => {
    const hasPayment = Boolean(h['PAYMENT-SIGNATURE'])
    calls.push({ method, url, hasPayment })
    if (!hasPayment) {
      const req = {
        x402Version: 2,
        accepts: [
          {
            scheme: 'exact',
            network: `eip155:${CHAIN_ID}`,
            maxAmountRequired: '10000',
            asset: USDC_BASE,
            payTo: '0xc8fF67FAE72596478599EAAcfad8656fAe1113c8',
            maxTimeoutSeconds: 60,
            extra: { name: TOKEN_NAME, version: TOKEN_VERSION, assetTransferMethod: 'eip3009' },
          },
        ],
      }
      return {
        status: 402,
        headers: { 'PAYMENT-REQUIRED': Buffer.from(JSON.stringify(req)).toString('base64') },
        body: { error: 'payment_required' },
      }
    }
    const signedBody = {
      kind: 'preflight/verdict',
      target: (body as any)?.target ?? 'unknown',
      verdict: 'go',
      observed_at: Math.floor(Date.now() / 1000),
    }
    const canonical = canonicalJson(signedBody)
    const sig = nodeSign(null, canonical, svc.privateKey)
    const payload = {
      ...signedBody,
      sha256: sha256Hex(canonical),
      signature: Buffer.from(sig).toString('hex'),
      publicKeyHex: svcPubHex,
    }
    return { status: 200, headers: { 'Content-Type': 'application/json' }, body: payload }
  }

  const result = await call('/v1/preflight', { target: 'example.com' }, {
    method: 'POST',
    baseUrl: 'http://mock.invalid',
    privateKey: buyerPriv,
    requestFn: mockRequest,
  })
  const verification = verify(result.body)
  const ok =
    result.status === 200 &&
    result.attempts === 2 &&
    calls.length === 2 &&
    calls[0]?.hasPayment === false &&
    calls[1]?.hasPayment === true &&
    verification.valid === true
  return { ok, result, verification, calls }
}
