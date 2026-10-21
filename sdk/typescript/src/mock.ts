/**
 * `npm run mock` — run the whole 402 -> sign -> retry flow locally.
 *
 * Spends nothing, touches no network, and prints the full result so the
 * flow is inspectable.
 */
import { runMock } from './index.js'

runMock()
  .then((out) => {
    console.log(JSON.stringify(out, null, 2))
    process.exit(out.ok ? 0 : 1)
  })
  .catch((err) => {
    console.error(err)
    process.exit(1)
  })
