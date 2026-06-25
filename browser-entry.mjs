// Browser bundle entry for the SAIHM /join card flow. Re-exports the
// non-custodial identity API from the published @saihm client library. The
// customer's secret key is generated and used ONLY in the browser; only the
// PUBLIC key is ever sent. Payment and token minting happen later in the
// pasted MCP client, not in the browser.
export { deriveIdentity, toHex, fromHex } from './dist/index.js';
