# Clocked documentation examples

Request bodies and recorded responses copied from Clocked's public docs (fictional content), captured Oct 21, 2026:

| Endpoint | Docs page | Request | Recorded response (Clocked's own recording, 2026-10-08) |
| --- | --- | --- | --- |
| `/injection` (Guard) | https://clocked.rezolve.ai/docs/injection | `injection.request.json` | `injection.response.recorded-2026-10-08.json` |
| `/pii` (Protect) | https://clocked.rezolve.ai/docs/pii | `pii.request.json` | `pii.response.recorded-2026-10-08.json` |
| `/script` (Inspect) | https://clocked.rezolve.ai/docs/script | `script.request.json` | `script.response.recorded-2026-10-08.json` |

These responses are Clocked's documentation recordings, not calls made by this project. Our own raw responses go to
`fixtures/recorded/` via `npm run record:clocked` once a Clocked API key exists.
