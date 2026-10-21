# Recorded Clocked responses (ours)

**Status: BLOCKED, empty.** No Clocked account or API key exists yet, so no live calls have been made.

Once `CLOCKED_API_KEY` is set (in `.env` or the shell, never committed):

```sh
node --env-file=.env scripts/record-clocked.mjs --yes
```

This sends the three docs example requests in `fixtures/docs/` to `/injection`, `/pii` and `/script` with the pinned
`clocked-sdk` and saves each raw response with its timing metadata here. Then read the actual credits per call off the
Clocked usage page and record them below.

| Endpoint | Recorded file | Model ms | Credits (from usage page) |
| --- | --- | --- | --- |
| `/injection` | | | |
| `/pii` | | | |
| `/script` | | | |
