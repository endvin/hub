# Official model services

ClawMuse account sessions authorize official services independently of cloud-space access. Upstream keys stay in the Hub environment. A host receives an encrypted, short-lived speech credential; it cannot recover the account session or upstream key. Each connection rechecks the account session, and active realtime connections recheck every 30 seconds.

Configure `CLAWMUSE_STEP_API_KEY` on the server. `CLAWMUSE_REALTIME_URL`, `CLAWMUSE_REALTIME_MODEL`, `CLAWMUSE_AUDIO_BASE_URL`, `CLAWMUSE_ASR_MODEL` and `CLAWMUSE_TTS_MODEL` select operator-owned upstream routes. Requests cannot choose an upstream or override the configured model. Never add keys to images or client configuration.

`/api/auth/clawmuse/official` returns the signed-in account's trial usage. POST `/session` issues a speech credential. Use that credential for the `/realtime` WebSocket and POST `/audio/asr/sse` or `/audio/speech`. The browser origin allowlist admits only account summary and session issuance; audio is sent by the user's host.

`CLAWMUSE_VOICE_FREE_SECONDS` sets a one-time account allowance, default 1800 seconds. It measures realtime connection duration across all connections, including task-check and narration connections. It is not supplier audio duration or a money budget. HTTP speech requests are recorded separately. Trial overage remains promotional, with zero amount due and no payment surface. Do not convert past trial records into debt when adding billing.

The usage table has a cascading user foreign key. Failed or interrupted requests need reconciliation; an active row left by a process crash must not be treated as a completed zero-cost request. Concurrency and per-minute request limits remain in force during the trial. Do not expose full audio, transcripts, task context, account tokens, or provider errors in usage history or logs.

Deploy the Hub and its migration before the client. New clients gate official speech once on the daemon's `officialVoice` capability. Custom speech credentials continue to belong to the user's host.
