# Security model

## What is protected

- Password processing and entry encryption happen in the browser. PBKDF2-SHA256 uses 600,000 iterations, a per-user random 16-byte salt and a 64-byte output; independent halves become the login credential and AES-256 key.
- Worker receives `auth_key` over TLS, never the password or encryption key. D1 stores SHA-256(auth_key), not the reusable auth_key. Database theft still permits **offline password guessing**, mitigated by password quality and PBKDF2. Encryption is not a substitute for a strong password.
- Every entry is AES-256-GCM with a fresh 12-byte random IV and 16-byte tag. Additional authenticated data binds the ciphertext to its entry ID. Labels, issuers, secrets and TOTP settings are encrypted together.
- Encrypted key-check data validates a password even when the vault is empty. Wrong-password unlock cannot silently show an empty vault or create data under the wrong key.
- The authentication credential and encryption key are different. Knowing a signed session or Worker SERVER_SECRET does not directly reveal an AES key.
- SQL uses bound parameters. Entry queries always constrain `user_id`. Foreign-key cascade removes a deleted member's entries and sessions. The single-admin partial unique index and atomic conditional INSERT prevent two simultaneous administrator setups.
- Setup requires a separate random SETUP_TOKEN. Delete that secret after initialization. An empty public deployment is not an invitation to race to create its administrator.
- HttpOnly, Secure, SameSite=Strict, host-only `__Host-` cookies. Cookie sessions have signed purpose/expiry and a database record, making logout immediately effective. Session cookies expire server-side within 24 hours; remembered cookies within 30 days.
- Bearer tokens have a signed **agent** purpose. Putting one into a Cookie cannot turn it into a browser session. Agent tokens cannot delete entries, manage users, create tokens, or invoke browser-only endpoints. Read-only tokens cannot add. No update/upsert endpoint exists for entries.
- Tokens can be revoked and expire within 1–30 days. Deleted users lose all access. Agent self-revocation removes the current session only, not vault data.
- POST requests require JSON. Browser API requests require same-origin context; foreign Origin and cross-site Fetch Metadata are rejected, including bodyless DELETE requests. No CORS. Request bodies are bounded while streaming, not only by Content-Length.
- CSP allows only SHA-256 hashes of the shipped inline scripts; no inline event handlers, eval or third-party scripts. Frame embedding, external connections, referrers and sensitive browser sensors are disabled. API and HTML responses use no-store.
- Untrusted text is rendered with textContent. The only innerHTML template is a fixed literal without user data. No third-party icon requests reveal issuer names.
- D1 atomic rate reservations limit login and setup attempts. IP addresses are keyed with a server HMAC rather than stored in plaintext. Challenge requests also have an independent bound. Cron removes expired sessions and stale buckets.

## Explicit limits

1. **No guarantee of zero vulnerabilities.** This is a test release reviewed locally, not a professional independent cryptographic audit. Test findings and boundaries are recorded in AUDIT.md.
2. **A compromised Cloudflare account or GitHub deployment pipeline can replace browser JavaScript.** The replacement could steal a password/key when a user next unlocks. “D1 stores ciphertext” protects a passive database copy; it does not protect against a malicious application delivery channel. Protect account and repository access; review deployments and dependencies.
3. **An Agent grant deliberately exports the encryption key.** Outside that explicit action, the browser keeps it in memory. A grant lets its holder read all records belonging to that user. Use a dedicated sub-user and narrowly scoped, short-lived tokens. Never give an Agent the master password or browser Cookie.
4. **Revocation does not erase exported material.** Revocation blocks future API calls. Previously downloaded ciphertext plus an exported key remain decryptable. Already exposed TOTP secrets must be rotated at their original services if needed. Clipboard contents cannot reliably be cleared remotely and follow the device's clipboard history rules.
5. **No password recovery or change flow in this version.** Losing the password loses the data. Admins create users with passwords they initially know; this is not protection against the creator retaining a known initial password. Administrators also control account deletion and the database operator controls availability.
6. **Runtime memory is not guaranteed erasure.** Lock/refresh/pagehide remove key references, forms, export text and rendered secrets, with generation guards against stale async rendering. JavaScript garbage collection and OS memory cannot provide a cryptographic secure-erase guarantee. BFCache return requires unlock. An extension, malware, devtools, screen capture or compromised device can still read unlocked data.
7. **No encryption of metadata.** D1 can see usernames, user IDs, roles, timestamps, entry counts, ciphertext lengths, session metadata and rate buckets. It cannot directly see entry labels, issuers, secrets or codes. “Only ciphertext” refers to entry payloads, not every database column.
8. **The hidden-looking login is cosmetic.** Open-source code and the network reveal its purpose. Generic responses and fake salts reduce obvious enumeration; they do not prove constant network timing or username anonymity.
9. **Rate limits are per IP.** Distributed attacks and shared NAT denial of service remain possible. Correct and incorrect login attempts are reserved atomically; successful login clears its own bucket. A five-minute challenge limit also applies. It is not a full anti-abuse service or a guarantee of free-tier availability.
10. **No rollback resistance or availability guarantee.** A database operator can delete or roll back ciphertext. GCM detects altered ciphertext but not restoration of an old valid snapshot. Keep database backups separate and protect them. The app does not authenticate DB write history.
11. **Password strength display is illustrative.** `length × log2(character-set size)` at 1e10 guesses/second models a uniform character search only. It does not represent measured PBKDF2 speed or model dictionary guesses. The old document's example times were inconsistent with its own formula; they are not copied as facts. Repetition/common phrases can be weak despite a high displayed estimate.
12. **HTTPS and an accurate device clock are required.** No offline PWA, service worker, camera scanner or server-generated codes. Trusted Cloudflare proxy behavior is assumed for CF-Connecting-IP; direct production access should be through the Worker runtime, not the local preview server.

## Dependency / release discipline

Production application code imports no npm packages. Wrangler and Playwright are development tools pinned via package-lock.json. Official CI actions are pinned to commit SHAs. Re-run npm audit after upgrades; a zero advisory count is not proof of correctness. Workflow deployment is opt-in and does not run on pull requests. Untrusted branches must not bind production D1 or receive deployment credentials.

Do not publish `.dev.vars`, `.env*`, `.git`, local state, grants, screenshots of real vaults, or tooling caches. The packaging script uses an explicit allowlist, scans for private paths / real credentials, and generates file hashes. Review the ZIP contents before publishing an edited fork.

## Reporting an issue

Do not open a public issue containing passwords, API grants or TOTP secrets. In your own GitHub fork, enable private vulnerability reporting and fill in your preferred security contact. This template intentionally contains no personal contact details.
