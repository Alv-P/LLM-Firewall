# P.I.F.F.A.I — Prompt Injection Firewall For AI

*(Formerly "LLM Guardrail" during early development — see Rebuild Note below.)*

A FastAPI-based reverse proxy that classifies both direct prompts and
uploaded documents for adversarial injection risk before their content
ever reaches a downstream LLM. Defends against direct prompt injection
(malicious text typed by a user) and indirect prompt injection (malicious
instructions hidden inside an uploaded document the user never sees),
per [OWASP LLM01](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
and [OWASP LLM02](https://owasp.org/www-project-top-10-for-large-language-model-applications/).

The system serves two distinct audiences through four endpoints, split
across two surfaces: a **public-facing surface** (chat, and chat-with-document)
that deceives detected attackers with plausible fake responses rather than
confirming a block, and an **authenticated admin/testing surface** (the
same two features, minus the deception) that gives companies and security
teams honest, transparent classification results for real evaluation work.

---

## Submitted to: AI Builders Hackathon 2026

Built for [ai-builders-hackathon-2026.devpost.com](https://ai-builders-hackathon-2026.devpost.com/),
under the Developer Tools / Generative AI Applications categories.

### Rebuild Note — project timeline

An earlier version of this project was started in July 2026 and deleted.
**The current codebase was rebuilt from scratch starting August 31,
2026**, inside the hackathon's eligibility window (August 21 – September
15, 2026). Every entry in the Dev Log below reflects work done on this
rebuilt codebase. This note exists for transparency, not because any rule
requires disclosing it — verify against `git log --format="%ad" --reverse`
for an objective, checkable timestamp if needed.

---

## How It Works

There are four endpoints, forming a 2×2 of (public / admin) × (chat /
chat-with-document). Detection logic (keyword pass + consolidated LLM
classification) is identical across all four — what differs is only
*who* can reach the endpoint and *what happens on a flag*.

### Public surface — no auth required

**`/chat`** — direct prompt injection path, text only.
1. A user message is submitted.
2. The keyword pass + consolidated LLM classification runs against the raw prompt text.
3. **If flagged, and Honeypot Mode is on (default):** a separate
   LLM call (`generate_honeypot_response`) generates a fabricated,
   plausible-sounding reply under strict rules — no real system
   information, no genuinely usable harmful content, no acknowledgment
   that anything was detected. The attacker receives a response with no
   signal their attempt failed. The real detection result is logged
   server-side only; the public JSON response never contains a status
   field indicating what happened.
4. **If flagged, and Honeypot Mode is off:** a plain, explicit denial is
   returned instead.
5. **If not flagged:** the request proceeds to the normal response-generating
   model call under `SYSTEM_PROMPT`.

**`/chat-with-document`** — indirect prompt injection path. Same logic as
`/chat` above, except the attack surface is a document the user uploads
rather than text they type directly. `is_document_sensitive()` extracts
content by file type (PDF, DOCX, XLSX, legacy Office) and classifies it
before any response is generated. A flag routes to
`generate_document_honeypot_response()` (honeypot on) or a plain denial
(honeypot off), exactly mirroring `/chat`'s behavior — including the same
rule that the public JSON response never reveals whether detection fired.

### Admin/testing surface — gated behind `X-Admin-Key`

**`/admin/chat`** — the private, non-deceptive equivalent of `/chat`.
Same detection path, but a flag returns the real `FLAGGED` status plus a
detail message explaining the classification, instead of a honeypot
reply. A `SAFE` result returns the actual model response. Exists for
red-teaming the direct-injection detection logic without the honeypot
layer obscuring whether a given payload was actually caught.

**`/admin/chat-with-document`** — the private, non-deceptive equivalent
of `/chat-with-document`. Same document extraction and classification as
the public version; returns the real `SAFE`/`FLAGGED` result and detail
for genuine evaluation work, since the entire point of this surface is
accurate testing, not attacker confusion.

All four endpoints are gated by the same `require_admin` dependency where
applicable (`/admin/chat`, `/admin/chat-with-document`), checked via
`secrets.compare_digest` against `ADMIN_API_KEY`.

### UI
A single static page (`static/index.html`, served at `/`) with two
top-level tabs, each split into two sub-tabs so all four endpoints are
directly reachable:

- **Public Demo** tab
  - A shared **Honeypot Mode** toggle at the top, applying to both public
    sub-tabs (kept visible specifically so it's demonstrable to hackathon
    judges — a real production deployment would hardcode this on and not
    expose the toggle to end users at all).
  - **Chat** sub-tab — text-only, hits `/chat`.
  - **Chat with a Document** sub-tab — file upload + question, hits
    `/chat-with-document`.
- **Admin / Testing Panel** tab
  - A shared **Admin API Key** field at the top, used by both admin
    sub-tabs.
  - **Private Chat** sub-tab — text-only, hits `/admin/chat`, shows the
    real SAFE/FLAGGED badge and detail.
  - **Document Classification** sub-tab — file upload + question, hits
    `/admin/chat-with-document`, same SAFE/FLAGGED badge and detail
    display.

---

## Setup

```bash
python -m venv venv
venv\Scripts\Activate.ps1      # or source venv/bin/activate on macOS/Linux
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Set an admin key before running (`.env`):
```
ADMIN_API_KEY=your-secret-here
```
If unset, a development fallback key is used — fine for local demoing,
**not** appropriate beyond that (see Known Limitations).

Visit `http://127.0.0.1:8000/` for the UI, or `/docs` for the raw
Swagger interface.

---

## Technical Stack

| Category | Tool / Library | Purpose |
|---|---|---|
| Core Language | Python 3.11+ | Primary development environment |
| Web Framework | FastAPI | API server, reverse-proxy architecture, and route-level auth via `Depends` |
| Web Server | Uvicorn | Local API server deployment |
| Validation | Pydantic | Schema definition and request validation |
| Target LLM | Groq (`openai/gpt-oss-20b`) | Chat responses, document classification, and honeypot response generation |
| PDF Processing | PyMuPDF (`fitz`) | Text extraction; xref-level scanning for embedded JavaScript |
| DOCX Processing | python-docx | Body text extraction (metadata scanning not yet implemented — see Known Limitations) |
| Spreadsheet Processing | pandas | XLSX content extraction for classification |
| Legacy Office Processing | oletools | Macro detection in legacy `.doc` / `.xls` / `.ppt` (OLE) files |
| File Uploads | python-multipart | Multipart form handling for document upload endpoints |
| Static UI | FastAPI `StaticFiles` | Serves the single-page public/admin demo interface, now covering all four endpoints via two-level tabs |

**Note:** if `StaticFiles` raises an import/runtime error referencing
`aiofiles`, install it explicitly (`pip install aiofiles`) — some
environments don't bundle it with FastAPI by default.

---

## Dev Log

*(Sessions below reflect the rebuilt codebase, starting August 31, 2026 — see Rebuild Note above.)*

### Session 1 — Project scaffolding
- Set up virtual environment, FastAPI skeleton, `/health` and `/chat` endpoints.
- Integrated Groq as the LLM provider.
- **Bug found → fixed:** `.env` typo (`GROQ_AI_KEY` instead of `GROQ_API_KEY`) caused `GroqError`.
- **Bug found → fixed:** stale/incorrectly copied API key caused `AuthenticationError` (401); regenerated and copied via console icon.

### Session 2 — Indirect injection via document upload
- Added document upload endpoint and first version of `is_document_sensitive()`.
- **Bug found → fixed:** `llama-3.1-8b-instant` deprecated by Groq; migrated to `openai/gpt-oss-20b`.

### Session 3 — Multi-format document support
- Extended detection to PDF, DOCX, XLSX, and legacy Office formats.
- **Bug found → fixed:** `Document()` called on already-decoded text instead of raw bytes, causing `ValueError`/`PackageNotFoundError`. Resolved by establishing a strict rule: detection always receives raw bytes; extraction happens once, inside the function.
- **Bug found → fixed:** `NameError` from an undefined `doc` variable in the DOCX branch.
- **Bug found → fixed:** endpoint silently returned `null` for `.docx` uploads specifically — the response logic was nested inside an `else` block the DOCX branch never reached; restructured so every file type reaches the same `return`.
- **Bug found → fixed:** `from turtle import pd` typo, corrected to `import pandas as pd`.
- **Bug found → fixed:** orphaned debug line referencing an undefined variable; removed.
- **Bug found → fixed:** redundant double-classification calls; consolidated to one.
- **Bug found → fixed:** `TypeError` on plain-text uploads (`str` compared against `bytes`); added a UTF-8 fallback decode for unrecognized file types.

### Session 4 — Adversarial test suite
- Built a 10-case test suite: paraphrased override, roleplay framing, fragmented payload,
  zero-width Unicode, homoglyph substitution, non-English injection, base64 encoding,
  hidden `.docx` metadata, and embedded PDF JavaScript (positive + negative control).
- **Gaps documented, not yet fixed:** hidden metadata injection (extraction never reads
  `doc.core_properties`), fragmented cross-section payloads, zero-width/homoglyph
  evasion of the keyword layer, non-English coverage, base64 encoding.

### Session 5 — Classification reliability fixes
- **Bug found → fixed:** LLM-based checks were very likely never triggering — responses
  were compared with strict `== "sensitive"` against free-text model output, and
  `"non-sensitive"` contains `"sensitive"` as a substring regardless. Switched vocabulary
  to `SAFE` / `FLAGGED` (no overlap) with normalized comparison.
- **Performance fix:** consolidated four separate LLM calls per document into one;
  shortened `SECURITY_PROMPT` significantly (removed nine near-duplicate clauses).

### Session 6 — PDF-specific detection fixes
- **Bug found → fixed:** `is_tagged` treated as a sensitivity signal — false positive
  generator, since tagging is a legitimate PDF accessibility feature. Removed.
- **Bug found, confirmed via direct testing → fixed:** `is_restricted` does not exist on
  this PyMuPDF `Document` object (`hasattr()` confirmed `False`); would have crashed
  every PDF upload. Removed.
- **Bug found → fixed:** `get_js_count()` also unavailable; replaced with a custom
  `has_pdf_javascript()` scanning `xref_object()` entries for `/JavaScript`/`/JS`.
  **Confirmed correct:** hand-built `test9_embedded_javascript.pdf` (real embedded JS)
  correctly `FLAGGED`; `test10_clean_pdf_control.pdf` (structurally identical, no JS)
  correctly `SAFE` — true positive and true negative both verified live.

### Session 7 — Variable-order bug
- **Bug found → fixed:** `Internal Server Error` on every PDF upload — `combined_prompt`
  referenced before the line constructing it had run. Fourth instance of this general
  bug shape in the project; flagged as a pattern to watch for during future restructuring.
- Verified fix against Test 9 and Test 10 through the live endpoint, not just in isolation.

### Session 8 — Honeypot deception layer, role separation, and UI
- **Feature added:** `generate_honeypot_response()` — on a flagged public request,
  generates a fabricated, plausible-sounding reply under an explicit system prompt
  forbidding real system disclosure or genuinely usable harmful content, so an attacker
  cannot distinguish a successful attack from a deceived one.
- **Design decision, deliberately enforced:** the public `/chat` JSON response never
  includes any field indicating detection occurred — only server-side `print()` logging
  records the real classification outcome. A status flag in the response would defeat
  the entire purpose of the honeypot.
- **Feature added:** role separation — document upload moved to
  `/admin/chat-with-document`, gated behind `require_admin` (header-based key check via
  `X-Admin-Key`). Public users can no longer reach document classification directly;
  admins/companies get transparent `SAFE`/`FLAGGED` results with no deception, since
  their use case is genuine testing, not attacker confusion.
- **Feature added:** single-page UI (`static/index.html`) — public chat panel with a
  visible Honeypot Mode toggle (kept visible for demonstrability; a real deployment
  would hardcode it on), and an admin panel with API key entry, document upload, and a
  SAFE/FLAGGED badge display.
- **Known scope limitation, documented not fixed:** admin auth is a single shared header
  key compared via `secrets.compare_digest`, appropriate for a hackathon demo only. A
  production version would need per-organization keys, OAuth/JWT, and rate limiting —
  see Known Limitations.

### Session 9 — Documentation/UI parity with the existing four-endpoint API
- **Context:** `/chat-with-document` (public) and `/admin/chat` (private/admin chat, no
  document) were already implemented in `app/main.py` — including
  `generate_document_honeypot_response()` mirroring the plain-text honeypot for the
  document path — but neither the UI nor the README had caught up to reflect them.
- **UI parity fix:** the UI previously only exposed `/chat` (public) and
  `/admin/chat-with-document` (admin). Restructured both tabs into two sub-tabs each so
  all four endpoints are directly reachable: **Public Demo** → Chat / Chat with a
  Document; **Admin / Testing Panel** → Private Chat / Document Classification. The
  Honeypot Mode toggle and Admin API Key field are now scoped once per tab (not
  duplicated per sub-tab) since they apply to both features within that tab.
- **Docs fix:** README's "How It Works" section rewritten to document all four
  endpoints instead of two; dev log, tech stack, and known-limitations entries updated
  to refer to both honeypot paths (`/chat` and `/chat-with-document`) wherever a claim
  previously only covered one.

---

## Known Limitations (Not Bugs — Documented Scope Boundaries)

| # | Item | Status |
|---|---|---|
| 1 | Paraphrased override (no trigger keywords) | Depends on LLM-based check catching intent; not guaranteed |
| 2 | Fictional/roleplay framing | Same as above |
| 3 | Payload fragmented across non-contiguous sections | Likely missed — no cross-section reassembly logic |
| 4 | Zero-width Unicode characters inside trigger words | Keyword search evaded; LLM-based check may still catch semantic intent, unconfirmed |
| 5 | Homoglyph substitution (Cyrillic look-alikes) | Same as #4 |
| 6 | Non-English injection | Hardcoded keyword lists are English-only; LLM-based check may generalize, unconfirmed |
| 7 | Base64-encoded payload | Not decoded before scanning — currently missed entirely |
| 9 | Oversized documents (413 rate-limit errors from Groq) | Not yet handled gracefully — can crash the request rather than being truncated or rejected cleanly |
| 10 | Admin authentication | Single shared secret via header comparison — appropriate for a hackathon demo, **not** production-grade. No per-organization keys, no OAuth/JWT, no rate limiting, no key rotation. |
| 11 | Honeypot response safety | Constrained by prompt instructions (no real disclosure, no usable harmful content) but not yet adversarially tested at scale — it's possible a sufficiently creative attacker prompt could still coax a less-fictional-sounding reply out of the honeypot model. Not yet verified against the adversarial test suite from Session 4, for either the text (`/chat`) or document (`/chat-with-document`) honeypot path. |

See `firewall_test_cases/README.md` for full technique descriptions of items 1–8.

---

## Test Files

`firewall_test_cases/` contains 10 files validating document-based detection
(see that folder's own README). **Not yet built:** a matching test set that
runs the Session 4 adversarial prompts through the honeypot paths specifically
(both `/chat` and `/chat-with-document`), to confirm the fake responses hold up
under the same evasion techniques used against document detection. Listed in
Possible Next Steps.

---

## Possible Next Steps

- Scan `doc.core_properties` alongside body text for DOCX uploads (closes gap #8)
- Detect and decode base64-shaped substrings before running detection (closes gap #7)
- Unicode-normalize input before the keyword pass (helps #4, #5)
- Multi-language trigger-phrase coverage, or rely more on LLM-based generalization (helps #6)
- Handle Groq's 413 token-limit error gracefully (closes gap #9)
- Replace the shared admin key with per-organization credentials and proper auth (closes gap #10)
- Run the full adversarial test suite against both honeypot response paths specifically
  (`/chat` and `/chat-with-document`), not just the admin document-classification path
  (addresses gap #11)
- Add automated regression tests asserting expected outcomes across all test files
