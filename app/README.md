# LLM Guardrail — Document Security Firewall

A FastAPI-based reverse proxy that classifies uploaded documents as `SAFE`
or `FLAGGED` before their content ever reaches a downstream LLM, defending
against both direct prompt injection (malicious text typed by a user) and
indirect prompt injection (malicious instructions hidden inside an
uploaded document the user never sees).

Built around [OWASP LLM01: Prompt Injection](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
and [OWASP LLM02: Insecure Output Handling](https://owasp.org/www-project-top-10-for-large-language-model-applications/).

> **A note on dates in this log:** entries below are organized by
> *development session* rather than calendar date, since exact timestamps
> weren't tracked during development. If you want real dates attached,
> the fastest way is to check `git log --format="%ad"` in this repo once
> everything is committed — that gives you an accurate, verifiable
> timeline for free, rather than guessing retroactively.

---

## How it works

1. A document is uploaded to `/chat-with-document` alongside a user question.
2. `is_document_sensitive()` extracts the document's content based on its
   file type (PDF, DOCX, XLSX, legacy Office, or plain text).
3. A fast, free keyword pass (`find_string_in_file`) checks for known
   hardcoded trigger strings.
4. If nothing is caught by the keyword pass, the full document is sent to
   an LLM-based classifier (`llm_classify_document`) that evaluates it
   across four dimensions at once: flagged phrases, structural/pattern
   anomalies, hidden content, and embedded code — governed by a dedicated
   system prompt (`SECURITY_PROMPT`) that the document's own content is
   never allowed to override.
5. If flagged, the request is rejected before the document ever reaches
   the main response-generating model. If safe, the document is passed
   to `/chat`'s underlying model alongside the user's actual question.

---

## Setup

See `LLM_Guardrail_Setup_Guide.pdf` / `.md` for the full walkthrough. Quick reference:

```bash
python -m venv venv
venv\Scripts\Activate.ps1      # or source venv/bin/activate on macOS/Linux
pip install -r requirements.txt
uvicorn app.main:app --reload
```

---

## Dev Log

### Session 1 — Project scaffolding
- Set up virtual environment, FastAPI skeleton, `/health` and `/chat` endpoints.
- Integrated Groq as the LLM provider.
- **Bug found:** `GroqError: api_key must be set` — `.env` contained a
  typo'd variable name, `GROQ_AI_KEY` instead of `GROQ_API_KEY`.
  **Fixed same session** — corrected the variable name.
- **Bug found:** `groq.AuthenticationError` (401) after the above fix —
  the key value itself had been copied incorrectly (partial copy via
  click-drag).
  **Fixed same session** — regenerated the key, copied via the console's
  copy icon instead.

### Session 2 — Indirect injection via document upload
- Added `/chat-with-document` endpoint (file upload + user question).
- Added the first version of `is_document_sensitive()`.
- **Bug found:** `llama-3.1-8b-instant` returning internal server errors
  on every call — the model had been deprecated by Groq (shutdown date
  August 16, 2026).
  **Fixed same session** — migrated to `openai/gpt-oss-20b`, Groq's
  official recommended replacement.

### Session 3 — Multi-format document support (PDF, DOCX, XLSX, legacy Office)
- Extended `is_document_sensitive()` with type-specific branches: PyMuPDF
  for PDF, `python-docx` for DOCX, `pandas` for XLSX, `oletools` for
  legacy OLE formats (`.doc`/`.xls`/`.ppt`).
- **Bug found:** `ValueError: embedded null character` / later
  `PackageNotFoundError: Package not found at 'Robert Nguyen...'` — a
  `Document()` call was being passed already-decoded text (a resume's
  own content) instead of raw bytes or a file path, because the function
  didn't have a consistent contract for what kind of input it expected.
  **Fixed same session** — established a strict rule: `is_document_sensitive()`
  always receives raw bytes; all type-specific extraction happens inside
  the function itself, exactly once.
- **Bug found:** `NameError` on the DOCX branch — code looped over
  `doc.paragraphs` without ever creating `doc` in that scope.
  **Fixed same session** — added the missing `Document(io.BytesIO(...))` call.
- **Bug found:** Endpoint returned `{"response": null}` for `.docx`
  uploads specifically, while `.txt` files worked. Root cause: the
  sensitivity check, LLM call, and `return` statement were nested inside
  an `else` block that only ran for non-DOCX files — the DOCX branch fell
  off the end of the function with no `return`, which Python implicitly
  resolves to `None`.
  **Fixed same session** — restructured so extraction, the sensitivity
  check, and the LLM call all sit at the top level of the function,
  reachable by every file type.
- **Bug found:** `from turtle import pd` — typo, `turtle` has no `pd` object.
  **Fixed same session** — corrected to `import pandas as pd`.
- **Bug found:** Orphaned debug line referencing `document_text` before
  it was defined, left over from an earlier debugging pass.
  **Fixed same session** — removed.
- **Bug found:** `is_document_sensitive()` was being called twice per
  request with inconsistent arguments.
  **Fixed same session** — consolidated to a single call.
- **Bug found:** `TypeError` on plain-text uploads once the "always pass
  raw bytes" rule was enforced — no branch matched `text/plain`, so
  `document_text` reached `find_string_in_file()` still as `bytes`,
  compared against `str` search terms.
  **Fixed same session** — added an `else` fallback decoding to UTF-8 for
  any unrecognized file type.

### Session 4 — Adversarial test suite (8 evasion techniques)
- Built `firewall_test_cases/`: paraphrased override, fictional/roleplay
  framing, fragmented payload, zero-width Unicode characters, homoglyph
  substitution, non-English injection, base64-encoded payload, and hidden
  `.docx` metadata injection.
- **Gap found (Test 8):** hidden metadata injection was never detected —
  root cause is architectural, not a bug: extraction only ever reads
  `doc.paragraphs` (visible body text), and has no code path that reads
  `doc.core_properties` (`comments`, `subject`, `author`) at all. Metadata
  scanning does not yet exist in this codebase.
  **Status: documented, not yet fixed.**
- **Gap found (Test 3):** fragmented payload split across non-contiguous
  document sections reassembles into a coherent instruction only when
  read as one continuous block — current detection has no cross-section
  reassembly logic.
  **Status: documented, not yet fixed — flagged as a genuinely hard
  problem even for production systems.**
- **Gaps found (Tests 4, 5, 6, 7):** zero-width Unicode characters,
  homoglyph substitution, non-English phrasing, and base64 encoding all
  evade the literal keyword search layer to varying degrees.
  **Status: documented; LLM-based check may partially cover some of these,
  unconfirmed.**

### Session 5 — Classification reliability fixes
- **Bug found:** LLM-based checks were very likely never actually
  triggering, even against obvious attacks. Root cause: each check
  compared the model's free-text response against the literal string
  `"sensitive"` using `==`. Models essentially never return a single bare
  word exactly as asked (extra punctuation, capitalization, a full
  sentence) — meaning the comparison silently failed almost every time.
  Compounding issue: `"non-sensitive"` contains `"sensitive"` as a
  substring, an ambiguity baked into the original vocabulary choice.
  **Fixed same session** — switched classification vocabulary to `SAFE` /
  `FLAGGED` (no substring overlap) and normalized responses with
  `.strip().upper()` before comparing.
- **Performance issue found:** four separate LLM API calls per document
  (phrase, pattern, hidden-content, embedded-code checks), each re-sending
  the full document and a lengthy system prompt.
  **Fixed same session** — consolidated into a single `llm_classify_document()`
  call covering all four dimensions in one request; shortened
  `SECURITY_PROMPT` itself, removing nine near-duplicate "never reveal X"
  clauses down to a denser equivalent set of rules.

### Session 6 — PDF-specific detection fixes
- **Bug found:** `pdf_document.is_tagged` was being treated as a
  sensitivity signal — but PDF tagging is a legitimate accessibility
  feature (screen-reader structure) present in large numbers of ordinary,
  compliant PDFs, producing false positives against benign documents.
  **Fixed same session** — removed the check.
- **Bug found and confirmed via direct testing:** `pdf_document.is_restricted`
  does not exist as an attribute on PyMuPDF's `Document` object —
  confirmed via `hasattr(doc, "is_restricted")` returning `False` in the
  actual development environment. This attribute would have thrown
  `AttributeError` on every single PDF upload, not just malicious ones.
  **Fixed same session** — removed the check; noted `doc.permissions`
  (bitmask-based) as the correct alternative if permission-restriction
  detection is added back later.
- **Bug found:** `get_js_count()` does not exist on this PyMuPDF version either.
  **Fixed same session** — replaced with a custom `has_pdf_javascript()`
  function that scans all objects via `xref_length()` / `xref_object()`
  for `/JavaScript` or `/JS` keys, matching PyMuPDF's own documented
  approach for JS detection where `get_js_count()` isn't available.
  **Confirmed working (Session 7):** `test9_embedded_javascript.pdf`
  (contains a real `/OpenAction` → `/JS` action) was correctly `FLAGGED`;
  `test10_clean_pdf_control.pdf` (structurally identical, no JS at all)
  was correctly classified `SAFE`. True positive and true negative both
  confirmed — closes the uncertainty noted when these test files were
  first hand-built, about whether they'd parse correctly under `fitz`'s
  stricter parser versus the more lenient `pypdf` used to originally
  verify them.

### Session 7 — Variable-order bug in the document chat endpoint
- **Bug found:** `Internal Server Error` on every PDF upload, immediately
  after the Session 6 PDF fixes were added.
- **Root cause:** `combined_prompt` was referenced in the LLM call before
  the line constructing it had actually run — a variable-use-before-definition
  bug, the fourth instance of this general pattern in the project (see also:
  the DOCX `NameError` in Session 3, and the orphaned debug line in Session 3).
- **Fixed same session** — reordered so `combined_prompt` is fully built
  before being passed to `client.chat.completions.create()`.
- **Note:** this class of bug (a variable referenced above its own
  definition) has now recurred multiple times across restructuring passes.
  Worth double-checking variable definition order specifically whenever
  moving code between `if`/`else` blocks or consolidating function calls
  going forward.
- **Verification after the fix:** ran `test9_embedded_javascript.pdf` and
  `test10_clean_pdf_control.pdf` through the live endpoint (not just in
  isolation) — Test 9 correctly `FLAGGED`, Test 10 correctly `SAFE`. See
  the Session 6 entry above for what this confirms about `has_pdf_javascript()`.

---

## Known Limitations (Not Bugs — Documented Scope Boundaries)

Identified through the adversarial test suite. Documenting known gaps
honestly is treated here as more valuable than claiming full coverage no
system at this scale actually has.

| # | Evasion technique | Status |
|---|---|---|
| 1 | Paraphrased override (no trigger keywords) | Depends on LLM-based check catching intent; not guaranteed |
| 2 | Fictional/roleplay framing | Same as above |
| 3 | Payload fragmented across non-contiguous sections | Likely missed — no cross-section reassembly logic |
| 4 | Zero-width Unicode characters inside trigger words | Keyword search evaded; LLM-based check may still catch semantic intent, unconfirmed |
| 5 | Homoglyph substitution (Cyrillic look-alikes) | Same as #4 |
| 6 | Non-English injection | Hardcoded keyword lists are English-only; LLM-based check may generalize, unconfirmed |
| 7 | Base64-encoded payload | Not decoded before scanning — currently missed entirely |
| 8 | Hidden `.docx` metadata (`comments`, `subject`, `author`) | **Confirmed missed** — extraction only reads `doc.paragraphs`, never `doc.core_properties` |
| 9 | Oversized documents (413 rate-limit errors from Groq) | Not yet handled gracefully — large documents can exceed the 8,000 TPM on-demand tier limit and crash the request rather than being truncated or rejected cleanly |

See `firewall_test_cases/README.md` for full technique descriptions.

---

## Test Files

`firewall_test_cases/` contains 10 files used to validate detection:

- **Tests 1-8:** adversarial documents (see that folder's own README for
  a full breakdown of each technique)
- **Test 9 — `test9_embedded_javascript.pdf`:** a minimal, hand-constructed
  PDF (not downloaded from any external source) containing a real
  `/OpenAction` → `/S /JavaScript` → `/JS (app.alert(...))` action.
  Confirmed via `pypdf` to be structurally valid and to contain genuine
  `/JavaScript` and `/JS` markers at the raw byte level — the true
  positive case for `has_pdf_javascript()`.
- **Test 10 — `test10_clean_pdf_control.pdf`:** structurally identical
  minimal PDF with no `/OpenAction` and no JS action object at all — the
  true negative control, confirming the detector doesn't flag ordinary
  PDFs by default.

---

## Possible Next Steps

- Scan `doc.core_properties` alongside body text for DOCX uploads (closes gap #8)
- Detect and decode base64-shaped substrings before running detection (closes gap #7)
- Unicode-normalize input (strip zero-width characters, map homoglyphs to
  Latin equivalents) before the keyword pass (helps #4, #5)
- Maintain trigger-phrase lists in multiple languages, or rely more on the
  LLM-based check's language generalization (helps #6)
- Handle Groq's 413 token-limit error gracefully with document truncation
  or a clear rejection message, rather than surfacing a raw API error (closes gap #9)
- Add automated tests asserting expected `SAFE`/`FLAGGED` outcomes across
  all 10 test files, rather than manual Swagger UI testing
