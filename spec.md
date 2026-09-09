# VoiceBook — Voice-Driven Medical Appointment Agent

**Spec version:** 3.1
**Changes from 3.0:** C-34's failed-reference counter moved from the appointment to (source IP, name) — see the revision note under C-34.
**Owner:** Ahsan Ali
**Status:** Ready for implementation
**Supersedes:** v2.0 — OTP removed, identity model rebuilt around a booking reference

---

## 1. Overview

A voice agent that books and cancels medical appointments over two channels — a browser demo and a real phone number — backed by a single FastAPI service with SQLite persistence. English only.

Two rules govern every decision below.

> **The voice platform is a microphone and a speaker.**
> All business logic and all authorization live behind the FastAPI tool API. The LLM never decides who the caller is.

> **The boundary is a network hop, not a convention.**
> The agent package calls the tool API over HTTP with the same authentication as any external caller. It never imports the service or data layer. A boundary you can bypass with an `import` is not a boundary.

### 1.1 Channels

| Channel | Stack | Purpose |
|---|---|---|
| Web demo | Pipecat, browser mic | Primary portfolio demo, always-on, zero marginal cost |
| Phone demo | Vapi (~$10 signup credit) | Recorded walkthrough; number not left publicly dialable |
| Text tester | Streamlit | Deterministic testing without audio |

All three call the same authenticated endpoints. No channel has a privileged path.

### 1.2 Components

| Layer | Choice | Rationale |
|---|---|---|
| Voice orchestration | Pipecat | Python library, in-process; no external media server |
| STT | Deepgram Nova or Groq Whisper — benchmark both on your own voice | Accent performance must be measured |
| TTS | Piper (local) for web; ElevenLabs for phone | Piper has no free tier that can lapse |
| LLM | Groq, behind a provider interface | Free tier, low latency, swappable |
| VAD | Silero (bundled, local) | No API cost |
| DB | SQLite, WAL mode | Single-writer workload |
| API | FastAPI + SQLAlchemy + Pydantic v2 | — |

**No SMS provider.** Removed with OTP in v3.0. Nothing in this system sends anything outbound.

**Latency budget:** 1200ms p95 from end-of-speech to first audio byte.

---

## 2. Scope and accepted risk

This section exists because v3.0 deliberately weakens authentication relative to v2.0. Stating that openly is part of the deliverable.

**What changed.** v2.0 verified callers by SMS OTP. That required a paid provider, added roughly 45 seconds to every call, and made the demo tedious. v3.0 replaces verification with **possession of a booking reference** — a 4-digit code the agent speaks once, at the moment of booking.

**What that buys.** No provider, no cost, one extra spoken field, and a flow that sounds like a real clinic. Cancellation still requires something only the person who made the booking was told.

**What it costs.** A 4-digit code has 10,000 combinations and is spoken aloud, so it is a weak secret. It proves *possession*, not *identity*. An attacker who overhears a code, or who is willing to brute-force against a name and date, can cancel that appointment. Rate limits (F8) make brute force impractical in a demo but do not make it impossible.

**What production would add**, and what the README should say it would add: phone verification at booking time, the reference sent by SMS rather than spoken, and a lockout on the guessing caller after a small number of failed attempts (C-34 — never on the appointment, which would be a denial of service against the patient). Knowing the difference between demo-scope and production-scope security — and documenting it rather than hiding it — is the point.

**Decision (settled).** The booking reference is **required**. There is no flag, no minimal mode, and no code path that cancels an appointment on a name and date alone. This was considered and rejected: a name is not a secret, and a cancel flow that accepts one is an open authorization bypass (C-31).

Implementers must not reintroduce this as a configuration option "for testing". The Streamlit tester completes the same reference flow as every other channel (C-13), so no such escape hatch is needed. A flag that can weaken authority is a flag that will eventually be set wrong in a deployed environment.

---

## 3. Non-goals

- **No medical advice, triage, or symptom evaluation.** No "reason for visit" field — it is the doorway symptoms walk through.
- No prescriptions, lab results, or clinical records.
- No payments or insurance.
- No outbound dialing, no SMS, no email.
- Not a HIPAA/GDPR-certified system. It implements appropriate *patterns* on synthetic data.

---

## 4. Findings

### 4.1 Carried forward from rounds 1 and 2

| ID | Finding | Status in v3.0 |
|---|---|---|
| C-03 | Unauthenticated tool endpoints | **Active** — HMAC + shared secret, per channel |
| C-04 | LLM-supplied identifiers cause IDOR | **Active** — ordinals only, server-resolved |
| C-05 | Prompt injection via speech | **Active** — no bulk-returning tool exists |
| C-06 | Emergencies routed into booking | **Active** — deterministic pre-filter, F10 |
| C-07 | Toll fraud and denial-of-wallet | **Active** — caps, no outbound, spend ceiling |
| C-08 | PHI stored in plaintext | **Active** — AES-GCM, `key_id`, per-row nonce |
| C-09 | Transcripts as an unbounded PHI sink | **Active** — redact before write, 30-day purge |
| C-10 | Existence oracle | **Active and widened** — see C-32 |
| C-11 | SQL injection at the fuzzy-match layer | **Active and widened** — see C-35 |
| C-12 | Booking race condition | **Active** — unique constraint decides |
| C-13 | Streamlit tester as a backdoor | **Active** — same authenticated path |
| C-14 | Booking spam and slot squatting | **Active but weakened** — see C-34 |
| C-15 | No recording consent | **Active** — spoken disclosure + web UI gate |
| C-16 | Secrets in a public repo | **Active** — env only, gitleaks |
| C-17 | Real data in a public demo | **Active** — synthetic seed, boot assertion |
| C-18 | Spoken digit capture is unreliable | **Active, retargeted** — now the reference code |
| C-19 | Trust boundary was decorative | **Active** — CI import check |
| C-25 | Second-order injection through logs | **Active** — transcripts are data, delimited |
| C-26 | Ephemeral disk destroys the database | **Resolved** — ephemeral by decision, F0 |
| C-27 | Web recording consent only in speech | **Active** — UI gate before `getUserMedia` |
| C-28 | No immutable audit trail | **Active and more important** — see C-31 |
| C-29 | Schedule enumeration | **Active** — ≤5 slots, ≤14-day horizon |
| C-30 | No defined provider-failure behavior | **Active** — timeouts, fallback utterance |
| C-01 | No caller authentication | **Partially retired** — replaced by possession, §2 |
| C-02 | Caller ID treated as identity | **Retired** — no phone number is collected at all |
| C-20 | Session fixation on escalation | **Retired** — no privilege escalation step remains |
| C-21 | `request_otp` as an SMS weapon | **Retired** — no OTP, no SMS |
| C-22 | `request_otp` existence oracle | **Retired** — superseded by C-32 |
| C-23 | Caps reset on reconnect | **Active and more important** — see C-34 |
| C-24 | No key versioning | **Active** — `key_id` retained |

### 4.2 Round 3 — new findings

**C-31 — Name plus date is not authorization. (CRITICAL)**
A name is not a secret. Removing OTP without a replacement would let any caller cancel any appointment by guessing a common name and a plausible date.
*Fix:* Possession model (§5). Cancellation requires the 4-digit booking reference issued at booking time — always, with no configurable bypass (§2). Every cancellation attempt, allowed or denied, writes an audit row (C-28).

**C-32 — Lookup by name is an existence oracle, and now anyone can query it. (CRITICAL)**
"Is there an appointment for Ahmed Khan on Tuesday?" answered honestly discloses that a named person has a medical appointment. In v2.0 this required passing OTP first; in v3.0 the lookup is the first step.
*Fix:* The agent never confirms existence before the reference is supplied and matched. Responses to name-plus-date are identical whether or not a record exists: the agent asks for the reference either way, and only after a correct reference does it describe the appointment. The no-match path performs a dummy comparison to normalize timing. Never say "I can't find anyone by that name."

**C-33 — Homonym collision is a correctness bug, not just a security one. (HIGH)**
Two patients named "Ahmed Khan" on the same day. Without a unique identifier there is no principled way to choose, and cancelling the wrong person's appointment is the worst possible demo outcome.
*Fix:* Resolution requires name **and** date **and** reference. The reference disambiguates. If multiple rows still match, the agent must **refuse and hand off** — it must never guess, and must never enumerate the candidates aloud (that would leak both patients).

**C-34 — Removing identity removes the key rate limits were built on. (HIGH)**
v2.0 keyed abuse budgets on a verified phone HMAC. No verified identity now exists, so budgets fall back to weaker signals.
*Fix:* Keep budgets on source IP and the platform call identifier, persisted across restart and reconnection (this is why C-23 matters more now, not less). Add a per-normalized-name daily booking cap as a soft layer, and a global daily booking cap as the hard backstop. Add a failed-reference-attempt counter keyed on **(source IP, normalized name asked about)**: 5 failures lock **that caller** out of cancelling under that name for 1 hour and write an audit row.

*Revised during F5 implementation (v3.1).* This counter was originally specified per appointment. That is wrong, and wrong in the direction that matters: a name is not a secret and neither is a plausible date, so anyone able to guess both could burn five deliberate failures and lock a real patient out of their own booking for an hour. The lockout would become the cheapest attack in the system. Keyed on the caller, the same five guesses cost the guesser their next hour and cost the patient nothing — a second caller holding the correct reference cancels normally. `appointments` therefore carries no lock column and no attempt counter; the budget lives in `rate_limit_buckets`, with the (IP, name) pair stored as a keyed HMAC because that table is not encrypted and the name is PHI.

The residual is stated rather than hidden: an attacker with many source addresses regains parallelism, exactly as §2 says a 4-digit spoken code cannot survive a determined adversary. What production adds is phone verification, not a bigger counter.

**C-35 — The name is now the primary matching field, and it arrives from STT. (HIGH)**
Free text from speech is now load-bearing for record resolution. This is both an injection surface and an accuracy problem — "Ahmad" and "Ahmed" are the same person to a human.
*Fix:* Store a normalized name form (case-folded, whitespace-collapsed, diacritics stripped) alongside the encrypted original, and match on the normalized form with parameterized equality — never `LIKE`, never interpolation. Phonetic matching may widen candidate selection but never auto-selects; ambiguity always asks. Names are validated by a Pydantic constrained type (§7) before reaching any query.

**C-36 — Pydantic validates shape, not permission. (HIGH)**
Treating "the request validated" as "the request is allowed" is the most common way a well-typed API ends up with no authorization at all. A perfectly-formed cancellation request from a stranger is still a perfectly-formed cancellation request.
*Fix:* Validation and authorization are separate layers with separate tests. Pydantic runs at the boundary and rejects malformed input with 422. Authorization runs in a FastAPI dependency after validation and rejects unauthorized input with 403. No endpoint may rely on a validator for an access decision, and the contract test suite asserts both codes independently for every mutating endpoint.

**C-37 — Listing appointments aloud after a weak match is disclosure. (MEDIUM)**
v2.0 read out a numbered list of a verified patient's appointments. Under a possession model there is no verified patient, so listing would disclose data to whoever supplied a name.
*Fix:* No list tool. The caller states the date; the agent confirms **one** appointment, only after the reference matches, and describes only that one. `list_my_appointments` is removed from the API surface entirely.

**C-38 — The tier model no longer describes reality. (MEDIUM)**
v2.0's `UNVERIFIED`/`VERIFIED` session tiers assumed an escalation step that no longer exists. Leaving them in place would produce code that looks authorized but is not.
*Fix:* Delete the tier concept. All sessions are equal. Mutation authority derives solely from a reference match performed server-side, per request, against the specific appointment being mutated. Nothing is stored on the session that grants standing access.

---

## 5. Identity model — possession, not verification

There is no login, no OTP, and no verified identity anywhere in this system. Authority to cancel comes from **possessing a value that was disclosed only at booking time**.

### 5.1 Booking reference

- 4 digits, generated with `secrets`, never sequential.
- Unique among **active** appointments; may be reused after an appointment completes or is cancelled.
- Stored as a keyed HMAC, never in plaintext (same treatment as any secret).
- Spoken once at the end of booking, and repeated once if the caller asks within the same call.
- Never spoken during a cancellation call, never confirmed as "close", never partially acknowledged.

### 5.2 Cancellation authority check

Performed server-side, in one step, on the specific appointment:

```
match = normalized_name  AND  appointment_date  AND  hmac(reference)
```

All three must match one row. Failure of any is a single indistinguishable outcome to the caller. The attempt counter increments on every failure regardless of which field was wrong.

### 5.3 Session record

```
session_id      opaque token; never enters LLM context
channel         web | phone | tester
state           booking state machine position
digit_buffer    server-side, survives turn boundaries
turn_count
consent_at
created_at, expires_at   15-minute TTL
```

No `patient_id`. No tier. Nothing on the session grants access to anything.

### 5.4 Tool surface

| Tool | Returns | Authority required |
|---|---|---|
| `search_doctors` | Public directory | None |
| `get_available_slots` | ≤5 slots, ≤14-day horizon | None |
| `book_appointment` | Confirmation + reference | None (creation only) |
| `cancel_appointment` | Confirmation | Name + date + reference match |

`list_my_appointments` does not exist (C-37). There is no reschedule tool in v3.0 — a reschedule is a cancel followed by a book, which keeps the authority check in exactly one place.

---

## 6. Conversation flows

### 6.1 Booking

1. **Disclosure.** "This call is recorded, and you're speaking with an AI assistant." Stated, not asked.
2. **Intent.** "Would you like to book or cancel an appointment?"
3. **Doctor or specialty.** Resolved against the whitelist; ambiguity asks.
4. **Date.** Relative expressions resolved in clinic timezone (F7).
5. **Slot.** Agent offers at most 5; caller picks one.
6. **Name.** Collected here, after the slot is chosen, because until this point no patient data exists in the session at all.
7. **Confirm.** "Dr. Ahmed, Tuesday the 12th at 4 PM, for Ahmed Khan. Shall I confirm?"
8. **Reference.** "Booked. Your reference is 4-7-2-9. Please keep it — you'll need it to cancel."
9. **Readback offer.** "Would you like me to repeat that?"

### 6.2 Cancellation

1. **Disclosure**, as above.
2. **Intent.** Cancel.
3. **Name.**
4. **Date** of the appointment.
5. **Reference.** "And your 4-digit reference?" — asked **every time**, including when no matching record exists (C-32).
6. **Confirm.** Only on a full match: "That's Dr. Ahmed, Tuesday the 12th at 4 PM. Cancel it?"
7. **Done**, or a single uniform failure message.

**Uniform failure text:** "I wasn't able to match that. Please check your details and try again, or contact the clinic directly." Used for no such name, wrong date, wrong reference, ambiguous match, and locked-out caller alike. The caller learns nothing about which field failed.

### 6.3 What the agent never asks

CNIC or any ID number. Date of birth. Address. Payment or insurance. **Symptoms, condition, or reason for visit** — under any phrasing, including a caller volunteering it. If a caller states symptoms unprompted, the agent does not acknowledge the content, does not store it, and continues the booking.

### 6.4 Digit capture (C-18)

VAD detects energy, not sentence completion. People pause mid-number and that pause looks exactly like a finished turn. Raising the silence threshold globally only trades an interrupting agent for a sluggish one.

The fix is a design where a mistimed turn boundary does no damage:

1. On entering a digit-collecting state, instruct explicitly: "Please say your four-digit reference."
2. Raise the VAD silence threshold to ~1200ms **for this state only** — a safety net, not the mechanism.
3. Digits accumulate in a **server-side buffer across turns**. An early cut just means the caller continues and fragments append.
4. Readback triggers only when the buffer holds exactly 4 digits.
5. Digit-by-digit readback, then explicit confirmation. "No" clears the buffer. Two retries, then handoff.

This is the principle used throughout: **do not try to make an unreliable component reliable — design so its failures are harmless.** The LLM is unreliable, so authority never passes through it. The application's free-slot check is unreliable under concurrency, so the database constraint decides. VAD is unreliable at pauses, so the buffer survives them.

---

## 7. Validation strategy

Pydantic v2, strict mode, `extra="forbid"` on every model. Validation is a boundary concern and is **never** an access decision (C-36).

**Constrained types**

```
PatientName     1–60 chars, letters/space/hyphen/apostrophe only,
                normalized form derived in a validator
AppointmentDate future-dated, within the 60-day horizon,
                clinic-timezone anchored
BookingRef      exactly 4 ASCII digits
DoctorId        positive int, existence checked in the service layer
IdempotencyKey  UUID
```

**Rules**

- Free text never reaches SQL. Names are matched on the normalized column with parameterized equality; doctors resolve to integer IDs via an in-memory whitelist (C-35, C-11).
- Validators normalize and reject. They never look anything up, never touch the database, and never decide permission.
- Every mutating endpoint has two independent contract tests: a malformed request returning 422, and a well-formed unauthorized request returning 403. Passing one does not imply the other.
- Response models are explicit. No ORM object is ever serialized directly — that is how an encrypted field or an internal ID leaks into a response.

---

## 8. Trust boundaries

```
   UNTRUSTED                   SEMI-TRUSTED                  TRUSTED
┌──────────────┐           ┌──────────────────┐         ┌──────────────┐
│ Caller voice │──audio──► │  agent/          │──HTTP──►│  app/        │
│ (adversary)  │           │  Pipecat, Vapi   │  +HMAC  │  FastAPI     │
└──────────────┘           │  LLM context     │  +TLS   │  + SQLite    │
                           └──────────────────┘         └──────────────┘
   Assume every        Assume the LLM can be         Sole authority for
   utterance is        talked into calling any       authorization and
   hostile input       tool with any argument        all state

   ENFORCED BY CI: nothing under agent/ may import app/services,
   app/db, or app/models.
```

Correctness cannot depend on the LLM behaving. Assume the model will eventually attempt every tool with attacker-chosen arguments.

---

## 9. Feature specs

### F0 — Schema, encryption, seed, persistence

Tables: `doctors`, `availability_rules`, `appointments`, `patients`, `sessions`, `audit_events`, `rate_limit_buckets`. (`otp_challenges` removed.)

Encryption: `patients.name_enc` (AES-GCM, per-row nonce, `key_id`), `patients.name_normalized` for matching, `appointments.reference_hmac`.

Constraints: `UNIQUE(doctor_id, slot_start_utc)` partial on active status; `UNIQUE(reference_hmac)` partial on active status. All timestamps UTC.

Persistence: **ephemeral, by decision** (C-26). The database is rebuilt from the synthetic seed on every cold start. Bookings made during a session are real and fully functional within that session; they do not survive a redeploy or a free-tier sleep cycle. This is a demo posture, not an oversight, and the README states it in one line: demo data resets on redeploy.

Two things this requires:
- Seeding is idempotent and runs automatically at startup — never a manual step, since a cold start can happen unattended.
- A boot check logs, at INFO, whether the database file was found or newly created. Silent data loss is the failure mode that costs hours; a log line makes it obvious in one glance.

**Acceptance:** WAL verified. Encrypted fields unreadable via the `sqlite3` CLI. Reference never appears in plaintext anywhere in the database. Boot fails without the synthetic-seed marker. ≥8 doctors across ≥5 specialties.

### F1 — Slot engine

Slots from availability rules, minus booked, minus blackouts. No booking within 2 hours.

**Acceptance:** Property test — no slot returned twice, none overlapping a booked appointment. DST-safe. Beyond-horizon returns empty, not an error.

### F2 — Booking state machine

`GREETING → CONSENT → INTENT → [BOOK | CANCEL] → CONFIRM → DONE`
Book path: `DOCTOR_SELECT → SLOT_SELECT → COLLECT_NAME → CONFIRM → BOOKED`
Cancel path: `COLLECT_NAME → COLLECT_DATE → COLLECT_REFERENCE → CONFIRM → CANCELLED`
Terminal: `BOOKED`, `CANCELLED`, `ABANDONED`, `ESCALATED_EMERGENCY`, `PROVIDER_FAILURE`, `HANDOFF`.

**Acceptance:** Illegal transitions raise and are logged. The cancel path cannot reach `CONFIRM` without a reference match. Every state defines behavior for silence, ambiguity, and off-topic input.

### F3 — Tool endpoints

Per §5.4 and §7. No tool accepts a database identifier.

**Acceptance:** Unexpected field → 422. Unauthorized well-formed request → 403. Both asserted separately for every mutating endpoint (C-36). No ORM object serialized directly.

### F4 — Request authentication (C-03, C-19)

Shared secret header, HMAC-SHA256 over `timestamp + raw_body`, 300s freshness, replay cache, separate secret per channel.

**Acceptance:** Tampered body, replayed signature, stale timestamp each return 401. Constant-time comparison. CI import-boundary check green.

### F5 — Reference issue, match, and digit capture (C-31, C-32, C-33, C-18)

Implements §5 and §6.4.

**Acceptance:**
- Reference is generated with `secrets`, stored only as HMAC.
- A cancel with a correct name and date but a wrong reference fails, and is indistinguishable from a nonexistent name.
- Response timing for "no such name" and "wrong reference" differs by under 20ms across 100 samples.
- Two identically-named patients on the same date with different references resolve correctly; if the reference also collides, the agent hands off rather than guessing, and names neither patient.
- 5 failed attempts lock that caller (source IP plus the name asked about) for 1 hour and write an audit row; the appointment itself is never locked (C-34).
- The digit buffer survives a mid-code VAD cut, proven by a test feeding "4-7", then "2-9".

### F6 — Entity resolution (C-11, C-35)

Doctor resolution against an in-memory whitelist. Name normalization in a Pydantic validator. Ambiguity asks; it never auto-selects.

**Acceptance:** CI greps clean for f-string and `.format()` SQL. Injection payloads spoken as a name or doctor resolve to no match — never an error, never a query. 30-case fixture ≥90% correct doctor resolution.

### F7 — Relative date parsing

"tomorrow", "next Tuesday", "the 15th". Clinic timezone anchored.

**Acceptance:** Ambiguous input always clarifies. Past dates reprompt. 40-phrasing fixture passes.

### F8 — Rate limits and abuse controls (C-07, C-14, C-23, C-29, C-34)

Buckets on source IP, platform call ID, normalized name (soft daily cap), and a global daily hard cap. Failed-reference counter keyed on (source IP, normalized name) — never on the appointment, see C-34. All persisted across restart and reconnection.

**Acceptance:** Reconnecting resets no budget. 4th call from a source in 24h refused. Global cap degrades gracefully. Brute-forcing a reference is blocked at the 5th attempt from that source against that name, **and a caller from another source holding the correct reference still cancels** — the lockout must never become a denial of service against the patient. All limits are configuration.

### F9 — Streamlit tester (C-13)

Full booking and cancellation in text. Displays state, tool calls with arguments, latencies, and audit events generated.

**Acceptance:** Refuses to start when `ENV=production`. Uses the identical authenticated path. No endpoint reachable by the tester and not by the voice channels.

### F10 — Safety guardrails (C-06, C-15, C-27, C-30)

- **Deterministic keyword layer** for emergencies, before the state machine, every turn, with **no external provider dependency**.
- LLM classifier as an additive second layer, never a replacement.
- On trigger: abandon the flow, state clearly that this system cannot help medically, direct to emergency services (configurable; default Rescue 1122), log it.
- Refuse all medical questions with one warm redirect. Do not acknowledge volunteered symptom content.
- Recording and AI disclosure in the opening utterance; UI consent gate before microphone activation on web.

**Acceptance:** 15 emergency fixtures escalate within one turn, including with the LLM stubbed unreachable. 20 medical-advice fixtures refuse with zero leakage. No symptom text appears in any stored record. Disclosure present in 100% of transcripts.

### F11 — Observability and evals (C-09, C-25)

Redact before store: names, dates of birth, **references**, any digit run of length ≥4. Structured events: session, turn, tool call, latency, outcome, escalation.

Eval set: 25 scripted conversations — 15 happy-path, 10 adversarial (injection, reference brute force, homonym collision, existence probing, emergency, ambiguity, digit fragmentation). Each asserts final database state.

Transcript content passed to eval tooling inside a delimited untrusted block.

**Acceptance:** Redactor fixtures pass with zero leaked names or references. Purge removes records older than 30 days. Eval suite gates CI.

### F12 — Pipecat web agent (C-19, C-27)

Browser mic, barge-in, server-minted 60-second room-scoped tokens. Silero VAD with **state-dependent** thresholds — ~700ms default, ~1200ms while collecting digits.

**Acceptance:** No provider key in any client bundle (build-time grep). Mid-sentence interruption handled cleanly. Reconnection resets no budget. Import-boundary check green.

### F13 — Vapi phone agent

Same tools, own secret, outbound disabled, number enabled only during recording windows.

**Acceptance:** Unsigned tool calls rejected. Duration cap enforced at platform and server. Parity test: identical scripted conversation, identical database state on web and phone.

### F14 — Cancellation (C-31, C-28, C-37)

Authority check per §5.2. Every attempt, allowed or denied, writes an audit row inside the mutation's transaction.

**Acceptance:** Cancelling an already-cancelled appointment is idempotent. A denied attempt produces exactly one audit row with the denial reason. No list tool exists at any privilege level.

### F15 — Idempotency

Client-supplied key on `book_appointment`; a repeat within 24h returns the original result and the original reference.

**Acceptance:** A retried call after a network timeout produces exactly one appointment row and does not issue a second reference.

### F16 — Deployment hardening

HTTPS only, HSTS, CORS restricted, security headers, generic client-facing errors with a correlation ID, structured server-side logging.

**Acceptance:** A forced 500 returns a generic body plus a correlation ID — no stack trace, no SQL. Unknown-origin preflight refused. `gitleaks` clean across full history.

### F17 — Audit trail (C-28)

Append-only `audit_events`: session, action, target appointment, decision, reason, timestamp. No `UPDATE` or `DELETE` path in application code. Written transactionally with the mutation.

**Acceptance:** A rolled-back mutation leaves no audit row. A committed one always leaves exactly one. No code path exists to modify an audit row.

---

## 10. Implementation order

1. **F0 → F4** — schema, slots, state machine, tools, request auth, import boundary
2. **F5** — reference issue, match, digit capture (the authority spine)
3. **F8, F10, F17** — limits, safety, audit
4. **F9** — Streamlit tester; perfect the whole flow in text
5. **F6, F7, F14, F15** — resolution, dates, cancellation, idempotency
6. **F11** — observability and evals
7. **F12** — Pipecat web agent
8. **F13** — Vapi phone agent
9. **F16** — deployment hardening

Perfect everything in text before adding audio. Debugging an authority check through a microphone wastes hours.

---

## 11. Pre-ship checklist

- [ ] Nothing under `agent/` imports `app/services`, `app/db`, or `app/models` — CI-enforced
- [ ] No tool schema accepts a database identifier
- [ ] `list_my_appointments` does not exist
- [ ] Reference stored only as HMAC; never logged, never in a response body
- [ ] Cancellation requires name + date + reference, checked in one server-side step
- [ ] Every failure mode returns the identical caller-facing message
- [ ] No-match and wrong-reference timings within 20ms
- [ ] Homonym collision hands off; candidates never enumerated aloud
- [ ] Failed-attempt lockout active and audited, keyed on the caller and not on the appointment
- [ ] 422 and 403 asserted independently for every mutating endpoint
- [ ] No ORM object serialized directly
- [ ] All SQL parameterized; CI greps for f-string SQL
- [ ] HMAC verified on every `/tools/*` call, constant-time, replay-windowed, per-channel secrets
- [ ] PHI encrypted with `key_id` and per-row random nonce
- [ ] Transcripts redact names, references, and digit runs before write
- [ ] No symptom text stored anywhere
- [ ] Emergency keyword layer works with all providers stubbed unreachable
- [ ] Rate-limit budgets survive reconnection and restart
- [ ] Recording disclosure spoken; web mic gated behind UI consent
- [ ] Seed runs idempotently at startup; boot logs whether the DB was found or created
- [ ] README states that demo data resets on redeploy
- [ ] `DEMO_MODE` refused when `ENV=production`
- [ ] Seed synthetic with boot assertion
- [ ] `gitleaks` clean; no provider key in any client bundle
- [ ] §2 accepted-risk statement reflected in the README
- [ ] Adversarial eval suite green in CI

---

## 12. Portfolio framing

The differentiator is not that it books appointments. It is that the design assumes the LLM is compromised and stays correct anyway, and that it is honest about where its own security ends.

Four points for the README:

1. **Authority never flows through the model.** The LLM cannot cancel anything — it relays a name, a date, and four digits, and the server decides. There is no privilege in the prompt to escalate.
2. **The trust boundary is enforced by CI, not by discipline.** A build fails if the agent package reaches into the service layer. An earlier draft of this design quietly violated its own boundary; that finding is worth telling.
3. **Safety is a pre-filter, not a prompt instruction.** The emergency interrupt runs before the agent reasons, and keeps working when every provider is down.
4. **The security scope is stated, not implied.** §2 says exactly what a 4-digit spoken reference does and does not protect, and what production would add. A demo that documents its own limits reads as engineering judgment. One that hides them reads as a demo that was never attacked.

Include the §8 diagram and the findings table in the README. Ten of twenty-five evals are attacks, and they gate the build.
