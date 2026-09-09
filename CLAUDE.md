# CLAUDE.md — VoiceBook

Context file for Claude Code sessions. Read `spec.md` in full before writing any code. It is version 3.0; anything you recall about OTP or verified sessions is from a superseded draft.

---

## What this is

A voice agent for medical appointment booking. Two channels (browser via Pipecat, phone via Vapi), one FastAPI backend, SQLite persistence, Streamlit for text-mode testing. English only.

**The database is ephemeral by decision.** It rebuilds from the synthetic seed on every cold start. Seeding must be idempotent and automatic at startup, never a manual step — a free-tier sleep cycle can restart the app unattended. Boot logs whether the DB file was found or newly created. Do not add migration machinery or persistence workarounds; the reset is intended (spec F0, C-26).

The point of this project is that **it stays correct under the assumption that the LLM is compromised**. A feature that works but bypasses a control in `spec.md` defeats the project. Correctness here means secure, not merely functional.

---

## The two rules that override everything

**1. The voice platform is a microphone and a speaker.**
No business logic, no authority, no access decisions in the agent layer. If you are writing a rule about who may do what and you are inside `agent/`, you are in the wrong file.

**2. The boundary is a network hop, not a convention.**
`agent/` may import an HTTP client and nothing else from this codebase. Never `app/services`, `app/db`, or `app/models`. CI enforces this. If a task seems to require crossing it, stop and raise it — that shortcut deletes the security model (C-19).

---

## Authority model — read this before touching cancellation

There is **no login, no OTP, and no verified identity**. Authority to cancel comes from possessing a 4-digit booking reference disclosed only at booking time.

- Cancellation requires **name + date + reference**, matched in one server-side step.
- Every failure — wrong name, wrong date, wrong reference, no such record, ambiguous match, locked appointment — returns the **identical** caller-facing message. The caller must never learn which field failed.
- The agent asks for the reference **even when no record matches**. Skipping that ask is an existence oracle (C-32).
- There is no list tool. The agent confirms one appointment, after the reference matches, and describes only that one.
- Sessions carry no tier and no patient ID. Nothing on a session grants standing access.

The reference is **always required**. Do not add a config flag, environment variable, or test-only path that cancels on a name and date alone — this was considered and rejected (spec §2, C-31). The Streamlit tester uses the same reference flow as every other channel, so no bypass is needed for testing.

---

## Layout

```
app/            FastAPI — the only trusted zone
  models/       SQLAlchemy
  services/     business logic, slot engine, state machine
  tools/        /tools/* endpoints — thin, no logic
  security/     HMAC middleware, encryption, reference match, rate limits, redaction
  db/
agent/          voice layer — HTTP client only, no app/ imports
  pipecat/
  vapi/
  prompts/
tester/         Streamlit
tests/
  unit/
  contract/     422 and 403 asserted separately per mutating endpoint
  adversarial/  the 10 attack evals — these gate the build
evals/          25 scripted conversations
spec.md
```

---

## Non-negotiables

Violating any of these is a bug even if tests pass and the feature works.

- **Pydantic validates shape. It never decides permission.** A well-formed request from a stranger is still unauthorized. Validation returns 422; authorization returns 403; they are separate layers with separate tests (C-36).
- **No database identifier in any tool schema.** The server resolves everything.
- **No tool returns more than one appointment.** `list_my_appointments` must not exist.
- **The reference is stored only as an HMAC.** Never plaintext in the DB, never in a log, never in a response body, never in a transcript.
- **Scoping is enforced in SQL and FastAPI dependencies**, never in prompt text.
- **No f-string or `.format()` SQL, ever.** Parameterized only. CI greps for this.
- **Names match on the normalized column with parameterized equality** — never `LIKE`, never interpolation. Ambiguity asks; it never auto-selects.
- **Homonym collision hands off.** Never guess between two matching patients, and never name them aloud.
- **Every cancellation attempt, allowed or denied, writes one audit row** in the mutation's transaction.
- **The emergency keyword check runs before the state machine, every turn, with no external provider dependency.** It must work with the LLM stubbed unreachable.
- **No symptom text is ever stored.** There is no reason-for-visit field. If a caller volunteers symptoms, do not acknowledge the content and do not persist it.
- **Rate-limit budgets key on IP and call ID, never on `session_id`**, which resets on reconnect.
- **Secrets from environment only.** No provider key in a client bundle. No real phone number or real patient data anywhere in the repo.
- **`DEMO_MODE` refuses to start when `ENV=production`.**

---

## Design principle to apply when stuck

**Do not try to make an unreliable component reliable. Design so its failures are harmless.**

Already applied in the spec:
- The LLM is unreliable → authority never passes through it.
- The application's free-slot check is unreliable under concurrency → the database unique constraint decides.
- VAD is unreliable at mid-number pauses → digits accumulate in a server-side buffer that survives a cut turn.

Reach for this shape before reaching for a better model or a tuned threshold.

---

## How to work

Ahsan works spec-driven, feature by feature.

1. Read the feature's section in `spec.md`, including acceptance criteria.
2. State your plan and name the findings (C-nn) the feature must satisfy.
3. Implement one feature at a time. Do not touch adjacent features opportunistically.
4. Write the tests the acceptance criteria demand, including adversarial ones. Happy-path tests alone mean it is not done.
5. Before declaring it complete, attack your own code and report what you found, even if you fixed it.

Build order is fixed in spec §10. **F5 (reference issue and match) is the authority spine** — nothing built on it is safe until it lands. Do not jump ahead to the voice layer because it demos better.

Perfect the flow in the Streamlit tester before adding audio.

---

## Communication

- Ahsan writes in Roman Urdu mixed with English. Reply the same way. Code, comments, and identifiers stay English.
- Use everyday Pakistani analogies where they make a concept concrete.
- Be direct about problems. If a request would introduce a hole, say so plainly and propose the alternative — do not implement it quietly and add a caveat at the end.
- Do not summarize what the diff already shows.

---

## Environment

- Windows. GitHub CLI available. GitHub MCP and Context7 MCP configured.
- Python with `uv`. FastAPI, SQLAlchemy, Pydantic v2 strict mode, `extra="forbid"`.
- Run `pytest tests/adversarial` before any commit touching `app/security/` or `app/tools/`.
- `gitleaks` as a pre-commit hook and in CI.

---

## Definition of done

- Acceptance criteria in `spec.md` pass, including adversarial ones
- Import-boundary check green
- SQL-interpolation grep clean
- 422 and 403 asserted independently for every mutating endpoint
- Mutations produce audit rows
- No secret, reference, real number, or real patient datum entered the repo
- You have named at least one way you tried to break it and what stopped you
