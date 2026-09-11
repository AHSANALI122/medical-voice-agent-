# VoiceBook

A voice agent for medical appointment booking, designed on the assumption that
the language model driving it is compromised.

**Status:** F0–F15 and F17 implemented (schema, slot engine, state machine,
tool endpoints, request authentication, the booking-reference authority spine,
entity resolution, relative dates, abuse budgets, the Streamlit tester, the
safety pre-filter, observability and the eval suite, the Pipecat web agent, the
Vapi phone agent, cancellation, idempotency, and the append-only audit trail).

**F16 — deployment hardening is not built.** Its correlation-id half is: every
response carries `x-correlation-id`, failures included. The rest is not — no
HSTS, no CORS restriction, no security headers. `gitleaks` is now wired up both
ways — over the full history in CI (`.github/workflows/ci.yml`) and over the
staged diff pre-commit (`.pre-commit-config.yaml`, one `pre-commit install` per
clone). Do not treat this as deployable as it stands.

---

## The design in five lines

1. **Authority never flows through the model.** The LLM cannot cancel anything.
   It relays a name, a date and four digits; the server decides. There is no
   privilege in the prompt to escalate.
2. **The trust boundary is enforced by CI, not by discipline.** Nothing under
   `agent/` or `tester/` may import `app/services`, `app/db`, `app/models`,
   `app/security` or `app/tools`. `scripts/check_import_boundary.py` fails the
   build if it does. That is also the whole answer to "is the test tool a
   backdoor?" — it cannot reach the service layer, rather than merely not
   reaching it today.
3. **Safety is a pre-filter, not a prompt instruction.** The emergency
   interrupt runs before the state machine on every turn, in pure Python, with
   no provider in its path — it keeps working with every provider stubbed
   unreachable. The LLM classifier is additive: it can add an escalation, never
   remove one.
4. **Validation is not authorization.** Pydantic rejects malformed input with
   422. A separate layer rejects unauthorized input with 403. Every mutating
   endpoint asserts both, independently.
5. **The security scope is stated, not implied.** See below.

## Accepted risk (spec §2)

Cancellation authority comes from **possessing a 4-digit booking reference**
spoken once at booking time. There is no login, no OTP, and no verified
identity.

A 4-digit code has 10,000 combinations and is spoken aloud, so it is a weak
secret. It proves *possession*, not *identity*. Someone who overhears a code, or
who is willing to brute-force against a name and a date, can cancel that
appointment. Five wrong guesses lock the guesser out for an hour; that makes
brute force impractical in a demo, not impossible, and someone with many source
addresses regains parallelism.

The lockout is charged to the caller — the pair (source IP, name asked about) —
and never to the appointment. Spec v3.0 said per-appointment, and that was a
hole: a name is not a secret and neither is a plausible date, so anyone able to
guess both could deliberately fail five times and lock a real patient out of
their own booking. The defence would have been the cheapest attack in the
system. See the revision note under C-34 in `spec.md`.

Production would add phone verification at booking time and the reference
delivered by SMS rather than spoken.

**Demo data resets on redeploy.** The database is ephemeral by decision: it
rebuilds from a synthetic seed on every cold start. Bookings made during a
session are real and fully functional within that session and do not survive a
restart. No real patient data, no real phone number, and no provider key exists
anywhere in this repository.

## Running it

```bash
uv sync
uv run python scripts/gen_keys.py     # prints keys for a local .env — do not commit
uv run uvicorn app.main:app --reload
```

Without a `.env`, a development boot generates ephemeral keys and says so in the
log. Under `ENV=production` every key is mandatory and `DEMO_MODE=true` refuses
to start.

### The text tester

```bash
uv sync --group tester
uv run streamlit run tester/app.py
```

The whole flow — book and cancel — in text, so the authority check can be
debugged without a microphone in the way. It signs every request with the
`tester` channel secret over HTTP, exactly as the phone and web channels do:
there is no privileged path, no test-only endpoint, and no way to cancel without
the reference. It refuses to run under `ENV=production`.

The panel on the right shows each tool call with its arguments, status and
latency, plus the audit rows the conversation produced. The reference is masked
in that log — a call log is a transcript, and a reference must not outlive the
moment it was disclosed in. Audit rows are read straight from the database over a
read-only connection rather than through an endpoint, because an `/audit`
endpoint built for the tester would be exactly the extra surface F9 forbids.

### A walk through the UI

Every button is one signed call to `/tools/*` and nothing else. The UI holds no
rule about who may do what — it collects a field, posts it, and renders what
came back. Reading it is therefore a reasonable way to read the tool surface.

**The sidebar** gates the rest. `Start a call` posts `create_session` and hands
back a session id, a state, and the disclosure the caller must hear. Until that
lands the page stops, because every other tool needs a session. It also mints a
fresh call id, which is what the per-call budget is keyed on.

**Tab 1 — Every turn.** Both tools here run on *every* turn rather than
belonging to a flow, which is why they sit above the other two tabs.
`screen_turn` is the F10 pre-filter: pure Python, no provider in its path. Type
a sentence about chest pain and the verdict comes back `emergency` with
`blocks_flow` set, and the session moves to `ESCALATED_EMERGENCY` — after which
booking and cancelling are refused on that session, which is the point.
`resolve_date` turns "next Tuesday" into a date in the clinic's timezone, on the
server; an ambiguous phrase returns a clarification rather than a guess.

**Tab 2 — Book.** Three steps, and the order is load-bearing:

1. `search_doctors` by specialty or by name, returning a list numbered from 1.
   Two doctors matching one name comes back `ambiguous`, and the server declines
   to pick — it never names both aloud either.
2. `get_available_slots` for a **doctor ordinal**, returning slots numbered
   from 1.
3. `book_appointment` for a **slot ordinal** and a patient name.

No tool takes a database identifier. An ordinal means "the nth item in the list
this server offered *this session*, a moment ago" — it is resolved against the
offer stored on the session, not against a table. Skip step 2, or pass an
ordinal outside the offered list, and the call is refused with 403 before
anything is written. That is not a validation error; it is the offer-scoping
check that `evals/` exercises as `attack_idor_through_an_unoffered_ordinal`.

On success the reference appears once, in green. It is the only time it is ever
shown.

**Tab 3 — Cancel.** Name, date and reference, matched in one server-side step.

The digit buffer above the reference field models the failure it exists for: on
a phone, people read four digits with a pause in the middle, and VAD cuts the
turn. `append_reference_digits` accumulates fragments server-side, so `"77"`
then `"1"` then `"3"` arrives as a readback of `7-7-1-3` that survives the cut.
Two exhausted retries hand off rather than looping.

Then attempt a cancellation, and attempt it wrong several times — wrong name,
wrong date, wrong reference, a patient who never existed. Every one of them
returns the same 403 with the same sentence. That uniformity is the feature: a
caller who cannot tell which field was wrong cannot use the endpoint to discover
what exists.

**The right panel** is where the two audiences separate. The call log is what a
transcript may hold, so the reference is masked in it. The audit rows below are
what the transcript may not: `cancel_appointment · denied · no_match`, one row
per attempt, allowed or denied. The caller gets one uniform sentence; the reason
lives only here. When something is refused and you want to know why, this panel
is the answer and the response body never will be.

One caveat on that panel: it opens the SQLite file directly, so it only works
when the tester and the API share a machine. Elsewhere it reports that the audit
log is unavailable rather than inventing an endpoint to fetch it.

**A round trip, in order:** start a call; screen an emergency and watch the flow
stop; start a fresh call; search, get slots, book; note the reference; attempt a
cancellation with the wrong reference, then the wrong name, then the wrong date,
and compare the three replies; cancel properly; then read the audit panel, which
distinguishes every one of those attempts that the caller could not.

One thing that surprises everyone once: the tester shares an IP with you, and
F8 refuses a fourth call from one source in 24 hours. That is the spec's number
and it is not softened for the tester. Raise it locally instead —
`MAX_SESSIONS_PER_IP_PER_DAY=50` in your `.env`. Every limit is configuration;
none of them is a code path.

Raising it locally cannot change what the suite asserts. `tests/conftest.py`
pins the F8 budgets into the environment, which outranks `.env`, so the
adversarial tests run on the numbers `app/config.py` ships no matter what your
own file says — and `test_the_suite_runs_on_the_budgets_the_code_ships` fails if
that pin ever drifts from those defaults. A security suite that means something
different on each machine would be worse than one that is merely strict.

The budgets are counted in the database and survive a reconnect, deliberately
(C-23). The database itself does not: delete `data/voicebook.db` and restart,
and the budgets are gone with it — which is the intended way out of an exhausted
window, not a workaround.

## Checks

```bash
uv run pytest                                    # 600 tests
uv run pytest tests/adversarial                  # required before any commit
                                                 # touching app/security or app/tools
uv run python -m evals                           # the 25 scripted conversations
uv run python scripts/check_import_boundary.py   # C-19
uv run python scripts/check_sql_interpolation.py # C-11
uv run python scripts/check_client_bundle.py     # C-16 — no key in the browser
```

Ten of the twenty-five evals are attacks and they gate the build: they run under
`tests/adversarial/test_f11_evals.py`, each on its own database, and each ends
on an assertion about what the database holds rather than about what the agent
said. `uv run python -m evals --transcripts` prints the same run as a report.

Measured for F5's timing acceptance criterion (100 interleaved samples each,
matcher level): no-match and wrong-reference medians differ by **0.28 ms**, p95
by **0.61 ms**, against a 20 ms budget. Interleaving matters — timing the two
arms in separate batches lets machine drift land on whichever runs second and
reads as a 60 ms leak that is not there.

## Layout

```
app/            FastAPI — the only trusted zone
  models/       SQLAlchemy
  services/     slots, state machine, sessions, digits, booking, directory,
                dates, safety
  tools/        /tools/* endpoints — thin, no logic
  security/     HMAC request auth, AES-GCM, reference match, abuse budgets,
                transcript redaction
  web/          room tokens and the browser's config — the only unauthenticated
                surface, and it hands out nothing but a 60-second room key
  db/           engine, WAL, synthetic seed
agent/          the voice layer — an HTTP client and nothing else from this
                codebase (CI-enforced)
  pipecat/      web channel; the browser bundle holds no key of any kind
  vapi/         phone channel; outbound absent, duration capped both sides
tester/         Streamlit text tester — HTTP client only, no app imports
evals/          25 scripted conversations, 15 happy and 10 attacks
tests/
  unit/         F0, F1, F2, F5, F6, F7, F11 redaction, configuration guards
  contract/     422 and 403 per mutating endpoint; the tester's signed path;
                the web and phone agents, including web/phone parity
  adversarial/  existence oracle, brute force, injection, homonym, rate
                limits, safety, cancellation, idempotency, observability,
                the eval suite, CI guards
scripts/        the three CI guards and a key generator
spec.md         the specification this is built against
```

See `spec.md` §8 for the trust-boundary diagram and §4 for the findings table.
