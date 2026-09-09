# VoiceBook

A voice agent for medical appointment booking, designed on the assumption that
the language model driving it is compromised.

**Status:** F0–F5 implemented (schema, slot engine, state machine, tool
endpoints, request authentication, and the booking-reference authority spine).
F6–F17 are specified in `spec.md` and not yet built.

---

## The design in four lines

1. **Authority never flows through the model.** The LLM cannot cancel anything.
   It relays a name, a date and four digits; the server decides. There is no
   privilege in the prompt to escalate.
2. **The trust boundary is enforced by CI, not by discipline.** Nothing under
   `agent/` may import `app/services`, `app/db`, `app/models`, `app/security` or
   `app/tools`. `scripts/check_import_boundary.py` fails the build if it does.
3. **Validation is not authorization.** Pydantic rejects malformed input with
   422. A separate layer rejects unauthorized input with 403. Every mutating
   endpoint asserts both, independently.
4. **The security scope is stated, not implied.** See below.

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

## Checks

```bash
uv run pytest                                   # 129 tests
uv run pytest tests/adversarial                 # required before any commit
                                                # touching app/security or app/tools
uv run python scripts/check_import_boundary.py  # C-19
uv run python scripts/check_sql_interpolation.py # C-11
```

Measured for F5's timing acceptance criterion (100 interleaved samples each,
matcher level): no-match and wrong-reference medians differ by **0.28 ms**, p95
by **0.61 ms**, against a 20 ms budget. Interleaving matters — timing the two
arms in separate batches lets machine drift land on whichever runs second and
reads as a 60 ms leak that is not there.

## Layout

```
app/            FastAPI — the only trusted zone
  models/       SQLAlchemy
  services/     slot engine, state machine, sessions, digits, booking
  tools/        /tools/* endpoints — thin, no logic
  security/     HMAC request auth, AES-GCM, reference match, abuse budgets
  db/           engine, WAL, synthetic seed
tests/
  unit/         F0, F1, F2, F5, configuration guards
  contract/     422 and 403 asserted separately per mutating endpoint
  adversarial/  existence oracle, brute force, injection, homonym, CI guards
scripts/        the two CI guards and a key generator
spec.md         the specification this is built against
```

See `spec.md` §8 for the trust-boundary diagram and §4 for the findings table.
