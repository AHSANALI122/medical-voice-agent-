# Setup

The confusing part of this project is not any one step — it is not knowing which
steps you still owe. So the whole of it is below, in the order it matters, and
each phase ends somewhere you can stop.

**The single most useful thing to know:** everything except live audio runs with
zero provider keys. The tests, the 25 evals, the Streamlit tester, the whole
booking and cancellation flow. Spec §10 says to perfect the flow in text before
adding audio, and the setup is arranged so you can.

At any point, this tells you where you stand:

```bash
uv run python scripts/doctor.py
```

---

## Phase 1 — text mode (no signup, no keys, ~2 minutes)

```bash
uv sync --group dev --group tester
uv run python scripts/init_env.py
uv run python scripts/doctor.py
```

`init_env.py` generates the six 32-byte keys and the Vapi webhook secret. Nobody
issues these — they are random bytes, and the script makes them. It never
overwrites a value that is already set, so it is safe to re-run.

> **Do not use `>> .env` in PowerShell.** Windows PowerShell 5.1 writes UTF-16,
> and appending that to a UTF-8 `.env` produces variable names nothing can parse
> — the symptom is a key that looks present and behaves as absent. Use
> `init_env.py`, which writes UTF-8. `doctor.py` detects the damage if it has
> already happened.

Now everything works:

```bash
uv run pytest                              # 586 tests
uv run python -m evals                     # 25 scripted conversations
uv run python -m evals --transcripts       # the same run, as a report

uv run uvicorn app.main:app --port 8000    # terminal 1
uv run streamlit run tester/app.py         # terminal 2 -> localhost:8501
```

You can stop here. This is a complete, attackable system: book, cancel, brute
force a reference, probe for existence, trigger an emergency. It just has no
microphone.

---

## Phase 2 — the phone channel (Vapi)

Three things have to line up: a public URL, a shared secret in two places, and
an assistant that points at both.

### 1. Expose the webhook

Vapi cannot reach `127.0.0.1`. Pick either:

```bash
ngrok http 8001
# or
cloudflared tunnel --url http://localhost:8001
```

Your webhook URL is the `https://…` it prints, plus `/vapi/tools`.

On free ngrok this URL changes on every restart, and you have to re-point the
assistant each time. `cloudflared` with a named tunnel avoids that.

### 2. Start both processes

Two processes, not one, and deliberately so — if the webhook lived on the API,
"the boundary is a network hop" would be a comment rather than a fact.

```bash
uv run uvicorn app.main:app --port 8000                                  # terminal 1
uv run uvicorn agent.vapi.server:create_app --factory --port 8001        # terminal 2
```

Check both: `curl localhost:8000/healthz` and `curl localhost:8001/healthz`.

### 3. Push the assistant

Sign up at **dashboard.vapi.ai** (~$10 credit). Under **API Keys**, copy the
**private** key — not the public one.

Put it in `.env`:

```
VAPI_PRIVATE_KEY=your-private-key
```

Then:

```bash
# Look at it first. Needs no key at all.
uv run python scripts/push_vapi_assistant.py --url https://<tunnel>/vapi/tools --dry-run

# Send it.
uv run python scripts/push_vapi_assistant.py --url https://<tunnel>/vapi/tools
```

`.env` is gitignored, so this is safe — and it goes no further than that file.
`agent/env.py` keeps `VAPI_PRIVATE_KEY` on a denylist, so the **webhook server
never loads it**, even though it reads the same file. It is an admin credential
that creates and deletes assistants, and the webhook server is the one process
here that accepts posts from strangers.

If you leave it empty the script prompts for it instead — but only when it has a
real terminal. Inside a wrapper or a captured shell it tells you what it wants
rather than hanging on a keystroke nobody can send.

The script prints an assistant id. Keep it — later updates use
`--id <assistant-id>`.

### 4. Set the shared secret

This is the step people miss. Vapi does not issue this secret — **you already
have it**, in `.env` as `VB_VAPI_WEBHOOK_SECRET`:

```bash
grep VB_VAPI_WEBHOOK_SECRET .env
```

In the dashboard, open the assistant → **Server** settings → **Server URL
Secret** → paste that value verbatim.

Vapi sends it as the `X-Vapi-Secret` header on every call, and
`agent/vapi/webhook.py` verifies it. Wrong or missing, every tool call comes back
401 and the assistant will sound like it has lost its tools.

### 5. Test

Use **Talk to Assistant** in the dashboard. Tool calls appear in the webhook
terminal. No phone number is needed to test.

### About the phone number

Buy or import it in the dashboard, and enable it **only during a recording
window** (spec §2). Nothing in this repository sets a number, and
`push_vapi_assistant.py` cannot attach one — a script that could attach a number
is a script that could leave one attached.

### What Vapi supplies, and what you do

The phone pipeline runs on Vapi's side, so its STT and TTS keys live in *their*
dashboard, not your `.env`. Your `.env` needs exactly two things for this
channel: `VB_CHANNEL_SECRET_PHONE` and `VB_VAPI_WEBHOOK_SECRET`, both of which
`init_env.py` already generated.

---

## Phase 3 — the web channel (Pipecat)

**Pipecat has no API key.** It is an open-source Python library that runs in your
own process — `pip install pipecat-ai`, no signup, no bill. What needs keys are
the providers it wires together, and spec §1.2 chose them so that most need none:

| Piece | Choice | Key? |
|---|---|---|
| VAD | Silero, bundled | no |
| TTS | Piper, local | no — chosen because it has no free tier to lapse |
| Transport | Pipecat SmallWebRTC | no — no external media server |
| LLM | Groq | **yes** |
| STT | Groq Whisper, or Deepgram | **yes**, one of them |

Groq serves both the LLM and Whisper, so **one key** runs the web demo.

- **Groq** — console.groq.com → API Keys. Free tier, no card. `GROQ_API_KEY=gsk_…`
- **Deepgram** — console.deepgram.com → ~$200 signup credit. `DEEPGRAM_API_KEY=…`

Take Deepgram too if you intend to do what §1.2 asks and benchmark both on your
own accent. One is enough to run.

Put them in `.env` by hand (`init_env.py` leaves provider keys alone — it cannot
invent them), then install the audio stack in whichever environment serves calls.
`agent/pipecat/pipeline.py` raises `PipecatUnavailable` with the missing names
until it has what it needs.

Nothing here reaches the browser. `scripts/check_client_bundle.py` fails the
build if a provider key — or even the *name* of one — appears in anything served
to a page. The browser gets a room id and a 60-second token, and that is all it
is trusted with.

---

## The keys, in one table

| Variable | Where it comes from | Needed for |
|---|---|---|
| `VB_ENCRYPTION_KEY` | `init_env.py` | always |
| `VB_REFERENCE_HMAC_KEY` | `init_env.py` | always |
| `VB_CHANNEL_SECRET_WEB` / `_PHONE` / `_TESTER` | `init_env.py` | always |
| `VB_ROOM_TOKEN_KEY` | `init_env.py` | web channel |
| `VB_VAPI_WEBHOOK_SECRET` | `init_env.py`, then paste into Vapi | phone channel |
| `GROQ_API_KEY` | console.groq.com | live audio |
| `DEEPGRAM_API_KEY` | console.deepgram.com | live audio (optional) |
| `VAPI_PRIVATE_KEY` | Vapi dashboard → API Keys | pushing the assistant. In `.env`, but denylisted from the webhook process |

`.env` and every `.env.*` variant are gitignored, and `gitleaks` runs pre-commit
and in CI. No key is ever printed by any script here — presence and length only.

The pre-commit half needs installing once per clone — a hook file is not in the
repository, so a fresh clone has no hooks until you ask for them:

```bash
uv tool install pre-commit
pre-commit install
```

`.pre-commit-config.yaml` also carries the three trust-boundary guards, and runs
the adversarial suite when a commit touches `app/security/` or `app/tools/`. CI
(`.github/workflows/ci.yml`) runs all of it again on the server, because a hook
that `--no-verify` can skip is a convenience, not a control.

---

## When something is wrong

```bash
uv run python scripts/doctor.py
```

| Symptom | Cause |
|---|---|
| Every webhook call is 401 | The dashboard secret and `VB_VAPI_WEBHOOK_SECRET` differ |
| Webhook 401s even though they match | The webhook process was started before the secret was in `.env` — restart it |
| A key "is set" but nothing works | UTF-16 damage from `>> .env`; re-run `init_env.py` |
| `PipecatUnavailable` | Expected without the audio stack. Text mode is unaffected |
| Booking says the slot was taken | The demo database resets on every restart; re-seed happens at boot |
