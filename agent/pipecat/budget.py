"""What one address may cost this process (F8, F12 — C-07, C-23, C-34).

`/api/offer` is unauthenticated by necessity: the browser holds no channel
secret and must not be given one. What it holds is a room token, and until this
file existed that was the only thing standing between a stranger and an
unbounded amount of work.

Two costs, and the second is the expensive one.

**Amplification.** Every offer makes this process send a *signed* request into
the trusted zone. Measured before this was written: thirty anonymous posts
produced thirty signed requests and not one 429. Cheap per request, and free to
the sender, which is the wrong shape.

**A pipeline per offer.** An offer that gets past the token check builds a
pipeline — a Silero load, a 120MB Piper voice, a peer connection, and from then
on Groq inference per turn. And a room token is *not* single-use: within its
sixty seconds it can be presented as often as you like. One minted token was
therefore worth an unbounded number of live bots, which is C-07's
denial-of-wallet with the wallet held open by a sixty-second string.

So, three limits, and the order they are applied in matters as much as the
numbers:

1. **Per address, per window.** Checked *before* the token is verified, so it
   costs the API nothing and — the part worth being careful about — so a 429
   says nothing about the token. A budget checked after verification would tell
   a prober their token was the good part.
2. **Concurrent calls, globally.** The demo's real ceiling. Inference is billed
   by the turn and this is a portfolio demo on a free tier.
3. **One live call per room.** A room token authorises "one browser to join one
   room for one minute" (`app/web/tokens.py`), so a second live call in the same
   room contradicts what the token says. A reconnect is the common case, though,
   not an attack — so a new offer for a live room **replaces** the old call
   rather than being refused. That keeps C-23 true (a reconnection resets no
   budget) while capping what one token can hold open at one.

Nothing here is an authority decision. It does not know who is calling, cannot
reach a record, and answers exactly one question: may this process spend
resources on this request. The budgets that decide what may happen to an
appointment are server-side, in `app/security/rate_limit.py`, and this does not
duplicate or weaken them.
"""

from __future__ import annotations

import os
import time
from collections import deque
from dataclasses import dataclass, field

# A reconnecting browser legitimately offers more than once — a network blip, a
# laptop lid, a refresh — so this is not tight. It is a flood ceiling, not a
# call quota; the call quota is the concurrency limit below.
DEFAULT_MAX_OFFERS_PER_IP = 12
DEFAULT_WINDOW_SECONDS = 3600

# Every concurrent call is a live model. Three is a demo, not a service.
DEFAULT_MAX_CONCURRENT_CALLS = 3

REFUSED_PER_IP = "per_ip"
REFUSED_CONCURRENT = "concurrent"
ADMITTED = "ok"


def _from_env(name: str, default: int) -> int:
    try:
        value = int(os.environ.get(name, default))
    except ValueError:
        return default
    return value if value > 0 else default


@dataclass(frozen=True)
class Verdict:
    """Admitted, or refused with a reason this process logs and never speaks.

    The caller is told "busy" whichever limit it was. Which budget somebody
    tripped is a fact about this server's configuration, and a prober who learns
    it learns which one to work around.
    """

    admitted: bool
    reason: str

    def __bool__(self) -> bool:
        return self.admitted


@dataclass
class OfferBudget:
    """Per-process, in memory, and that is the right scope.

    Deliberately not in the database. This protects *this process's* CPU and
    memory from *this process's* callers; it is the same kind of thing as the
    body-size cap, not the same kind of thing as "how many appointments may this
    name book today". Putting it in the database would put a write on the path
    of every offer, and give an attacker a way to make the API do work by
    talking to the agent — which is the shape this is here to prevent.
    """

    max_offers_per_ip: int = field(
        default_factory=lambda: _from_env("VB_MAX_OFFERS_PER_IP", DEFAULT_MAX_OFFERS_PER_IP)
    )
    window_seconds: int = field(
        default_factory=lambda: _from_env("VB_OFFER_WINDOW_SECONDS", DEFAULT_WINDOW_SECONDS)
    )
    max_concurrent_calls: int = field(
        default_factory=lambda: _from_env(
            "VB_MAX_CONCURRENT_CALLS", DEFAULT_MAX_CONCURRENT_CALLS
        )
    )

    _offers: dict[str, deque[float]] = field(default_factory=dict, repr=False)
    _live: dict[str, object] = field(default_factory=dict, repr=False)

    # ------------------------------------------------------------- admission

    def admit(self, *, client_ip: str, room: str, now: float | None = None) -> Verdict:
        """Decide, and charge the offer if it is admitted.

        Charged on the attempt, not on success. An offer that turns out to carry
        a forged token still cost this process a signed request into the trusted
        zone, and a budget that only counts the successes is a budget an
        attacker never touches.
        """
        now = time.time() if now is None else now

        seen = self._offers.setdefault(client_ip, deque())
        cutoff = now - self.window_seconds
        while seen and seen[0] < cutoff:
            # Bounded by the window, not by a count: an entry older than the
            # window can never refuse anything, so it is not worth keeping.
            seen.popleft()

        if len(seen) >= self.max_offers_per_ip:
            return Verdict(False, REFUSED_PER_IP)

        # A room that is already live is not a new call — it is the same caller
        # reconnecting, and replacing their own call costs no extra slot.
        if room not in self._live and len(self._live) >= self.max_concurrent_calls:
            return Verdict(False, REFUSED_CONCURRENT)

        seen.append(now)
        return Verdict(True, ADMITTED)

    # ---------------------------------------------------------- live calls

    def register(self, room: str, connection: object) -> object | None:
        """Record a live call. Returns the connection it displaced, if any.

        The caller closes what comes back. This class holds no event loop and
        starts no task, so it cannot do it itself — and a budget that quietly
        awaited something would be a budget that could hang an offer.
        """
        displaced = self._live.get(room)
        self._live[room] = connection
        return displaced

    def release(self, room: str, connection: object | None = None) -> None:
        """Forget a call that has ended.

        `connection` guards against the late-close race: a replaced call's
        "closed" handler fires *after* its replacement registered, and a blind
        pop would free the room while the new call is still running.
        """
        current = self._live.get(room)
        if current is None:
            return
        if connection is not None and current is not connection:
            return
        del self._live[room]

    @property
    def live_calls(self) -> int:
        return len(self._live)


__all__ = [
    "ADMITTED",
    "DEFAULT_MAX_CONCURRENT_CALLS",
    "DEFAULT_MAX_OFFERS_PER_IP",
    "DEFAULT_WINDOW_SECONDS",
    "OfferBudget",
    "REFUSED_CONCURRENT",
    "REFUSED_PER_IP",
    "Verdict",
]
