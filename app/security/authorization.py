"""Authorization (C-36).

Separate layer, separate status code, separate tests. Pydantic has already run
by the time anything here executes: the request is well-formed, which says
nothing about whether it is allowed.

Two decisions live here:

  - session standing: the request must name a live session opened by this same
    authenticated channel. Failing that is 403, not 401 and not 422.
  - cancellation authority: name + date + reference matched in one server-side
    step (section 5.2). Every failure returns the same 403 with the same body.

Nothing here is expressible in prompt text, and nothing in agent/ can reach it.
"""

from __future__ import annotations

from dataclasses import dataclass

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session as OrmSession

from app.db.base import db_session
from app.models import Session
from app.observability import stamp
from app.security import rate_limit
from app.security.reference import UNIFORM_FAILURE_TEXT
from app.security.request_auth import AuthenticatedChannel, require_signed_request
from app.services.sessions import load_live_session
from app.services.state_machine import State

# A denied session and a denied cancellation say the same thing, so probing one
# endpoint teaches nothing about the other.
FORBIDDEN_DETAIL = UNIFORM_FAILURE_TEXT


def forbidden() -> HTTPException:
    return HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=FORBIDDEN_DETAIL)


@dataclass
class Authorizer:
    """Bound to one authenticated channel and one database session.

    Injected as a dependency, but invoked from inside the endpoint after
    validation, because the decision needs a validated field from the body.
    """

    channel: AuthenticatedChannel
    db: OrmSession
    # Carried so the session id and turn index can be stamped onto this
    # request's observation (F11). The Authorizer is the only place that has
    # both the request and a session it has just proved standing for.
    request: Request | None = None

    def session(self, session_id: str) -> Session:
        # F13 — checked before the session is loaded, so a call past its cap is
        # refused whether or not it names a session that exists. The answer is
        # the same 403 as every other denial: a caller who can tell "your call
        # ran too long" apart from "that session is not yours" has learned that
        # the session exists.
        try:
            rate_limit.require_call_within_duration(
                self.db, call_id=self.channel.call_id
            )
        except rate_limit.RateLimited:
            raise forbidden() from None

        record = load_live_session(
            self.db, session_id=session_id, channel=self.channel.name
        )
        if record is None:
            raise forbidden()
        if record.state == State.ESCALATED_EMERGENCY.value:
            # F10: escalation abandons the flow. Enforced here rather than in
            # the prompt, so an injected "actually, carry on with the booking"
            # has nothing to talk to. One-way, because ESCALATED_EMERGENCY is
            # terminal and no transition leaves it.
            raise forbidden()
        if self.request is not None:
            # Stamped only once standing is proved. A caller who names a session
            # they have no claim to must not get that id written into telemetry
            # under their own request — that would make the event table a place
            # to record which session ids somebody had been guessing at.
            stamp(self.request, session_id=record.id, turn=record.turn_count)
        return record


def get_authorizer(
    request: Request,
    channel: AuthenticatedChannel = Depends(require_signed_request),
    db: OrmSession = Depends(db_session),
) -> Authorizer:
    return Authorizer(channel=channel, db=db, request=request)
