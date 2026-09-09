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

from fastapi import Depends, HTTPException, status
from sqlalchemy.orm import Session as OrmSession

from app.db.base import db_session
from app.models import Session
from app.security.reference import UNIFORM_FAILURE_TEXT
from app.security.request_auth import AuthenticatedChannel, require_signed_request
from app.services.sessions import load_live_session

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

    def session(self, session_id: str) -> Session:
        record = load_live_session(
            self.db, session_id=session_id, channel=self.channel.name
        )
        if record is None:
            raise forbidden()
        return record


def get_authorizer(
    channel: AuthenticatedChannel = Depends(require_signed_request),
    db: OrmSession = Depends(db_session),
) -> Authorizer:
    return Authorizer(channel=channel, db=db)
