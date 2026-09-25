"""Trusted state the mediator may consult: structured, server-authenticated metadata.

Some objects cannot be named in advance. "Cancel my 1:1 with Bob on Friday" does
not tell us the event id. It does tell us two facts the calendar server can
vouch for: the event starts on Friday, and Bob is an attendee.
:class:`TrustedState` exposes exactly those structured fields and nothing else:
no titles, no descriptions, no bodies. Those can be written by anyone who sends
an invite, so the mediator still never reads free text.

The trust assumption is the same as for any reference monitor that reads file
metadata. The tool server is in the trusted base (a compromised tool server is
out of scope in the threat model), and the fields used are set by the object's
owner. For an event, those are its organiser's choices of time and attendees.
An attacker who organises their own event can make it match, but cancelling
that event harms no one but the attacker.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class EventFacts:
    event_id: str
    start: str  # ISO 8601, e.g. 2026-10-02T09:30
    attendees: tuple[str, ...]
    organizer: str | None = None


class TrustedState(Protocol):
    def event(self, event_id: str) -> EventFacts | None: ...
