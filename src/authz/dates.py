"""Resolving date expressions in a request against the (trusted) current date."""

from __future__ import annotations

import datetime as dt
import re

_ISO = re.compile(r"\b(\d{4})-(\d{2})-(\d{2})\b")
_WEEKDAYS = ("monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday")
_WORD = re.compile(r"\b(today|tomorrow|monday|tuesday|wednesday|thursday|friday|saturday|sunday)(?:['’]s)?\b",
                   re.IGNORECASE)


def resolve_dates(text: str, today: str | None) -> list[str]:
    """Every date the text names, as YYYY-MM-DD, in order of appearance.

    Weekday names mean the next such day strictly after ``today`` ("Friday" said
    on a Friday means next week). Relative words resolve only when ``today`` is
    known; otherwise they are skipped, so the grant fails closed.
    """
    found: list[tuple[int, str]] = []
    for m in _ISO.finditer(text):
        try:
            found.append((m.start(), dt.date(int(m.group(1)), int(m.group(2)), int(m.group(3))).isoformat()))
        except ValueError:
            continue
    if today:
        base = dt.date.fromisoformat(today)
        for m in _WORD.finditer(text):
            word = m.group(1).lower()
            if word == "today":
                day = base
            elif word == "tomorrow":
                day = base + dt.timedelta(days=1)
            else:
                ahead = (_WEEKDAYS.index(word) - base.weekday()) % 7 or 7
                day = base + dt.timedelta(days=ahead)
            found.append((m.start(), day.isoformat()))
    return [d for _, d in sorted(found)]
