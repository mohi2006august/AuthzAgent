"""Rule-based intent parser.

It reads only the user's request and the trusted profile, and it is
deterministic: the same request and profile always yield the same record.
It is deliberately simple. It works from a fixed verb lexicon, resolves names
against the profile, and uses one-step pronoun resolution, and it fails
closed. When it cannot resolve a target it records the reference as
unresolved rather than guessing, so the capability set grants nothing for it.

Known blind spots (see the report's failure-mode section): verbs outside the
lexicon, recipients that exist only in retrieved data, and noun/verb ambiguity
beyond the determiner heuristic in :func:`_is_noun_use`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .constraints import HostAllowList, canonical_path
from .intent import Action, IntentRecord
from .profile import Profile

# ---------------------------------------------------------------------------
# entity patterns (applied to the raw request, then masked out)

_URL_RE = re.compile(r"https?://[^\s<>\"'()]+")
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_PATH_RE = re.compile(r"(?<![\w/.:~\-])(~?/[A-Za-z0-9._\-]+(?:/[A-Za-z0-9._\-]+)*/?)")
_QUOTE_RE = re.compile(r"(?<!\w)(?:'([^'\n]{1,80}?)'|\"([^\"\n]{1,80}?)\"|‘([^’\n]{1,80}?)’|“([^”\n]{1,80}?)”)(?!\w)")
_AMOUNT_RE = re.compile(
    r"([£$€])\s?(\d{1,3}(?:,\d{3})+(?:\.\d{1,2})?|\d+(?:\.\d{1,2})?)"
    r"|\b(\d+(?:\.\d{1,2})?)\s?(?:GBP|USD|EUR|pounds|dollars|euros)\b"
)
_EXT_RE = re.compile(r"(?<![\w/])\*?\.([A-Za-z0-9]{1,8})\b")
_TOKEN_RE = re.compile(r"⟦[A-Z]\d+⟧|[A-Za-z0-9]+(?:['’][A-Za-z]+)?|[^\sA-Za-z0-9]")
_ONE_ON_ONE_RE = re.compile(r"\b1:1\b|\bone-on-one\b", re.IGNORECASE)

# ---------------------------------------------------------------------------
# lexicon

_SEND = {"email", "send", "forward", "reply", "tell", "notify", "inform", "message", "cc", "share"}
_PAY = {"pay", "transfer", "reimburse", "remit", "wire", "settle", "refund"}
_DELETE = {"delete", "remove", "erase", "trash", "purge", "wipe"}
_WRITE = {"save", "write", "store", "update", "edit", "set", "change", "modify", "overwrite", "create", "put", "fix"}
_MOVE = {"move", "rename"}
_CREATE_EVENT = {"schedule", "book", "invite", "arrange"}
_CANCEL = {"cancel"}
_PHRASES: tuple[tuple[tuple[str, ...], str], ...] = (
    (("clean", "up"), "delete"),
    (("get", "rid", "of"), "delete"),
    (("clear", "out"), "delete"),
    (("set", "up"), "create_event"),
    (("call", "off"), "cancel"),
    (("add",), "add"),  # only meaningful with a calendar word; see _classify
)

# Words that can also be nouns ("the latest email", "a reply", "an invite").
_AMBIGUOUS = {"email", "reply", "message", "transfer", "schedule", "book", "change", "update", "set",
              "store", "share", "invite", "edit", "fix", "cc", "forward", "wire", "trash"}
_DETERMINERS = {"a", "an", "the", "this", "that", "these", "those", "my", "your", "his", "her", "our",
                "their", "its", "latest", "last", "recent", "previous", "next", "first", "new", "any",
                "each", "every", "some", "no", "whose", "which"}
_NOUN_FOLLOWERS = {"about", "from", "thread", "address", "chain", "inbox", "and", "or", "then",
                   ",", ".", ";", ":", "—", "-", "?", "!", ")"}
_NEGATORS = {"don't", "dont", "not", "never", "without", "no"}
_PRONOUNS = {"him", "her", "them"}
_BULK = {"all", "every", "everything", "any"}
_SEPARATELY = {"separately", "individually", "each"}
_SENTENCE_END = {".", "?", "!", ";"}

_FS_WORDS = {"file", "files", "folder", "folders", "document", "documents", "directory", "notes", "drive"}
_EMAIL_WORDS = {"inbox", "emails", "mail", "thread", "message", "messages"}
_PAYMENT_WORDS = {"invoice", "invoices", "balance", "payment", "payments", "bill", "bills"}
_CALENDAR_WORDS = {"calendar", "meeting", "meetings", "event", "events", "appointment", "schedule", "diary"}
_MEETING_WORDS = {"meeting", "event", "call", "appointment", "invite", "sync", "standup", "calendar"}


@dataclass
class _Token:
    text: str
    lower: str
    base: str  # lower-case with any possessive 's removed
    possessive: bool


@dataclass
class _Mention:
    start: int
    end: int  # exclusive
    contact_email: str | None
    payee_account: str | None
    name: str
    possessive: bool


@dataclass
class _Verb:
    index: int
    word: str
    kind: str  # send | pay | delete | write | move | create_event | cancel | add
    span_end: int | None = None  # for "let X know": recipients live strictly inside the span
    end: int = 0  # clause end (exclusive), filled in later


@dataclass
class _Draft:
    kind: str
    explicit: list[str] = field(default_factory=list)
    inferred: list[str] = field(default_factory=list)
    globs: list[tuple[str, str]] = field(default_factory=list)
    amount: float | None = None
    count: int = 1
    unresolved: list[str] = field(default_factory=list)
    evidence: str = ""


class RuleBasedParser:
    name = "rule-based/1"

    def __init__(self, profile: Profile):
        self.profile = profile
        self._aliases: list[tuple[tuple[str, ...], str, str | None, str | None]] = []
        for c in profile.contacts:
            for alias in {c.name, *c.aliases}:
                self._aliases.append((self._alias_tokens(alias), c.name, c.email, None))
        for p in profile.payees:
            for alias in {p.name, *p.aliases}:
                self._aliases.append((self._alias_tokens(alias), p.name, None, p.account))
        self._aliases.sort(key=lambda a: (-len(a[0]), a[0], a[1]))

    @staticmethod
    def _alias_tokens(alias: str) -> tuple[str, ...]:
        return tuple(t.lower() for t in _TOKEN_RE.findall(alias))

    # -- public ---------------------------------------------------------------

    def parse(self, request: str) -> IntentRecord:
        notes: list[str] = []
        masked, entities = self._mask(request, notes)
        tokens = [self._token(t) for t in _TOKEN_RE.findall(masked)]
        mentions = self._mentions(tokens)
        verbs = self._verbs(tokens, notes)

        drafts = [self._draft(v, tokens, mentions, entities, notes) for v in verbs]
        drafts = self._merge(_expand_moves([d for d in drafts if d is not None]))
        actions = tuple(self._finish(d) for d in drafts)

        paths = [p for key, p in entities.items() if key.startswith("P") and p is not None]
        read_paths = set(paths)
        for d in drafts:
            read_paths.update(directory for directory, _ in d.globs)
        hosts = sorted({str(h) for key, h in entities.items() if key.startswith("H")})
        read_domains = self._domains(request, tokens, drafts, bool(paths), bool(hosts))
        if "fs" in read_domains and not read_paths:
            read_paths.add(self.profile.home)
            notes.append(f"no path named; file reads default to {self.profile.home}")

        return IntentRecord(
            request=request,
            read_domains=tuple(sorted(read_domains)),
            read_paths=tuple(sorted(read_paths)),
            fetch_hosts=tuple(hosts),
            actions=actions,
            parser=self.name,
            notes=tuple(notes),
        )

    # -- masking ---------------------------------------------------------------

    def _mask(self, text: str, notes: list[str]) -> tuple[str, dict[str, object]]:
        entities: dict[str, object] = {}
        counters = {"U": 0, "E": 0, "P": 0, "Q": 0, "A": 0, "X": 0}

        def put(prefix: str, value: object) -> str:
            key = f"{prefix}{counters[prefix]}"
            counters[prefix] += 1
            entities[key] = value
            return f" ⟦{key}⟧ "

        def url(m: re.Match[str]) -> str:
            raw = m.group(0).rstrip(".,;:!?")
            host = HostAllowList.host_of(raw)
            if host:
                entities[f"H{counters['U']}"] = host
            else:
                notes.append(f"ignored URL {raw!r}: not a plain http(s) URL")
            return put("U", raw) + m.group(0)[len(raw):]

        def path(m: re.Match[str]) -> str:
            raw = m.group(1)
            stripped = raw.rstrip(".,;:-")
            trailing = raw[len(stripped):]
            value = stripped
            if value.startswith("~"):
                value = self.profile.home + value[1:]
            if len(value) > 1:
                value = value.rstrip("/")
            canonical = canonical_path(value)
            if canonical is None:
                notes.append(f"ignored non-canonical path {stripped!r}")
            return put("P", canonical) + trailing

        text = _URL_RE.sub(url, text)
        text = _EMAIL_RE.sub(lambda m: put("E", m.group(0).lower()), text)
        text = _PATH_RE.sub(path, text)
        text = _QUOTE_RE.sub(lambda m: put("Q", next(g for g in m.groups() if g is not None)), text)

        def amount(m: re.Match[str]) -> str:
            number = m.group(2) if m.group(2) is not None else m.group(3)
            return put("A", float(number.replace(",", "")))

        text = _AMOUNT_RE.sub(amount, text)
        text = _EXT_RE.sub(lambda m: put("X", m.group(1).lower()), text)
        return text, entities

    @staticmethod
    def _token(text: str) -> _Token:
        lower = text.lower().replace("’", "'")
        possessive = lower.endswith("'s") and len(lower) > 2
        return _Token(text, lower, lower[:-2] if possessive else lower, possessive)

    # -- mentions of people and payees ------------------------------------------

    def _mentions(self, tokens: list[_Token]) -> list[_Mention]:
        mentions: list[_Mention] = []
        i = 0
        while i < len(tokens):
            matched = None
            for alias, name, email, account in self._aliases:
                n = len(alias)
                window = tokens[i:i + n]
                if len(window) == n and all(
                    (t.base if k == n - 1 else t.lower) == a for k, (t, a) in enumerate(zip(window, alias))
                ):
                    matched = (n, name, email, account)
                    break
            if matched is None:
                i += 1
                continue
            n, name, email, account = matched
            # the same span may name both a contact and a payee (e.g. a colleague you reimburse)
            for alias, other_name, other_email, other_account in self._aliases:
                if len(alias) == n and other_name == name and all(
                    (t.base if k == n - 1 else t.lower) == a for k, (t, a) in enumerate(zip(tokens[i:i + n], alias))
                ):
                    email = email or other_email
                    account = account or other_account
            mentions.append(_Mention(i, i + n, email, account, name, tokens[i + n - 1].possessive))
            i += n
        return mentions

    # -- verbs ------------------------------------------------------------------

    def _verbs(self, tokens: list[_Token], notes: list[str]) -> list[_Verb]:
        verbs: list[_Verb] = []
        i = 0
        while i < len(tokens):
            tok = tokens[i]
            found: _Verb | None = None
            width = 1
            for phrase, kind in _PHRASES:
                n = len(phrase)
                if tuple(t.lower for t in tokens[i:i + n]) == phrase and (n > 1 or kind == "add"):
                    found, width = _Verb(i, " ".join(phrase), kind), n
                    break
            if found is None and tok.lower == "let":
                end = self._sentence_end(tokens, i)
                for j in range(i + 1, min(end, i + 8)):
                    if tokens[j].lower == "know":
                        found, width = _Verb(i, "let … know", "send", span_end=j), j - i + 1
                        break
            if found is None:
                kind = self._lexicon_kind(tok.lower)
                if kind is not None and not (tok.lower in _AMBIGUOUS and _is_noun_use(tokens, i)):
                    found = _Verb(i, tok.lower, kind)
            if found is not None:
                nxt = tokens[i + 1].lower if i + 1 < len(tokens) else ""
                if found.kind == "send" and nxt == "me":
                    found = None  # "tell me", "let me know": an answer to the user, not a message
                elif _negated(tokens, i):
                    notes.append(f"negated verb {found.word!r} ignored")
                    found = None
            if found is not None:
                verbs.append(found)
            i += width if found is not None else 1
        for k, verb in enumerate(verbs):
            next_start = verbs[k + 1].index if k + 1 < len(verbs) else len(tokens)
            verb.end = min(next_start, self._sentence_end(tokens, verb.index))
        return verbs

    @staticmethod
    def _lexicon_kind(word: str) -> str | None:
        for lexicon, kind in ((_SEND, "send"), (_PAY, "pay"), (_DELETE, "delete"), (_WRITE, "write"),
                              (_MOVE, "move"), (_CREATE_EVENT, "create_event"), (_CANCEL, "cancel")):
            if word in lexicon:
                return kind
        return None

    @staticmethod
    def _sentence_end(tokens: list[_Token], start: int) -> int:
        for j in range(start, len(tokens)):
            if tokens[j].lower in _SENTENCE_END:
                return j
        return len(tokens)

    # -- one verb -> one draft action ---------------------------------------------

    def _draft(self, verb: _Verb, tokens: list[_Token], mentions: list[_Mention],
               entities: dict[str, object], notes: list[str]) -> _Draft | None:
        lo, hi = verb.index, verb.end
        words = {t.lower for t in tokens[lo:hi]}
        keys = [t.text[1:-1] for t in tokens[lo:hi] if t.text.startswith("⟦")]
        paths = [entities[k] for k in keys if k.startswith("P") and entities[k] is not None]
        emails = [entities[k] for k in keys if k.startswith("E")]
        amounts = [entities[k] for k in keys if k.startswith("A")]
        extensions = [str(entities[k]) for k in keys if k.startswith("X")]
        evidence = self._evidence(tokens[lo:hi], entities)
        has_calendar = bool(words & _CALENDAR_WORDS) or bool(_ONE_ON_ONE_RE.search(evidence))
        has_meeting = bool(words & _MEETING_WORDS)

        kind = verb.kind
        if kind == "send" and verb.word == "send" and amounts:
            kind = "pay"
        if kind == "write" and verb.word == "write" and not paths:
            kind = "send" if self._people(mentions, lo, hi) else "write"
        if kind == "add":
            if not has_calendar:
                return None
            kind = "create_event"
        if kind == "write" and verb.word in ("put", "create"):
            if has_calendar or (verb.word == "create" and has_meeting):
                kind = "create_event"
        if kind == "create_event" and verb.word == "set up" and not has_meeting:
            notes.append("'set up' without a meeting word ignored")
            return None
        if kind == "delete" and not paths and not extensions and has_calendar:
            kind = "cancel"

        if kind == "send":
            return self._people_draft("send_email", verb, tokens, mentions, emails, evidence, words, notes)
        if kind == "create_event":
            return self._people_draft("create_event", verb, tokens, mentions, emails, evidence, words, notes)
        if kind == "pay":
            return self._payment_draft(verb, tokens, mentions, amounts, evidence, notes)
        if kind == "cancel":
            count = self.profile.bulk_limit if words & _BULK else 1
            return _Draft("cancel_event", count=count, evidence=evidence)
        if kind == "move":
            if len(paths) < 2:
                notes.append(f"'{verb.word}' without source and destination paths ignored")
                return None
            return _Draft("move", explicit=[paths[0], paths[-1]], evidence=evidence)
        if kind == "write":
            if not paths:
                notes.append(f"'{verb.word}' without a path ignored")
                return None
            return _Draft("write_file", explicit=list(paths), count=len(set(paths)), evidence=evidence)
        if kind == "delete":
            if words & _BULK and paths:
                pattern = f"*.{extensions[0]}" if extensions else "*"
                globs = [(p, pattern) for p in paths]
                return _Draft("delete_file", globs=globs, count=self.profile.bulk_limit, evidence=evidence)
            if not paths:
                notes.append(f"'{verb.word}' without a path ignored")
                return None
            return _Draft("delete_file", explicit=list(paths), count=len(set(paths)), evidence=evidence)
        return None

    def _people(self, mentions: list[_Mention], lo: int, hi: int) -> list[_Mention]:
        return [m for m in mentions if lo <= m.start < hi and not m.possessive and m.contact_email]

    def _people_draft(self, kind: str, verb: _Verb, tokens: list[_Token], mentions: list[_Mention],
                      emails: list[object], evidence: str, words: set[str], notes: list[str]) -> _Draft:
        lo, hi = verb.index, (verb.span_end if verb.span_end is not None else verb.end)
        draft = _Draft(kind, evidence=evidence)
        draft.explicit.extend(str(e) for e in emails)
        for m in self._people(mentions, lo, hi):
            draft.explicit.append(m.contact_email)  # type: ignore[arg-type]
            notes.append(f"resolved {' '.join(t.text for t in tokens[m.start:m.end])!r} -> {m.contact_email}")
        for j in range(lo, hi):
            if tokens[j].lower in _PRONOUNS:
                ref = self._antecedent(mentions, j, want="contact")
                if ref is not None:
                    draft.inferred.append(ref.contact_email)  # type: ignore[arg-type]
                    notes.append(f"pronoun {tokens[j].text!r} -> {ref.name}")
                else:
                    draft.unresolved.append(tokens[j].text)
        if kind == "send_email" and not draft.explicit and not draft.inferred and not draft.unresolved:
            draft.unresolved.append(evidence)
        if kind == "send_email" and words & _SEPARATELY:
            draft.count = max(1, len(set(draft.explicit + draft.inferred)))
        if draft.unresolved and kind == "send_email":
            notes.append(f"unresolved recipient in {evidence!r}")
        return draft

    def _payment_draft(self, verb: _Verb, tokens: list[_Token], mentions: list[_Mention],
                       amounts: list[object], evidence: str, notes: list[str]) -> _Draft:
        lo, hi = verb.index, verb.end
        draft = _Draft("transfer", evidence=evidence)
        for m in mentions:
            if lo <= m.start < hi and m.payee_account:
                draft.explicit.append(m.payee_account)
                notes.append(f"resolved payee {m.name!r} -> {m.payee_account}")
        if not draft.explicit:
            for j in range(lo, hi):
                if tokens[j].lower in _PRONOUNS:
                    ref = self._antecedent(mentions, j, want="payee")
                    if ref is not None:
                        draft.inferred.append(ref.payee_account)  # type: ignore[arg-type]
                        notes.append(f"pronoun {tokens[j].text!r} -> payee {ref.name}")
                        break
        if not draft.explicit and not draft.inferred:
            draft.unresolved.append(evidence)
            notes.append(f"unresolved payee in {evidence!r}")
        if amounts:
            draft.amount = float(max(amounts))  # type: ignore[arg-type]
        draft.count = max(1, len(set(draft.explicit + draft.inferred)))
        return draft

    @staticmethod
    def _antecedent(mentions: list[_Mention], index: int, want: str) -> _Mention | None:
        for m in reversed(mentions):
            if m.end <= index and (m.contact_email if want == "contact" else m.payee_account):
                return m
        return None

    @staticmethod
    def _evidence(tokens: list[_Token], entities: dict[str, object]) -> str:
        out = []
        for t in tokens:
            if t.text.startswith("⟦"):
                key = t.text[1:-1]
                value = entities.get(key)
                if key.startswith("X"):
                    out.append(f".{value}")
                else:
                    out.append(str(value) if value is not None else "<invalid path>")
            else:
                out.append(t.text)
        return " ".join(out)

    # -- merging and finishing ------------------------------------------------------

    @staticmethod
    def _merge(drafts: list[_Draft]) -> list[_Draft]:
        """Adjacent verbs of one kind where one side names nobody are one action.

        "Reply ... and tell them" is one message; "put it on my calendar and
        invite her" is one event. "Email Alice and email Bob" stays two.
        """
        merged: list[_Draft] = []
        for d in drafts:
            prev = merged[-1] if merged else None
            if (
                prev is not None
                and prev.kind == d.kind
                and d.kind in ("send_email", "create_event", "transfer")
                and (not prev.explicit or not d.explicit)
            ):
                prev.explicit += d.explicit
                prev.inferred += d.inferred
                prev.unresolved += d.unresolved
                prev.count = max(prev.count, d.count)
                if d.amount is not None:
                    prev.amount = max(prev.amount or 0.0, d.amount)
                prev.evidence = f"{prev.evidence} … {d.evidence}"
                continue
            merged.append(d)
        return merged

    def _finish(self, d: _Draft) -> Action:
        targets = tuple(sorted(set(d.explicit + d.inferred)))
        unresolved = () if targets else tuple(dict.fromkeys(d.unresolved))
        ceiling, source = None, None
        if d.kind == "transfer":
            if d.amount is not None:
                ceiling, source = d.amount, "request"
            else:
                ceiling, source = self.profile.default_amount_ceiling, "policy"
        return Action(
            kind=d.kind,
            targets=targets,
            globs=tuple(sorted(set(d.globs))),
            amount_ceiling=ceiling,
            ceiling_source=source,
            count=d.count,
            unresolved=unresolved,
            evidence=d.evidence,
        )

    def _domains(self, request: str, tokens: list[_Token], drafts: list[_Draft], has_paths: bool,
                 has_urls: bool) -> set[str]:
        domains: set[str] = set()
        lowers = [t.lower for t in tokens]
        if has_paths or set(lowers) & _FS_WORDS:
            domains.add("fs")
        for i, word in enumerate(lowers):
            if word in _EMAIL_WORDS or (word in ("email", "reply") and _is_noun_use(tokens, i)):
                domains.add("email")
            if word in ("forward", "reply") and not _is_noun_use(tokens, i):
                domains.add("email")
        if set(lowers) & _PAYMENT_WORDS:
            domains.add("payments")
        if set(lowers) & _CALENDAR_WORDS or _ONE_ON_ONE_RE.search(request):
            domains.add("calendar")
        if has_urls:
            domains.add("web")
        for d in drafts:
            if d.kind == "transfer":
                domains.add("payments")
            if d.kind in ("create_event", "cancel_event"):
                domains.add("calendar")
            if d.kind in ("write_file", "delete_file", "move"):
                domains.add("fs")
        return domains


def _is_noun_use(tokens: list[_Token], i: int) -> bool:
    prev = tokens[i - 1] if i > 0 else None
    nxt = tokens[i + 1].lower if i + 1 < len(tokens) else None
    if prev is not None and (prev.lower in _DETERMINERS or prev.possessive):
        return True
    return nxt is None or nxt in _NOUN_FOLLOWERS


def _negated(tokens: list[_Token], i: int) -> bool:
    return any(tokens[j].lower in _NEGATORS for j in range(max(0, i - 2), i))


def _expand_moves(drafts: list[_Draft]) -> list[_Draft]:
    """A move is a write to the destination plus a delete of the source."""
    out: list[_Draft] = []
    for d in drafts:
        if d.kind == "move":
            src, dst = d.explicit
            out.append(_Draft("write_file", explicit=[dst], evidence=d.evidence))
            out.append(_Draft("delete_file", explicit=[src], evidence=d.evidence))
        else:
            out.append(d)
    return out