"""Rule-based intent parser (version 2).

It reads only the user's request and the trusted profile, and it is
deterministic: the same request, profile and date always yield the same
record. It is deliberately simple. It works from a verb lexicon, resolves
names against the profile, uses clause-level pronoun resolution, and it fails
closed. When it cannot resolve a target it records the reference as
unresolved rather than guessing, so the capability set grants nothing for it.

Changes from version 1 (tag ``v1``), each driven by a failure in the
development data. That data is the original requests of t01–t40 plus the first
paraphrase set. The held-out set (``heldout`` in task.json) was not used.

* A stated amount is never replaced by the policy ceiling (F6), and several
  payees with several amounts are paired in order.
* "move/put/send £X to …" is a transfer.
* "them" resolves to everyone named in the nearest clause that names people.
* cancel_event carries the date and attendees named in its sentence, so the
  grant can bind the event through trusted calendar metadata (F2).
* Write and delete verbs can take a path that comes earlier in the sentence.
* Plural "<ext> files" in a folder is a bulk delete of ``*.<ext>``.
* More verbs: mail, respond, answer, pass (on), append, document, turn, relocate,
  clear, "take care of" (an invoice), "give … a heads-up". "Send X an invite"
  is an event, not an e-mail.
* The request's URLs are recorded, so web access can be limited to them (F3).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .constraints import HostAllowList, canonical_path
from .dates import resolve_dates
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
_SPACED_ISO = re.compile(r"\b(\d{4}) - (\d{2}) - (\d{2})\b")

# ---------------------------------------------------------------------------
# lexicon

_SEND = {"email", "send", "forward", "reply", "tell", "notify", "inform", "message", "cc", "share",
         "mail", "respond", "answer", "pass"}
_PAY = {"pay", "transfer", "reimburse", "remit", "wire", "settle", "refund"}
_DELETE = {"delete", "remove", "erase", "trash", "purge", "wipe", "clear"}
_WRITE = {"save", "write", "store", "update", "edit", "set", "change", "modify", "overwrite", "create", "put", "fix",
          "append", "document", "turn"}
_MOVE = {"move", "rename", "relocate"}
_CREATE_EVENT = {"schedule", "book", "invite", "arrange"}
_CANCEL = {"cancel"}
_PHRASES: tuple[tuple[tuple[str, ...], str], ...] = (
    (("clean", "up"), "delete"),
    (("get", "rid", "of"), "delete"),
    (("clear", "out"), "delete"),
    (("set", "up"), "create_event"),
    (("call", "off"), "cancel"),
    (("take", "care", "of"), "settle"),  # a payment only with an invoice/bill word; see _draft
    (("add",), "add"),  # an event with a calendar word, a write with a path; see _draft
)
_READ_REPLY = {"forward", "reply", "respond", "answer", "pass"}  # sending these needs the original message

# Words that can also be nouns ("the latest email", "a reply", "an invite").
_AMBIGUOUS = {"email", "reply", "message", "transfer", "schedule", "book", "change", "update", "set",
              "store", "share", "invite", "edit", "fix", "cc", "forward", "wire", "trash", "mail", "answer",
              "document", "clear", "turn", "pass"}
_DETERMINERS = {"a", "an", "the", "this", "that", "these", "those", "my", "your", "his", "her", "our",
                "their", "its", "latest", "last", "recent", "previous", "next", "first", "new", "any",
                "each", "every", "some", "no", "whose", "which", "one", "two", "three", "both",
                "by", "via", "per"}
_NOUN_FOLLOWERS = {"about", "from", "thread", "address", "chain", "inbox", "and", "or", "then",
                   "into", "on", "in", "with", "saying",
                   ",", ".", ";", ":", "—", "-", "?", "!", ")"}
_NEGATORS = {"don't", "dont", "not", "never", "without", "no"}
_BULK = {"all", "every", "everything", "any"}
_SEPARATELY = {"separately", "individually", "each"}
_SENTENCE_END = {".", "?", "!", ";"}
_INVITE_NOUNS = {"invite", "invitation"}
_BILL_WORDS = {"invoice", "invoices", "bill", "bills", "payment"}

_FS_WORDS = {"file", "files", "folder", "folders", "document", "documents", "directory", "notes", "drive"}
_EMAIL_WORDS = {"inbox", "emails", "emailed", "thread", "message", "messages"}
_EMAIL_NOUNS = {"email", "reply", "mail"}  # e-mail domain only when used as a noun
_PAYMENT_WORDS = {"invoice", "invoices", "balance", "payment", "payments", "bill", "bills"}
_CALENDAR_WORDS = {"calendar", "meeting", "meetings", "event", "events", "appointment", "schedule", "diary"}
_MEETING_WORDS = {"meeting", "event", "call", "appointment", "invite", "sync", "standup", "calendar",
                  "retro", "review", "demo", "workshop", "interview"}


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
    kind: str  # send | pay | delete | write | move | create_event | cancel | add | settle
    span_end: int | None = None  # "let X know", "give X a heads-up": recipients live inside the span
    end: int = 0  # clause end (exclusive)


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
    date: str | None = None


class RuleBasedParser:
    name = "rule-based/2"

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
        self._segments = self._make_segments(verbs, tokens)

        drafts: list[_Draft] = []
        for v in verbs:
            drafts.extend(self._draft(v, verbs, tokens, mentions, entities, notes))
        drafts = self._merge(_expand_moves(drafts))
        self._attach_request_amounts(drafts, entities, notes)
        actions = tuple(self._finish(d) for d in drafts)

        paths = [p for key, p in entities.items() if key.startswith("P") and p is not None]
        read_paths = set(paths)
        for d in drafts:
            read_paths.update(directory for directory, _ in d.globs)
        hosts = sorted({str(h) for key, h in entities.items() if key.startswith("H")})
        urls = sorted({str(entities[f"U{key[1:]}"]) for key in entities if key.startswith("H")})
        read_domains = self._domains(request, tokens, drafts, bool(paths), bool(hosts))
        if "fs" in read_domains and not read_paths:
            read_paths.add(self.profile.home)
            notes.append(f"no path named; file reads default to {self.profile.home}")

        return IntentRecord(
            request=request,
            read_domains=tuple(sorted(read_domains)),
            read_paths=tuple(sorted(read_paths)),
            fetch_hosts=tuple(hosts),
            fetch_urls=tuple(urls),
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

    def _matches(self, tokens: list[_Token], i: int, alias: tuple[str, ...]) -> bool:
        n = len(alias)
        window = tokens[i:i + n]
        return len(window) == n and all(
            (t.base if k == n - 1 else t.lower) == a for k, (t, a) in enumerate(zip(window, alias))
        )

    def _mentions(self, tokens: list[_Token]) -> list[_Mention]:
        mentions: list[_Mention] = []
        i = 0
        while i < len(tokens):
            matched = next(((len(a), name, email, acct) for a, name, email, acct in self._aliases
                            if self._matches(tokens, i, a)), None)
            if matched is None:
                i += 1
                continue
            n, name, email, account = matched
            # the same span may name both a contact and a payee (e.g. a colleague you reimburse)
            for alias, other_name, other_email, other_account in self._aliases:
                if len(alias) == n and other_name == name and self._matches(tokens, i, alias):
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
                if tuple(t.lower for t in tokens[i:i + n]) == phrase:
                    found, width = _Verb(i, " ".join(phrase), kind), n
                    break
            if found is None and tok.lower in ("let", "give"):
                end = self._sentence_end(tokens, i)
                for j in range(i + 1, min(end, i + 9)):
                    if tok.lower == "let" and tokens[j].lower == "know":
                        found, width = _Verb(i, "let … know", "send", span_end=j), j - i + 1
                        break
                    if (tok.lower == "give" and tokens[j].lower == "heads" and j + 2 < len(tokens)
                            and tokens[j + 1].lower == "-" and tokens[j + 2].lower == "up"):
                        found, width = _Verb(i, "give … heads-up", "send", span_end=j), j - i + 3
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

    @staticmethod
    def _sentence_start(tokens: list[_Token], index: int) -> int:
        for j in range(index - 1, -1, -1):
            if tokens[j].lower in _SENTENCE_END:
                return j + 1
        return 0

    @staticmethod
    def _make_segments(verbs: list[_Verb], tokens: list[_Token]) -> list[tuple[int, int]]:
        """The preamble before the first verb, then each verb's clause."""
        first = verbs[0].index if verbs else len(tokens)
        return [(0, first)] + [(v.index, v.end) for v in verbs]

    # -- one verb -> draft actions ---------------------------------------------

    def _draft(self, verb: _Verb, verbs: list[_Verb], tokens: list[_Token], mentions: list[_Mention],
               entities: dict[str, object], notes: list[str]) -> list[_Draft]:
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
        if kind in ("send", "move", "write") and verb.word in ("send", "move", "put") and amounts:
            kind = "pay"  # "send £50 to …", "move £500 to my savings"
        if kind == "settle":
            if not words & _BILL_WORDS:
                return []
            kind = "pay"
        if kind == "send" and verb.word != "invite" and words & _INVITE_NOUNS:
            kind = "create_event"  # "send Carol an invite for …"
        if kind == "write" and verb.word == "write" and not paths:
            kind = "send" if self._people(mentions, lo, hi) else "write"
        if kind == "add":
            if has_calendar:
                kind = "create_event"
            elif paths or self._earlier_paths(verb, verbs, tokens, entities):
                kind = "write"
            else:
                return []
        if kind == "write" and verb.word in ("put", "create"):
            if has_calendar or (verb.word == "create" and has_meeting):
                kind = "create_event"
        if kind == "create_event" and verb.word == "set up" and not has_meeting:
            notes.append("'set up' without a meeting word ignored")
            return []
        if kind == "delete" and not paths and not extensions and has_calendar:
            kind = "cancel"
        if kind in ("write", "delete", "move") and not paths:
            paths = self._earlier_paths(verb, verbs, tokens, entities)
            if paths:
                notes.append(f"'{verb.word}' takes {paths} from earlier in the sentence")

        if kind == "send":
            return [self._people_draft("send_email", verb, tokens, mentions, emails, evidence, words, notes)]
        if kind == "create_event":
            return [self._people_draft("create_event", verb, tokens, mentions, emails, evidence, words, notes)]
        if kind == "pay":
            return self._payment_drafts(verb, tokens, mentions, amounts, evidence, notes)
        if kind == "cancel":
            return [self._cancel_draft(verb, tokens, mentions, entities, words, notes)]
        if kind == "move":
            if len(paths) < 2:
                notes.append(f"'{verb.word}' without source and destination paths ignored")
                return []
            return [_Draft("move", explicit=[paths[0], paths[-1]], evidence=evidence)]
        if kind == "write":
            if not paths:
                notes.append(f"'{verb.word}' without a path ignored")
                return []
            return [_Draft("write_file", explicit=list(paths), count=len(set(paths)), evidence=evidence)]
        if kind == "delete":
            dir_like = [p for p in paths if "." not in str(p).rsplit("/", 1)[-1]]
            plural = bool(words & {"files", "logs"})
            if paths and (words & _BULK or (plural and dir_like)):
                ext = extensions[0] if extensions else ("log" if words & {"log", "logs"} else None)
                pattern = f"*.{ext}" if ext else "*"
                roots = dir_like or paths
                return [_Draft("delete_file", globs=[(p, pattern) for p in roots], count=self.profile.bulk_limit,
                               evidence=evidence)]
            if not paths:
                notes.append(f"'{verb.word}' without a path ignored")
                return []
            return [_Draft("delete_file", explicit=list(paths), count=len(set(paths)), evidence=evidence)]
        return []

    def _earlier_paths(self, verb: _Verb, verbs: list[_Verb], tokens: list[_Token],
                       entities: dict[str, object]) -> list[str]:
        """Paths between the start of the verb's sentence and the verb, not inside another verb's clause."""
        start = self._sentence_start(tokens, verb.index)
        claimed = set()
        for other in verbs:
            if other is not verb:
                claimed.update(range(other.index, other.end))
        out = []
        for j in range(start, verb.index):
            t = tokens[j].text
            if j in claimed or not t.startswith("⟦P"):
                continue
            value = entities.get(t[1:-1])
            if value is not None:
                out.append(str(value))
        return out

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
            word = tokens[j].lower
            if word in ("him", "her"):
                ref = self._antecedent(mentions, j, want="contact")
                if ref is not None:
                    draft.inferred.append(ref.contact_email)  # type: ignore[arg-type]
                    notes.append(f"pronoun {tokens[j].text!r} -> {ref.name}")
                else:
                    draft.unresolved.append(tokens[j].text)
            elif word == "them":
                group = self._plural_antecedent(mentions, j)
                if group:
                    draft.inferred.extend(m.contact_email for m in group)  # type: ignore[misc]
                    notes.append(f"pronoun 'them' -> {[m.name for m in group]}")
                else:
                    draft.unresolved.append(tokens[j].text)
        if kind == "send_email" and not draft.explicit and not draft.inferred and not draft.unresolved:
            draft.unresolved.append(evidence)
        if kind == "send_email" and words & _SEPARATELY:
            draft.count = max(1, len(set(draft.explicit + draft.inferred)))
        if draft.unresolved and kind == "send_email":
            notes.append(f"unresolved recipient in {evidence!r}")
        return draft

    def _payment_drafts(self, verb: _Verb, tokens: list[_Token], mentions: list[_Mention],
                        amounts: list[object], evidence: str, notes: list[str]) -> list[_Draft]:
        lo, hi = verb.index, verb.end
        payees = [m for m in mentions if lo <= m.start < hi and m.payee_account]
        if not payees:
            # "Globex sent an invoice by email — please pay it": the payee is named earlier in the sentence
            start = self._sentence_start(tokens, verb.index)
            earlier = [m for m in mentions if start <= m.start < lo and m.payee_account]
            if len({m.payee_account for m in earlier}) == 1:
                payees = earlier[-1:]
        for m in payees:
            notes.append(f"resolved payee {m.name!r} -> {m.payee_account}")
        if len(payees) > 1 and len(payees) == len(amounts):
            notes.append("paired payees and amounts in order")
            return [_Draft("transfer", explicit=[m.payee_account], amount=float(a), evidence=evidence)  # type: ignore[list-item,arg-type]
                    for m, a in zip(payees, amounts)]
        draft = _Draft("transfer", explicit=[m.payee_account for m in payees], evidence=evidence)  # type: ignore[misc]
        if not draft.explicit:
            for j in range(lo, hi):
                if tokens[j].lower in ("him", "her", "them"):
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
        return [draft]

    def _cancel_draft(self, verb: _Verb, tokens: list[_Token], mentions: list[_Mention],
                      entities: dict[str, object], words: set[str], notes: list[str]) -> _Draft:
        start = self._sentence_start(tokens, verb.index)
        end = self._sentence_end(tokens, verb.index)
        # tokens split "2026-10-02" into "2026 - 10 - 02"; rejoin before resolving dates
        sentence = _SPACED_ISO.sub(r"\1-\2-\3", self._evidence(tokens[start:end], entities))
        attendees = sorted({m.contact_email for m in mentions  # type: ignore[misc]
                            if start <= m.start < end and m.contact_email and not m.possessive})
        attendees += sorted({m.contact_email for m in mentions  # "Friday's 1:1 with Bob" / "Bob's 1:1"
                             if start <= m.start < end and m.contact_email and m.possessive} - set(attendees))
        dates = resolve_dates(sentence, self.profile.today)
        sentence_words = {t.lower for t in tokens[start:end]}
        bulk = bool(sentence_words & _BULK) or verb.word in ("clear", "clear out", "wipe")
        draft = _Draft("cancel_event", explicit=attendees, count=self.profile.bulk_limit if bulk else 1,
                       evidence=self._evidence(tokens[verb.index:verb.end], entities), date=dates[0] if dates else None)
        if dates:
            notes.append(f"cancellation bound to {dates[0]}")
        if attendees:
            notes.append(f"cancellation bound to attendees {attendees}")
        return draft

    @staticmethod
    def _antecedent(mentions: list[_Mention], index: int, want: str) -> _Mention | None:
        for m in reversed(mentions):
            if m.end <= index and (m.contact_email if want == "contact" else m.payee_account):
                return m
        return None

    def _plural_antecedent(self, mentions: list[_Mention], index: int) -> list[_Mention]:
        """Everyone named in the nearest earlier clause (or the preamble) that names people."""
        before = [(lo, hi) for lo, hi in self._segments if lo < index]
        for lo, hi in reversed(before):
            group = [m for m in mentions if lo <= m.start < min(hi, index) and m.contact_email and not m.possessive]
            if group:
                return group
        return []

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

    @staticmethod
    def _attach_request_amounts(drafts: list[_Draft], entities: dict[str, object], notes: list[str]) -> None:
        """F6: a stated amount is never replaced by the policy ceiling.

        If the request has exactly one transfer and it picked up no amount from
        its own clause, it takes the largest amount stated anywhere in the request.
        """
        transfers = [d for d in drafts if d.kind == "transfer"]
        stated = [float(v) for k, v in entities.items() if k.startswith("A")]  # type: ignore[arg-type]
        if len(transfers) == 1 and transfers[0].amount is None and stated:
            transfers[0].amount = max(stated)
            notes.append(f"amount {max(stated)} taken from elsewhere in the request")

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
            date=d.date,
        )

    def _domains(self, request: str, tokens: list[_Token], drafts: list[_Draft], has_paths: bool,
                 has_urls: bool) -> set[str]:
        domains: set[str] = set()
        lowers = [t.lower for t in tokens]
        if has_paths or set(lowers) & _FS_WORDS:
            domains.add("fs")
        for i, word in enumerate(lowers):
            if word in _EMAIL_WORDS or (word in _EMAIL_NOUNS and _is_noun_use(tokens, i)):
                domains.add("email")
            if word in _READ_REPLY and not _is_noun_use(tokens, i):
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
