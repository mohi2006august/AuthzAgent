import pytest

from authz import RuleBasedParser, derive


@pytest.fixture(scope="module")
def parser(profile):
    return RuleBasedParser(profile)


def test_original_requests_match_the_hand_labelled_intent(suite, parser):
    mismatches = [t.id for t in suite.tasks if parser.parse(t.request).scope() != t.gold().scope()]
    assert mismatches == []


def test_parsing_and_derivation_are_deterministic(suite, profile):
    for task in suite.tasks:
        for request in [task.request, *task.paraphrases]:
            prints = {derive(request, profile=profile).fingerprint() for _ in range(3)}
            assert len(prints) == 1, request


def kinds(record):
    return sorted(a.kind for a in record.actions)


def test_negation_withholds_the_negated_action(parser):
    r = parser.parse("Draft a reply to Bob's email about hiring and save it to /home/sam/drafts/r.md. Don't send it.")
    assert kinds(r) == ["write_file"]
    assert any("negated" in n for n in r.notes)


def test_possessive_owner_is_not_a_recipient(parser):
    r = parser.parse("Forward Carol's email about the venue contract to Legal.")
    assert [a.targets for a in r.actions] == [("legal@helix.example",)]


def test_tell_me_is_an_answer_not_an_email(parser):
    r = parser.parse("Check https://docs.vendorapi.example/changelog and tell me whether v2 is deprecated.")
    assert r.actions == ()
    assert r.fetch_hosts == ("docs.vendorapi.example",)


def test_aliases_inside_paths_are_not_people(parser):
    r = parser.parse("Move /home/sam/downloads/c.pdf to /home/sam/legal/c.pdf.")
    assert kinds(r) == ["delete_file", "write_file"]
    assert all("legal@" not in t for a in r.actions for t in a.targets)


def test_pronoun_resolves_to_the_previous_person(parser):
    r = parser.parse("Read Dana's expenses email, add up the receipts, and reimburse her the total.")
    (action,) = r.actions
    assert action.kind == "transfer"
    assert action.targets == ("GB12 HLXB 0000 4521 7788 90",)
    assert action.ceiling_source == "policy"


def test_unresolvable_recipient_grants_nobody(parser, profile):
    r = parser.parse("Reply to the latest email about the server outage and tell them we're investigating.")
    (action,) = r.actions
    assert action.kind == "send_email" and action.targets == () and action.unresolved
    capset = derive(r.request, profile=profile)
    assert capset.grant("send_email").constraint_for("to").values == ()


def test_separately_sets_the_budget(parser):
    r = parser.parse("Send the notes in /home/sam/notes/o.md to Bob and Priya separately.")
    (action,) = r.actions
    assert action.count == 2


def test_bulk_delete_becomes_a_glob(parser):
    r = parser.parse("Clean up all the .tmp files in /home/sam/scratch.")
    (action,) = r.actions
    assert action.globs == (("/home/sam/scratch", "*.tmp"),)
    assert action.targets == ()


def test_stated_amount_is_the_ceiling(parser):
    (action,) = parser.parse("Pay Globex Consulting £2,500 for the September retainer.").actions
    assert action.amount_ceiling == 2500.0 and action.ceiling_source == "request"


def test_unknown_names_stay_unresolved(parser):
    (action,) = parser.parse("Email the report at /home/sam/r.md to Mallory.").actions
    assert action.targets == ()


def test_home_relative_paths_expand(parser):
    r = parser.parse("Delete ~/scratch/a.tmp please.")
    assert r.actions[0].targets == ("/home/sam/scratch/a.tmp",)


def test_no_path_means_home_minus_sensitive(profile):
    capset = derive("Summarise my notes.", profile=profile)
    scope = capset.grant("read_file").constraint_for("path")
    assert scope.check("/home/sam/notes/todo.md") is None
    assert scope.check("/home/sam/.ssh/id_ed25519") is not None
