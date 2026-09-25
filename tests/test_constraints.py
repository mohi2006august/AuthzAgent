import math

import pytest

from authz.constraints import AllowList, HostAllowList, MaxValue, PathScope, canonical_path, constraint_from_json
from authz.types import Reason


@pytest.mark.parametrize("path", [
    "/home/sam/../sam/x", "/home/sam/./x", "/home/sam//x", "/home/sam/x/", "relative/x", "//etc/passwd",
    "/home/sam/x\x00", "C:\\Users\\x", 42,
])
def test_non_canonical_paths_are_rejected(path):
    assert canonical_path(path) is None


def test_prefix_is_a_directory_boundary_not_a_string_prefix():
    scope = PathScope(prefixes=("/home/sam/reports",))
    assert scope.check("/home/sam/reports/q3.md") is None
    assert scope.check("/home/sam/reports") is None
    assert scope.check("/home/sam/reports-old/q3.md") is not None


def test_traversal_out_of_a_granted_prefix_is_denied():
    scope = PathScope(prefixes=("/home/sam/scratch",))
    assert scope.check("/home/sam/scratch/../projects/thesis/thesis.tex") is not None


def test_glob_matches_basename_under_directory_only():
    scope = PathScope(globs=(("/home/sam/scratch", "*.tmp"),))
    assert scope.check("/home/sam/scratch/a.tmp") is None
    assert scope.check("/home/sam/scratch/deep/b.tmp") is None
    assert scope.check("/home/sam/scratch/analysis.ipynb") is not None
    assert scope.check("/home/sam/other/a.tmp") is not None
    assert scope.check("/home/sam/scratch") is not None


def test_sensitive_paths_need_to_be_named_exactly():
    scope = PathScope(prefixes=("/home/sam",), exclude=("/home/sam/.ssh",))
    assert scope.check("/home/sam/notes/a.md") is None
    assert scope.check("/home/sam/.ssh/id_ed25519") is not None
    named = PathScope(exact=("/home/sam/.ssh/config",), prefixes=("/home/sam",), exclude=("/home/sam/.ssh",))
    assert named.check("/home/sam/.ssh/config") is None


def test_allow_parents_permits_listing_ancestors_only():
    scope = PathScope(prefixes=("/home/sam/notes/offsite.md",), allow_parents=True)
    assert scope.check("/home/sam/notes") is None
    assert scope.check("/home/sam") is None
    assert scope.check("/home/sam/reports") is not None


@pytest.mark.parametrize("url,ok", [
    ("https://docs.vendorapi.example/changelog", True),
    ("http://docs.vendorapi.example/x?y=1", True),
    ("https://DOCS.vendorapi.example/", True),
    ("https://docs.vendorapi.example.telemetry-cdn.example/collect", False),
    ("https://docs.vendorapi.example@evil.example/", False),
    ("https://evil.example/?u=docs.vendorapi.example", False),
    ("https://docs.vendorapi.example:8443/", False),
    ("ftp://docs.vendorapi.example/", False),
    ("https://api.docs.vendorapi.example/", False),
])
def test_host_allow_list(url, ok):
    assert (HostAllowList(("docs.vendorapi.example",)).check(url) is None) is ok


def test_allow_list_normalisation():
    emails = AllowList(("Alice.Chen@helix.example",), Reason.RECIPIENT_NOT_ALLOWED, "email")
    assert emails.check(" alice.chen@HELIX.example ") is None
    assert emails.check("alice.chen@he1ix.example") is not None
    accounts = AllowList(("GB82 WEST 1234",), Reason.ACCOUNT_NOT_ALLOWED, "account")
    assert accounts.check("gb82west1234") is None
    assert AllowList((), Reason.RECIPIENT_NOT_ALLOWED, "email").check("a@b.example") is not None


@pytest.mark.parametrize("value,ok", [(340, True), (340.0, True), (340.01, False), (math.nan, False),
                                      (math.inf, False), (True, False), ("340", False)])
def test_max_value(value, ok):
    assert (MaxValue(340.0).check(value) is None) is ok


def test_constraints_round_trip_through_json():
    for c in (AllowList(("a@b.example",), Reason.RECIPIENT_NOT_ALLOWED, "email"), MaxValue(12.5, source="policy"),
              PathScope(("/a",), ("/b",), (("/c", "*.tmp"),), ("/b/.ssh",), True), HostAllowList(("x.example",))):
        assert constraint_from_json(c.to_json()) == c
