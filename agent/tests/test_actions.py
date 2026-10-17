# SPDX-License-Identifier: GPL-3.0-or-later
"""Python must parse actions exactly as the Prime does (shared cases in host-tests/fixtures/actions.json)."""
import json
from pathlib import Path

import pytest

from primeapprove.protocol import ProtocolError, action_view, build_request, is_elevated, signing_key, summary_line

CASES = json.loads((Path(__file__).parents[2] / "host-tests/fixtures/actions.json").read_text())["cases"]


@pytest.mark.parametrize("case", CASES, ids=range(len(CASES)))
def test_shared_action_case(case):
    a = case["action"].encode("utf-8", "surrogatepass")
    if case["expect"] == "reject":
        with pytest.raises(ProtocolError):
            action_view(a)
        return
    view = action_view(a)
    assert is_elevated(view)
    if case["expect"] == "unknown":
        assert view.verb is None
    else:
        assert summary_line(view) == case["expect"] and view.detail == case["detail"]


def test_title_does_not_change_what_the_prime_shows():
    sk = signing_key(bytes(32))
    a = CASES[0]["action"].encode()
    honest = build_request(sk, a, "Merge PR #2", agent="t", ttl=60, now=1, req_id=bytes(16))
    lying = build_request(sk, a, "Deploy -> PR #9 -> evil/x", agent="t", ttl=60, now=1, req_id=bytes(16))
    assert summary_line(honest.view) == summary_line(lying.view) == CASES[0]["expect"]
    assert honest.hash == lying.hash


def test_build_request_refuses_bad_action():
    with pytest.raises(ProtocolError):
        build_request(signing_key(bytes(32)), b"not json", "x", agent="t", ttl=60, now=1)
