# SPDX-FileCopyrightText: 2026 Michael McClanahan
# SPDX-License-Identifier: GPL-3.0-or-later
"""Guard for the gap found in the external review (v1.1, October 17, 2026): the approval didn't say which
branch the PR merges into, so a PR approved while aimed at `release` could be retargeted to `main` and its
green check still counted. Since item 16 the base is in the signed action, shown on the Prime, checked by
the gate, and the status context names it (`prime-approve/<base>`). These tests assert the retarget is refused.
"""
from test_gate import PR, REPO, gh, ghome, go, merge_action, reply_for, req  # noqa: F401  (fixtures)

from primeapprove.protocol import ProtocolError, action_view, summary_line
import pytest


def test_approved_for_release_then_retargeted_to_main_is_refused(gh, ghome):
    gh.prs[(REPO, PR)]["base"]["ref"] = "release"
    rec = req(merge_action(base="release"))
    assert summary_line(rec.view) == f"Merge PR #{PR} into release → {REPO}", "the Prime shows the base"
    # The PR is retargeted to main after the approval, before the gate runs.
    gh.prs[(REPO, PR)]["base"]["ref"] = "main"
    for mode in ("status", "merge"):
        r = go(gh, ghome, rec, reply_for(rec, 1), mode=mode)
        assert r.code == 2 and "base moved" in r.message, r.message
    assert gh.statuses == [] and gh.merges == []


def test_a_release_approval_never_posts_the_main_context(gh, ghome):
    gh.prs[(REPO, PR)]["base"]["ref"] = "release"
    rec = req(merge_action(base="release"))
    assert go(gh, ghome, rec, reply_for(rec, 1)).code == 0
    # Branch protection on main requires `prime-approve/main`; this approval only ever posts the release one.
    assert [s["context"] for s in gh.statuses] == ["prime-approve/release"]


def test_an_action_without_a_base_is_refused():
    with pytest.raises(ProtocolError):
        action_view(b'{"tool":"github.merge_pull_request","repo":"a/b","pr":2,"method":"squash","head":"' + b"a" * 40 + b'"}')
