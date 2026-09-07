"""Visibility transitions and the auto-hide rule.

The rule (spec section 4): once N *distinct* reporter keys have an open report
against a model, it goes 'unlisted' pending a human's review. N is
cfg.report_autohide_threshold, default 3, and it is configuration rather than
a constant because the right number depends on how many people are actually
using the gallery — 3 is far too twitchy at ten users and far too slow at ten
thousand.

Auto-hide is deliberately weak: it unlists, it never deletes. The reversible
action is the only one a machine is allowed to take on its own. Deleting and
banning are Task 20's admin actions and need a human's key.
"""

from __future__ import annotations

import sqlite3
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover - types only, avoids an import cycle
    from .http_server import TesseraApp

VISIBILITIES = ("public", "unlisted", "deleted")


def open_report_count(conn: sqlite3.Connection, model_id: int) -> int:
    """Distinct reporter keys with an unresolved report against this model.

    COUNT(DISTINCT reporter_key), not COUNT(*), even though the UNIQUE
    constraint on (model_id, reporter_key) already makes them identical today.
    If that constraint is ever relaxed, this stays correct instead of silently
    turning into a one-person mass-report button.
    """
    return int(conn.execute(
        "SELECT COUNT(DISTINCT reporter_key) FROM reports"
        " WHERE model_id = ? AND resolved_at IS NULL",
        (model_id,),
    ).fetchone()[0])


def set_visibility(conn: sqlite3.Connection, model_id: int, visibility: str) -> None:
    """Move a model between states. 'deleted' is terminal.

    The WHERE clause refuses to move anything out of 'deleted': a delete is a
    moderator's decision, and no later automatic transition — nor a stray
    admin 'approve' — may undo it by accident.
    """
    if visibility not in VISIBILITIES:
        raise ValueError(f"visibility must be one of {VISIBILITIES}")
    conn.execute(
        "UPDATE models SET visibility = ? WHERE id = ? AND visibility != 'deleted'",
        (visibility, model_id),
    )


def resolve_reports(conn: sqlite3.Connection, model_id: int, now: int) -> int:
    """Close every open report against a model. Returns how many were closed."""
    cursor = conn.execute(
        "UPDATE reports SET resolved_at = ? WHERE model_id = ? AND resolved_at IS NULL",
        (now, model_id),
    )
    return int(cursor.rowcount)


def apply_autohide(app: "TesseraApp", model_id: int) -> tuple[int, bool]:
    """Count open reports and unlist if the threshold is met.

    Called from inside handle_report's transaction, so the count and the
    visibility change land together — two reports arriving at once cannot each
    read a count of N-1 and both decline to hide.
    """
    count = open_report_count(app.conn, model_id)
    hidden = count >= app.cfg.report_autohide_threshold
    if hidden:
        set_visibility(app.conn, model_id, "unlisted")
    return count, hidden
