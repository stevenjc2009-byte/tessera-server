"""Social endpoints: votes, favourites, reports.

Every route here is signed, because every one of them writes. The identity is
the console's public key and nothing else — there are no accounts, no
passwords and no sessions (spec section 5.1), so "one vote per person" is
really "one vote per keypair", and the ceiling on abuse is how many keypairs
someone is willing to generate. That is what the report system and the per-IP
rate limit are for; it is not something votes can solve on their own.
"""

from __future__ import annotations

import json
import sqlite3

from .http_server import (
    RequestContext,
    Response,
    TesseraApp,
    error,
    json_response,
    signed_route,
)
from .moderation import apply_autohide

VOTE_VALUES = (-1, 0, 1)


class BadRequest(ValueError):
    """The signature was fine; the body was not. Always answered with 400."""


def read_json(ctx: RequestContext, *, required: tuple[str, ...]) -> dict:
    """Parse a JSON object body and check the required keys are present.

    Raises BadRequest with a message safe to hand back to the caller — these
    are all shape complaints, they leak nothing about other users or state.
    """
    try:
        payload = json.loads(ctx.body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BadRequest(f"body is not valid UTF-8 JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise BadRequest("body must be a JSON object")
    missing = [name for name in required if name not in payload]
    if missing:
        raise BadRequest(f"missing: {', '.join(missing)}")
    return payload


def read_model_id(payload: dict) -> int:
    raw = payload["model_id"]
    # isinstance(True, int) is True in Python, so booleans are excluded
    # explicitly — otherwise {"model_id": true} would silently mean id 1.
    if isinstance(raw, bool) or not isinstance(raw, int) or raw < 1:
        raise BadRequest("model_id must be a positive integer")
    return raw


def require_visible_model(app: TesseraApp, model_id: int) -> sqlite3.Row | None:
    """Fetch a model that may be interacted with.

    'deleted' is invisible to everything; 'unlisted' is still a real model
    that can be voted on, favourited and reported — hiding it from browse is
    the moderation action, not erasing it.
    """
    return app.conn.execute(
        "SELECT id, author_key, visibility FROM models WHERE id = ? AND visibility != 'deleted'",
        (model_id,),
    ).fetchone()


def require_not_banned(app: TesseraApp, key_hex: str) -> Response | None:
    row = app.conn.execute("SELECT 1 FROM bans WHERE key = ?", (key_hex,)).fetchone()
    if row is not None:
        return error(403, "banned", "this key is banned")
    return None


def tally(app: TesseraApp, model_id: int, voter_key: str) -> dict:
    row = app.conn.execute(
        "SELECT score, up_votes, down_votes FROM models WHERE id = ?", (model_id,)
    ).fetchone()
    mine = app.conn.execute(
        "SELECT value FROM votes WHERE model_id = ? AND voter_key = ?", (model_id, voter_key)
    ).fetchone()
    return {
        "model_id": model_id,
        "score": int(row["score"]),
        "up_votes": int(row["up_votes"]),
        "down_votes": int(row["down_votes"]),
        "your_vote": int(mine["value"]) if mine is not None else 0,
    }


@signed_route("POST", r"/vote")
def handle_vote(app: TesseraApp, ctx: RequestContext, params: dict[str, str]) -> Response:
    assert ctx.identity is not None  # guaranteed by signed_route
    try:
        payload = read_json(ctx, required=("model_id", "value"))
        model_id = read_model_id(payload)
        value = payload["value"]
        if isinstance(value, bool) or value not in VOTE_VALUES:
            raise BadRequest(f"value must be one of {VOTE_VALUES}")
    except BadRequest as exc:
        return error(400, "bad_request", str(exc))

    refusal = require_not_banned(app, ctx.identity.key_hex)
    if refusal is not None:
        return refusal

    if require_visible_model(app, model_id) is None:
        return error(404, "not_found")

    voter = ctx.identity.key_hex
    # One transaction. The counters on `models` are denormalised so browse can
    # sort without a join, which means they must be RECOMPUTED from the votes
    # table inside the same transaction as the vote itself. A counter updated
    # by arithmetic ("score = score + 1") is how these drift, and drift here
    # silently corrupts sort=top with nothing to notice it.
    with app.conn:
        if value == 0:
            app.conn.execute(
                "DELETE FROM votes WHERE model_id = ? AND voter_key = ?", (model_id, voter)
            )
        else:
            app.conn.execute(
                "INSERT INTO votes (model_id, voter_key, value, created_at) VALUES (?, ?, ?, ?)"
                " ON CONFLICT (model_id, voter_key) DO UPDATE SET value = excluded.value,"
                " created_at = excluded.created_at",
                (model_id, voter, value, app.now()),
            )
        app.conn.execute(
            "UPDATE models SET"
            "  score      = (SELECT COALESCE(SUM(value), 0) FROM votes WHERE model_id = ?),"
            "  up_votes   = (SELECT COUNT(*) FROM votes WHERE model_id = ? AND value = 1),"
            "  down_votes = (SELECT COUNT(*) FROM votes WHERE model_id = ? AND value = -1)"
            " WHERE id = ?",
            (model_id, model_id, model_id, model_id),
        )

    return json_response(200, tally(app, model_id, voter))


@signed_route("POST", r"/favourite")
def handle_favourite(app: TesseraApp, ctx: RequestContext, params: dict[str, str]) -> Response:
    assert ctx.identity is not None
    try:
        payload = read_json(ctx, required=("model_id", "on"))
        model_id = read_model_id(payload)
        on = payload["on"]
        if not isinstance(on, bool):
            raise BadRequest("on must be true or false")
    except BadRequest as exc:
        return error(400, "bad_request", str(exc))

    refusal = require_not_banned(app, ctx.identity.key_hex)
    if refusal is not None:
        return refusal

    if require_visible_model(app, model_id) is None:
        return error(404, "not_found")

    owner = ctx.identity.key_hex
    with app.conn:
        if on:
            app.conn.execute(
                "INSERT INTO favourites (owner_key, model_id, created_at) VALUES (?, ?, ?)"
                " ON CONFLICT (owner_key, model_id) DO NOTHING",
                (owner, model_id, app.now()),
            )
        else:
            app.conn.execute(
                "DELETE FROM favourites WHERE owner_key = ? AND model_id = ?", (owner, model_id)
            )
        count = int(app.conn.execute(
            "SELECT COUNT(*) FROM favourites WHERE model_id = ?", (model_id,)
        ).fetchone()[0])

    return json_response(200, {"model_id": model_id, "favourited": on, "favourite_count": count})


# Favourites deliberately get no denormalised counter on `models`, unlike the
# vote tallies above. Nothing sorts or filters on the favourite count, so a
# COUNT(*) against idx_favourites_model for the one row being touched is
# cheaper than another column to keep honest.


@signed_route("GET", r"/favourites")
def handle_favourites(app: TesseraApp, ctx: RequestContext, params: dict[str, str]) -> Response:
    """List the caller's own hearted models.

    Not in the original spec's endpoint table, but approved for
    implementation (steve, 2026-09-07): a heart the console can set but never
    read back is write-only, and the client needs this list to render a
    favourites view. Signed, because a key's favourites are that key's own
    business — the same reasoning as vote/favourite/report all being signed.
    Mirrors handle_browse's response shape so a client already parsing
    /browse pages needs no second code path to render "my favourites".
    """
    from .handlers_content import _positive_int  # the same query parsing browse uses

    assert ctx.identity is not None
    page = _positive_int(ctx.query.get("page"), 1, 1_000_000)
    per_page = _positive_int(
        ctx.query.get("per_page"), app.cfg.browse_page_size, app.cfg.browse_max_page_size
    )
    rows = app.conn.execute(
        "SELECT m.id, m.title, m.author_key, m.kind, m.thumb_hash, m.score,"
        " m.up_votes, m.down_votes, m.created_at FROM favourites f"
        " JOIN models m ON m.id = f.model_id"
        " WHERE f.owner_key = ? AND m.visibility != 'deleted'"
        " ORDER BY f.created_at DESC LIMIT ? OFFSET ?",
        (ctx.identity.key_hex, per_page, (page - 1) * per_page),
    ).fetchall()
    return json_response(
        200, {"page": page, "per_page": per_page, "items": [dict(row) for row in rows]}
    )


MAX_DETAIL_CHARS = 512


def _clean_detail(raw: object) -> str:
    if raw is None:
        return ""
    if not isinstance(raw, str):
        raise BadRequest("detail must be a string")
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in raw):
        # This text is printed straight into a terminal by
        # tools/tessera-reports. Escape sequences in it would be executed by
        # the terminal rather than displayed — a report is an
        # attacker-controlled string aimed directly at the moderator's screen.
        # Rejected here, and stripped again on the way out (defence in depth,
        # because rows written before this check existed are still readable).
        raise BadRequest("detail contains control characters")
    return raw.strip()[:MAX_DETAIL_CHARS]


@signed_route("POST", r"/report")
def handle_report(app: TesseraApp, ctx: RequestContext, params: dict[str, str]) -> Response:
    assert ctx.identity is not None
    try:
        payload = read_json(ctx, required=("model_id", "reason"))
        model_id = read_model_id(payload)
        reason = payload["reason"]
        if not isinstance(reason, str) or reason not in app.cfg.report_reasons:
            raise BadRequest(f"reason must be one of {sorted(app.cfg.report_reasons)}")
        detail = _clean_detail(payload.get("detail"))
    except BadRequest as exc:
        return error(400, "bad_request", str(exc))

    refusal = require_not_banned(app, ctx.identity.key_hex)
    if refusal is not None:
        return refusal

    if require_visible_model(app, model_id) is None:
        return error(404, "not_found")

    with app.conn:
        # ON CONFLICT DO UPDATE, not DO NOTHING: one key gets one report per
        # model (the UNIQUE), but it may correct the reason it gave. The row
        # count is what the auto-hide threshold counts, so a correction must
        # never become a second row.
        app.conn.execute(
            "INSERT INTO reports (model_id, reporter_key, reason, detail, created_at)"
            " VALUES (?, ?, ?, ?, ?)"
            " ON CONFLICT (model_id, reporter_key) DO UPDATE SET"
            "   reason = excluded.reason, detail = excluded.detail,"
            "   created_at = excluded.created_at",
            (model_id, ctx.identity.key_hex, reason, detail, app.now()),
        )
        count, hidden = apply_autohide(app, model_id)

    # 202, not 200: the report is recorded, and whether anything happens to the
    # model is a human's decision later. Nothing is sent anywhere — the
    # moderator PULLS the queue (spec section 4).
    return json_response(
        202, {"model_id": model_id, "reported": True, "report_count": count, "hidden": hidden}
    )
