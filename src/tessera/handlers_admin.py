"""The moderation queue and the four moderation actions.

Pull-based, entirely (spec section 4). Nothing is sent anywhere when a report
arrives: no webhook, no email, no push. A moderator signs a GET with the admin
key and reads the queue, either over HTTP from the console or with
tools/tessera-reports on the box itself. That is the whole notification
mechanism, and it is deliberate — an outbound webhook would be a hole punched
straight through the egress rules of Task 23 for the convenience of one person.

The admin key is an ordinary console keypair that happens to be listed in
cfg.admin_keys. There is no password, no session and no separate admin login;
losing the console means editing one line of the config file.
"""

from __future__ import annotations

from .handlers_social import BadRequest, read_json, read_model_id
from .http_server import (
    RequestContext,
    Response,
    TesseraApp,
    error,
    json_response,
    signed_route,
)
from .moderation import resolve_reports, set_visibility

ADMIN_ACTIONS = ("approve", "unlist", "delete", "ban")

# What each action does to the model's visibility. `unlist` is the only one
# that leaves the reports OPEN — a model parked pending a decision has to stay
# in the queue, or the next moderator cannot tell why it is hidden.
_ACTION_VISIBILITY = {
    "approve": "public",
    "unlist": "unlisted",
    "delete": "deleted",
    "ban": "deleted",
}

MAX_REASON_CHARS = 512


@signed_route("GET", r"/admin/reports", admin=True)
def handle_admin_reports(app: TesseraApp, ctx: RequestContext, params: dict[str, str]) -> Response:
    from .handlers_content import _positive_int  # the same query parsing browse uses

    page = _positive_int(ctx.query.get("page"), 1, 1_000_000)
    per_page = _positive_int(
        ctx.query.get("per_page"), app.cfg.browse_page_size, app.cfg.browse_max_page_size
    )
    want_resolved = (ctx.query.get("resolved") or ["0"])[0] == "1"
    # Two fixed literals chosen by a boolean — no request text reaches the SQL.
    clause = "r.resolved_at IS NOT NULL" if want_resolved else "r.resolved_at IS NULL"

    total = int(app.conn.execute(
        f"SELECT COUNT(DISTINCT r.model_id) FROM reports r WHERE {clause}"
    ).fetchone()[0])

    # One row per MODEL with the reasons and details rolled up, not one row per
    # report. A moderator reading this on a terminal needs to see a model at a
    # time; five reports on one model is one decision, not five.
    rows = app.conn.execute(
        "SELECT r.model_id AS model_id, m.title AS title, m.author_key AS author_key,"
        "       m.kind AS kind, m.visibility AS visibility, m.created_at AS created_at,"
        "       COUNT(DISTINCT r.reporter_key) AS report_count,"
        "       GROUP_CONCAT(DISTINCT r.reason) AS reasons_csv,"
        "       GROUP_CONCAT(r.detail, char(10)) AS details,"
        "       MAX(r.created_at) AS last_report_at"
        " FROM reports r JOIN models m ON m.id = r.model_id"
        f" WHERE {clause}"
        " GROUP BY r.model_id"
        " ORDER BY report_count DESC, last_report_at DESC"
        " LIMIT ? OFFSET ?",
        (per_page, (page - 1) * per_page),
    ).fetchall()

    items = []
    for row in rows:
        entry = dict(row)
        reasons_csv = entry.pop("reasons_csv") or ""
        entry["reasons"] = sorted(part for part in reasons_csv.split(",") if part)
        entry["details"] = entry["details"] or ""
        items.append(entry)

    return json_response(
        200, {"page": page, "per_page": per_page, "total": total, "items": items}
    )


@signed_route("POST", r"/admin/action", admin=True)
def handle_admin_action(app: TesseraApp, ctx: RequestContext, params: dict[str, str]) -> Response:
    assert ctx.identity is not None
    try:
        payload = read_json(ctx, required=("model_id", "action"))
        model_id = read_model_id(payload)
        action = payload["action"]
        if not isinstance(action, str) or action not in ADMIN_ACTIONS:
            raise BadRequest(f"action must be one of {list(ADMIN_ACTIONS)}")
        reason = payload.get("reason", "")
        if not isinstance(reason, str):
            raise BadRequest("reason must be a string")
        reason = reason.strip()[:MAX_REASON_CHARS]
    except BadRequest as exc:
        return error(400, "bad_request", str(exc))

    # Deliberately NOT require_visible_model: a moderator must be able to act
    # on something already deleted (to log a ban against it, for instance).
    row = app.conn.execute(
        "SELECT id, author_key, visibility FROM models WHERE id = ?", (model_id,)
    ).fetchone()
    if row is None:
        return error(404, "not_found")

    now = app.now()
    banned_key = None
    with app.conn:
        set_visibility(app.conn, model_id, _ACTION_VISIBILITY[action])
        resolved = resolve_reports(app.conn, model_id, now) if action != "unlist" else 0

        if action == "ban":
            banned_key = row["author_key"]
            app.conn.execute(
                "INSERT INTO bans (key, reason, created_at) VALUES (?, ?, ?)"
                " ON CONFLICT (key) DO UPDATE SET reason = excluded.reason",
                (banned_key, reason, now),
            )
            # A ban takes down everything that key uploaded, not just the model
            # that triggered it. Anything less means re-reporting the same
            # person model by model, which is how a moderator gives up.
            app.conn.execute(
                "UPDATE models SET visibility = 'deleted' WHERE author_key = ?", (banned_key,)
            )

        app.conn.execute(
            "INSERT INTO admin_log (model_id, admin_key, action, reason, created_at)"
            " VALUES (?, ?, ?, ?, ?)",
            (model_id, ctx.identity.key_hex, action, reason, now),
        )

    visibility = app.conn.execute(
        "SELECT visibility FROM models WHERE id = ?", (model_id,)
    ).fetchone()["visibility"]

    return json_response(
        200,
        {
            "model_id": model_id,
            "action": action,
            "visibility": visibility,
            "resolved": resolved,
            "banned_key": banned_key,
        },
    )
