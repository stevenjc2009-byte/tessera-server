"""Content endpoints: upload, browse, download.

Nothing in this module inspects an uploaded byte. `envelope.parse_upload`
splits the body on declared lengths, the blob store hashes and writes it, and
the download handlers read it back and hand it over. There is no decode step
to attack (spec section 5.6).
"""

from __future__ import annotations

import sqlite3

from .envelope import EnvelopeError, parse_upload
from .http_server import (
    RequestContext,
    Response,
    TesseraApp,
    error,
    json_response,
    route,
    signed_route,
)
from .quota import QuotaError, check_upload_allowed
from .store import BlobNotFound, InvalidDigest


@signed_route("POST", r"/upload")
def handle_upload(app: TesseraApp, ctx: RequestContext, params: dict[str, str]) -> Response:
    assert ctx.identity is not None  # guaranteed by signed_route
    try:
        envelope = parse_upload(ctx.body, app.cfg)
    except EnvelopeError as exc:
        return error(400, "bad_envelope", str(exc))

    now = app.now()
    try:
        check_upload_allowed(
            conn=app.conn,
            store=app.store,
            cfg=app.cfg,
            author_key=ctx.identity.key_hex,
            incoming_bytes=len(envelope.model) + len(envelope.thumb),
            now=now,
        )
    except QuotaError as exc:
        return error(exc.status, exc.code, exc.detail)

    model_hash = app.store.put(envelope.model)
    thumb_hash = app.store.put(envelope.thumb)

    try:
        cursor = app.conn.execute(
            "INSERT INTO models (model_hash, thumb_hash, title, author_key, kind,"
            " model_bytes, thumb_bytes, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                model_hash, thumb_hash, envelope.title, ctx.identity.key_hex, envelope.kind,
                len(envelope.model), len(envelope.thumb), now,
            ),
        )
    except sqlite3.IntegrityError:
        # The UNIQUE on model_hash. The blobs are already stored and shared
        # with the existing row, so nothing is orphaned by returning here.
        return error(409, "duplicate", "these exact bytes are already in the gallery")

    return json_response(
        201, {"id": int(cursor.lastrowid), "model_hash": model_hash, "thumb_hash": thumb_hash}
    )


BROWSE_FIELDS = (
    "id", "title", "author_key", "kind", "thumb_hash",
    "score", "up_votes", "down_votes", "created_at",
)

_SORTS = {
    "new": "created_at DESC, id DESC",
    "top": "score DESC, created_at DESC, id DESC",
}


def _positive_int(values: list[str] | None, default: int, maximum: int) -> int:
    """Query parameters are attacker-controlled. Anything unusable becomes the
    default rather than an error — a browse request is not the place to teach
    someone which inputs the parser dislikes."""
    if not values:
        return default
    try:
        parsed = int(values[0], 10)
    except ValueError:
        return default
    if parsed < 1:
        return default
    return min(parsed, maximum)


@route("GET", r"/browse")
def handle_browse(app: TesseraApp, ctx: RequestContext, params: dict[str, str]) -> Response:
    page = _positive_int(ctx.query.get("page"), 1, 1_000_000)
    per_page = _positive_int(
        ctx.query.get("per_page"), app.cfg.browse_page_size, app.cfg.browse_max_page_size
    )
    sort = _SORTS.get((ctx.query.get("sort") or ["new"])[0], _SORTS["new"])

    kind = (ctx.query.get("kind") or [""])[0]
    where = "visibility = 'public'"
    args: list[object] = []
    if kind in {"pixel", "model"}:
        where += " AND kind = ?"
        args.append(kind)

    total = int(app.conn.execute(f"SELECT COUNT(*) FROM models WHERE {where}", args).fetchone()[0])
    rows = app.conn.execute(
        f"SELECT {', '.join(BROWSE_FIELDS)} FROM models WHERE {where}"
        f" ORDER BY {sort} LIMIT ? OFFSET ?",
        [*args, per_page, (page - 1) * per_page],
    ).fetchall()

    return json_response(
        200,
        {
            "page": page,
            "per_page": per_page,
            "total": total,
            "items": [dict(row) for row in rows],
        },
    )


BLOB_HEADERS = (
    ("Content-Disposition", "attachment"),
    ("Cache-Control", "public, max-age=86400, immutable"),
)


def _serve_blob(app: TesseraApp, model_id_raw: str, column: str) -> Response:
    """Look the id up, fetch the blob, hand back the bytes.

    The route regex already guarantees `model_id_raw` is digits, so the int()
    below cannot fail on a request that reached here — but it is wrapped
    anyway, because a regex and a parser drifting apart is exactly the kind of
    gap that stops being caught.

    `column` is never request-derived: it is one of two literals passed by the
    two callers below.
    """
    try:
        model_id = int(model_id_raw, 10)
    except ValueError:
        return error(404, "not_found")

    row = app.conn.execute(
        f"SELECT {column} AS digest, visibility FROM models WHERE id = ?", (model_id,)
    ).fetchone()
    if row is None or row["visibility"] == "deleted":
        return error(404, "not_found")

    try:
        data = app.store.get(row["digest"])
    except (BlobNotFound, InvalidDigest):
        # A row whose blob is gone. Answered as 404 rather than 500 because
        # from the caller's side it is indistinguishable, and a 500 would
        # invite a retry loop.
        print(f"blob missing for model {model_id} ({column})", flush=True)
        return error(404, "not_found")

    return Response(200, data, "application/octet-stream", BLOB_HEADERS)


@route("GET", r"/model/(?P<model_id>\d{1,18})")
def handle_model(app: TesseraApp, ctx: RequestContext, params: dict[str, str]) -> Response:
    return _serve_blob(app, params["model_id"], "model_hash")


@route("GET", r"/thumb/(?P<model_id>\d{1,18})")
def handle_thumb(app: TesseraApp, ctx: RequestContext, params: dict[str, str]) -> Response:
    return _serve_blob(app, params["model_id"], "thumb_hash")


@signed_route("POST", r"/vote")
def handle_vote_placeholder(app, ctx, params):
    """Replaced by handlers_social.handle_vote in Task 16."""
    return json_response(200, {"ok": True, "key": ctx.identity.key_hex})


@signed_route("GET", r"/admin/reports", admin=True)
def handle_admin_reports_placeholder(app, ctx, params):
    """Replaced by handlers_admin.handle_admin_reports in Task 20."""
    return json_response(200, {"reports": []})
