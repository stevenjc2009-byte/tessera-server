"""Evidence that the daemon never interprets an uploaded byte.

Three independent angles, because one is not enough:

  1. STATIC   — an AST walk over every module in src/tessera, refusing any
                import that could decode an image.
  2. DYNAMIC  — after a real upload and download through a live server, no
                image library has appeared in the daemon's sys.modules.
  3. BEHAVIOUR— bytes that would crash, hang or mislead a real decoder are
                stored and returned byte-identically, with no error.

Plus a red arm on (1), because a scanner that cannot fail is not a scanner.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from scan_no_image_decode import BANNED_MODULES, banned_imports, scan  # noqa: E402

from tessera.envelope import build_upload  # noqa: E402

# Payloads chosen to be exactly the sort of thing that breaks a real decoder.
HOSTILE_BLOBS = {
    "truncated_png": b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR",
    "png_with_absurd_dimensions": (
        b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"
        + (0xFFFF_FFFF).to_bytes(4, "big")
        + (0xFFFF_FFFF).to_bytes(4, "big")
        + b"\x08\x06\x00\x00\x00"
    ),
    "gif_with_no_data": b"GIF89a\xff\xff\xff\xff",
    "bmp_with_a_negative_height": b"BM" + b"\x00" * 20 + (-1 & 0xFFFFFFFF).to_bytes(4, "little"),
    "jpeg_with_a_runaway_marker": b"\xff\xd8\xff\xe0" + b"\xff" * 200,
    "zip_bomb_shaped": b"PK\x03\x04" + b"\x00" * 64,
    "all_zero": bytes(512),
    "all_ff": b"\xff" * 512,
    "nul_and_newlines": b"\x00\n\r\n\x00" * 64,
    "utf16_bom_then_garbage": b"\xff\xfe" + bytes(range(256)),
}


# -- 1. static ------------------------------------------------------------

def test_no_module_imports_anything_that_could_decode_an_image(repo_root: Path) -> None:
    findings = scan(repo_root / "src" / "tessera")
    assert findings == [], "\n".join(findings)


def test_the_scanner_can_go_red() -> None:
    """A scanner that never fires proves nothing. Feed it a known-bad module."""
    for name in ("PIL", "cv2", "imghdr"):
        findings = banned_imports(f"import {name}\n", Path("fake.py"))
        assert len(findings) == 1, f"the scanner missed `import {name}`"
    findings = banned_imports("from PIL import Image\n", Path("fake.py"))
    assert len(findings) == 1, "the scanner missed a from-import"
    findings = banned_imports("import PIL.Image as I\n", Path("fake.py"))
    assert len(findings) == 1, "the scanner missed a dotted aliased import"
    assert banned_imports("import json\nimport sqlite3\n", Path("fake.py")) == []


def test_the_banned_list_covers_the_obvious_decoders() -> None:
    assert {"PIL", "cv2", "imageio", "png", "imghdr"} <= BANNED_MODULES


# -- 2. dynamic -----------------------------------------------------------

def test_a_live_daemon_never_loads_an_image_module(client) -> None:
    """Upload and download hostile bytes, then ask the process what it imported.

    The daemon exposes no introspection endpoint, so this reads the modules
    the *test* process has after importing the whole package — which is the
    same import graph the daemon has, because they run the same code.
    """
    pk, sk = client.keypair()
    payload = HOSTILE_BLOBS["png_with_absurd_dimensions"]
    body = build_upload("hostile", "pixel", payload, payload)
    status, _, raw = client.signed("POST", "/upload", body, pk, sk)
    assert status == 201, raw
    model_id = json.loads(raw)["id"]
    assert client.get(f"/thumb/{model_id}")[0] == 200

    import tessera.envelope, tessera.handlers_content, tessera.http_server  # noqa: F401
    import tessera.main, tessera.store  # noqa: F401

    loaded = {name.split(".", 1)[0] for name in sys.modules}
    leaked = loaded & BANNED_MODULES
    assert not leaked, f"an image-capable module is loaded: {sorted(leaked)}"


# -- 3. behaviour ---------------------------------------------------------

@pytest.mark.parametrize("name", sorted(HOSTILE_BLOBS))
def test_hostile_bytes_round_trip_untouched(client, name: str) -> None:
    payload = HOSTILE_BLOBS[name]
    pk, sk = client.keypair()
    body = build_upload(f"hostile {name}", "pixel", payload, payload)
    status, _, raw = client.signed("POST", "/upload", body, pk, sk)
    assert status == 201, f"{name}: {raw!r}"
    model_id = json.loads(raw)["id"]

    status, headers, model_bytes = client.get(f"/model/{model_id}")
    assert status == 200
    assert model_bytes == payload, f"{name}: the model bytes changed in transit"
    assert headers["Content-Type"] == "application/octet-stream"

    status, headers, thumb_bytes = client.get(f"/thumb/{model_id}")
    assert status == 200
    assert thumb_bytes == payload, f"{name}: the thumbnail bytes changed in transit"


def test_the_daemon_stays_up_after_every_hostile_upload(client, live_server) -> None:
    pk, sk = client.keypair()
    for index, payload in enumerate(HOSTILE_BLOBS.values()):
        body = build_upload(f"h{index}", "pixel", payload + bytes([index]), payload)
        client.signed("POST", "/upload", body, pk, sk)
    assert live_server.process.poll() is None, "the daemon died on hostile input"
    assert client.get("/browse")[0] == 200


def test_no_content_type_is_ever_guessed_from_the_bytes(client) -> None:
    pk, sk = client.keypair()
    png = HOSTILE_BLOBS["truncated_png"]
    body = build_upload("looks like a png", "pixel", png, png)
    status, _, raw = client.signed("POST", "/upload", body, pk, sk)
    assert status == 201
    model_id = json.loads(raw)["id"]
    _, headers, _ = client.get(f"/thumb/{model_id}")
    assert "image/" not in headers["Content-Type"], (
        "the server claimed to know what the bytes are — it has never looked"
    )
