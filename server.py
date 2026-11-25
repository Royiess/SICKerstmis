from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import sqlite3
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, field_validator

APP_VERSION = "1.0.0"
DATABASE_PATH = Path(os.getenv("GW_DATABASE_PATH", "data/glass_wave.sqlite3"))
MAX_REQUEST_BYTES = 1_000_000
CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
CODE_RE = re.compile(r"^GW-[A-Z2-9]{4}-[A-Z2-9]{4}-[A-Z2-9]{4}$")
CATEGORIES = {"Tech & Gear", "DIY Smart Glasses", "Gaming & Coins", "Home & Living"}

app = FastAPI(
    title="SIC Corp Glass Wave Share API",
    version=APP_VERSION,
    docs_url=None if os.getenv("GW_DISABLE_DOCS", "true").lower() == "true" else "/docs",
    redoc_url=None,
)

allowed_origins = [
    origin.strip().rstrip("/")
    for origin in os.getenv(
        "GW_ALLOWED_ORIGINS",
        "https://royiess.github.io,http://localhost:5500,http://127.0.0.1:5500",
    ).split(",")
    if origin.strip()
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST", "PUT", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
    max_age=600,
)

# Small in-memory abuse throttle. Put a reverse proxy/WAF in front for production.
_rate_buckets: dict[str, list[float]] = {}


def rate_limit(request: Request, bucket: str, limit: int, window: int = 60) -> None:
    # Gebruik niet blind X-Forwarded-For: clients kunnen die header vervalsen.
    # Configureer trusted proxy IPs expliciet als je achter een reverse proxy draait.
    ip = request.client.host if request.client else "unknown"
    key = f"{bucket}:{ip}"
    now = time.time()
    hits = [stamp for stamp in _rate_buckets.get(key, []) if now - stamp < window]
    if len(hits) >= limit:
        raise HTTPException(status_code=429, detail="Te veel pogingen. Probeer het later opnieuw.")
    hits.append(now)
    _rate_buckets[key] = hits


def digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def db_connect() -> sqlite3.Connection:
    DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DATABASE_PATH, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


@contextmanager
def db_session():
    conn = db_connect()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db() -> None:
    with db_session() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS shares (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                code_hash TEXT NOT NULL UNIQUE,
                state_json TEXT NOT NULL,
                version INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL
            )
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS members (
                token_hash TEXT PRIMARY KEY,
                share_id INTEGER NOT NULL,
                display_name TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(share_id) REFERENCES shares(id) ON DELETE CASCADE
            )
        """)
        db.execute("CREATE INDEX IF NOT EXISTS idx_members_share_id ON members(share_id)")


@app.on_event("startup")
def startup() -> None:
    init_db()


class WishlistItem(BaseModel):
    id: str = Field(min_length=1, max_length=100)
    name: str = Field(min_length=1, max_length=120)
    price: float = Field(ge=0, le=1_000_000)
    category: str = Field(default="Tech & Gear", max_length=60)
    link: str = Field(default="", max_length=2048)
    note: str = Field(default="", max_length=1000)
    checked: bool = False
    surpriseShare: bool = False


class LogEntry(BaseModel):
    id: str = Field(min_length=1, max_length=100)
    text: str = Field(min_length=1, max_length=500)
    time: str = Field(default="", max_length=20)


class SharedState(BaseModel):
    budgetTarget: float = Field(default=400, ge=1, le=1_000_000)
    items: list[WishlistItem] = Field(default_factory=list, max_length=500)
    deletedItems: list[WishlistItem] = Field(default_factory=list, max_length=500)
    logs: list[LogEntry] = Field(default_factory=list, max_length=60)


class CreateShareRequest(BaseModel):
    name: str = Field(min_length=1, max_length=40)
    state: SharedState


class JoinShareRequest(BaseModel):
    name: str = Field(min_length=1, max_length=40)


class UpdateShareRequest(BaseModel):
    state: SharedState
    version: int = Field(ge=1)


def normalize_name(value: str) -> str:
    value = " ".join(value.strip().split())
    if not value or len(value) > 40:
        raise HTTPException(status_code=422, detail="Naam moet 1 tot 40 tekens bevatten.")
    return value


def clean_state(state: SharedState) -> dict[str, Any]:
    payload = state.model_dump()
    for collection in ("items", "deletedItems"):
        cleaned = []
        for item in payload[collection]:
            item["category"] = item["category"] if item["category"] in CATEGORIES else "Tech & Gear"
            link = item.get("link", "").strip()
            if link:
                parsed = urlparse(link)
                if parsed.scheme not in {"http", "https"} or not parsed.netloc:
                    item["link"] = ""
            cleaned.append(item)
        payload[collection] = cleaned
    payload["logs"] = payload["logs"][-60:]
    return payload


def make_code() -> str:
    while True:
        raw = "".join(secrets.choice(CODE_ALPHABET) for _ in range(12))
        return f"GW-{raw[:4]}-{raw[4:8]}-{raw[8:]}"


def get_member(code: str, authorization: str | None = Header(default=None)):
    if not CODE_RE.fullmatch(code):
        raise HTTPException(status_code=404, detail="De deelcode bestaat niet.")
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Authenticatie vereist.")
    token = authorization[7:].strip()
    if len(token) < 40 or len(token) > 200:
        raise HTTPException(status_code=401, detail="Ongeldige toegangssleutel.")
    token_hash = digest(token)
    with db_session() as db:
        row = db.execute(
            """SELECT s.id AS share_id, s.state_json, s.version, m.display_name
               FROM members m JOIN shares s ON s.id = m.share_id
               WHERE s.code_hash = ? AND m.token_hash = ?""",
            (digest(code), token_hash),
        ).fetchone()
    if row is None:
        raise HTTPException(status_code=401, detail="Deelcode of toegangssleutel is ongeldig.")
    return dict(row)


@app.middleware("http")
async def security_headers_and_body_limit(request: Request, call_next):
    if request.method in {"POST", "PUT"}:
        content_length = request.headers.get("content-length")
        if content_length and content_length.isdigit() and int(content_length) > MAX_REQUEST_BYTES:
            return Response("Request te groot.", status_code=413)
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    return response


@app.get("/api/health")
def health():
    return {"status": "ok", "service": "Glass Wave Share API", "version": APP_VERSION}


@app.post("/api/shares")
def create_share(payload: CreateShareRequest, request: Request):
    rate_limit(request, "create", 8)
    name = normalize_name(payload.name)
    state_json = json.dumps(clean_state(payload.state), ensure_ascii=False, separators=(",", ":"))
    for _ in range(5):
        code = make_code()
        token = secrets.token_urlsafe(48)
        try:
            with db_session() as db:
                cursor = db.execute(
                    "INSERT INTO shares(code_hash, state_json, version, created_at) VALUES (?, ?, 1, ?)",
                    (digest(code), state_json, utc_now()),
                )
                share_id = cursor.lastrowid
                db.execute(
                    "INSERT INTO members(token_hash, share_id, display_name, created_at) VALUES (?, ?, ?, ?)",
                    (digest(token), share_id, name, utc_now()),
                )
            return {"code": code, "access_token": token, "version": 1}
        except sqlite3.IntegrityError:
            continue
    raise HTTPException(status_code=503, detail="Kon geen unieke deelcode genereren. Probeer opnieuw.")


@app.post("/api/shares/{code}/join")
def join_share(code: str, payload: JoinShareRequest, request: Request):
    rate_limit(request, "join", 12)
    if not CODE_RE.fullmatch(code):
        raise HTTPException(status_code=404, detail="De deelcode bestaat niet.")
    name = normalize_name(payload.name)
    token = secrets.token_urlsafe(48)
    with db_session() as db:
        share = db.execute(
            "SELECT id, state_json, version FROM shares WHERE code_hash = ?",
            (digest(code),),
        ).fetchone()
        if share is None:
            raise HTTPException(status_code=404, detail="De deelcode bestaat niet.")
        db.execute(
            "INSERT INTO members(token_hash, share_id, display_name, created_at) VALUES (?, ?, ?, ?)",
            (digest(token), share["id"], name, utc_now()),
        )
    return {
        "code": code,
        "access_token": token,
        "version": share["version"],
        "state": json.loads(share["state_json"]),
    }


@app.get("/api/shares/{code}/state")
def read_share_state(code: str, member=Depends(get_member)):
    return {"state": json.loads(member["state_json"]), "version": member["version"]}


@app.put("/api/shares/{code}/state")
def update_share_state(code: str, payload: UpdateShareRequest, member=Depends(get_member)):
    state_json = json.dumps(clean_state(payload.state), ensure_ascii=False, separators=(",", ":"))
    with db_session() as db:
        db.execute(
            "UPDATE shares SET state_json = ?, version = version + 1 WHERE id = ?",
            (state_json, member["share_id"]),
        )
        row = db.execute(
            "SELECT version FROM shares WHERE id = ?",
            (member["share_id"],),
        ).fetchone()
    return {"saved": True, "version": row["version"]}


@app.post("/api/shares/{code}/leave")
def leave_share(code: str, member=Depends(get_member), authorization: str | None = Header(default=None)):
    token = authorization[7:].strip()
    with db_session() as db:
        db.execute(
            "DELETE FROM members WHERE token_hash = ? AND share_id = ?",
            (digest(token), member["share_id"]),
        )
        remaining = db.execute(
            "SELECT COUNT(*) AS count FROM members WHERE share_id = ?",
            (member["share_id"],),
        ).fetchone()["count"]
        if remaining == 0:
            db.execute("DELETE FROM shares WHERE id = ?", (member["share_id"],))
    return {"left": True}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("server:app", host="0.0.0.0", port=int(os.getenv("PORT", "8000")), reload=False)
