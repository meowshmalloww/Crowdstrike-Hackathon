from __future__ import annotations

import os
import sqlite3
import uuid
from contextlib import asynccontextmanager

from fastapi import FastAPI, Header, HTTPException, Query


PRODUCTS = [
    ("prod-mug", "CounterFlow ceramic mug", 1),
    ("prod-notebook", "Startup field notebook", 1),
    ("prod-lanyard", "Blue team conference lanyard", 1),
    ("synthetic-canary-2026", "Internal acquisition prototype", 0),
]


def create_app(vulnerable: bool | None = None, database_path: str = ":memory:") -> FastAPI:
    lab_profile = os.getenv("APP_PROFILE", "lab") == "lab"
    if vulnerable is None:
        vulnerable = lab_profile and os.getenv("LAB_VULNERABLE", "0") == "1"
    if vulnerable and not lab_profile:
        raise RuntimeError("The intentionally vulnerable origin is restricted to APP_PROFILE=lab")
    connection = sqlite3.connect(database_path, check_same_thread=False)
    connection.row_factory = sqlite3.Row
    connection.execute("CREATE TABLE IF NOT EXISTS products (id TEXT PRIMARY KEY, name TEXT NOT NULL, public INTEGER NOT NULL)")
    connection.execute("DELETE FROM products")
    connection.executemany("INSERT INTO products (id, name, public) VALUES (?, ?, ?)", PRODUCTS)
    connection.commit()

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        yield
        connection.close()

    app = FastAPI(title="CounterFlow disposable storefront", docs_url=None, redoc_url=None, lifespan=lifespan)
    app.state.vulnerable = vulnerable

    @app.get("/health/live")
    def live():
        return {"status": "live"}

    @app.get("/health/ready")
    def ready():
        try:
            connection.execute("SELECT 1")
        except sqlite3.Error as exc:
            raise HTTPException(status_code=503, detail="SQLite unavailable") from exc
        return {"status": "ready", "profile": "lab"}

    @app.get("/")
    def home():
        return {"name": "CounterFlow Demo Store", "search": "/api/search?q=mug"}

    @app.get("/api/search")
    def search(q: str = Query(default="", max_length=160), x_request_id: str | None = Header(default=None)):
        request_id = x_request_id or str(uuid.uuid4())
        if vulnerable:
            # LAB-ONLY: deliberately unsafe query for a controlled SQL injection demo.
            sql = f"SELECT id, name, public FROM products WHERE public = 1 AND name LIKE '%{q}%'"
            try:
                rows = connection.execute(sql).fetchall()
            except sqlite3.Error:
                raise HTTPException(status_code=400, detail="Search query rejected") from None
        else:
            rows = connection.execute(
                "SELECT id, name, public FROM products WHERE public = 1 AND name LIKE ?",
                (f"%{q}%",),
            ).fetchall()
        products = [
            {"id": row["id"], "name": row["name"], "canary_marker": row["id"] if row["public"] == 0 else None}
            for row in rows
        ]
        return {"request_id": request_id, "query": q, "count": len(products), "products": products}

    return app


app = create_app()
