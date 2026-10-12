from __future__ import annotations

import uuid

from fastapi import FastAPI, Header, Query

app = FastAPI(title="CounterFlow isolated fictional decoy", docs_url=None, redoc_url=None)


@app.get("/health/live")
def live():
    return {"status": "live"}


@app.get("/api/search")
def search(q: str = Query(default="", max_length=160), x_request_id: str | None = Header(default=None)):
    request_id = x_request_id or str(uuid.uuid4())
    # All records are fictional and kept in this service; there is no origin DB connection.
    fictional = [
        {"id": "decoy-ink-01", "name": "Midnight fountain pen"},
        {"id": "decoy-map-02", "name": "Northstar route planner"},
        {"id": "decoy-case-03", "name": "Project Meridian travel case"},
    ]
    matches = [item for item in fictional if not q or q.casefold() in item["name"].casefold()]
    # An adversarial search that matches no decoy records still gets fictional
    # results; an empty result would make the deception behavior obvious.
    if q and not matches:
        matches = fictional
    return {"request_id": request_id, "count": len(matches), "products": matches}
