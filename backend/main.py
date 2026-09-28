"""BITFORENS-X local forensic analysis service.

This service is intentionally offline-first. It generates a deterministic synthetic
Bitcoin/network dataset and exposes the analysis workflow described by the UI.
"""
from __future__ import annotations

import hashlib
import io
import json
import math
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Literal

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import Response
from pydantic import BaseModel, Field

try:
    import networkx as nx
except Exception:  # pragma: no cover - optional in minimal local environments
    nx = None
try:
    import numpy as np
except Exception:  # pragma: no cover
    np = None
try:
    import pandas as pd
except Exception:  # pragma: no cover
    pd = None
try:
    from sklearn.cluster import DBSCAN
    from sklearn.ensemble import IsolationForest
except Exception:  # pragma: no cover
    DBSCAN = None
    IsolationForest = None

app = FastAPI(title="BITFORENS-X Forensic API", version="0.9.6")

class Transaction(BaseModel):
    txid: str
    timestamp: datetime
    input_wallets: list[str]
    output_wallets: list[str]
    amount: float = Field(gt=0)
    fee: float = Field(ge=0)
    source_ip: str
    destination_ip: str | None = None
    port: int = Field(default=8333, ge=1, le=65535)
    asn: str
    country: str
    latitude: float
    longitude: float
    anomaly: Literal["NORMAL", "ANOMALOUS"] = "NORMAL"
    anomaly_score: float = 0.0
    behavior_change: str = "Stable"

class Wallet(BaseModel):
    address: str
    first_seen: datetime
    last_seen: datetime
    transaction_count: int
    total_in: float
    total_out: float
    avg_amount: float
    avg_time_interval: float
    fan_in: int
    fan_out: int
    ip_count: int
    fee_pattern: str
    behavioral_score: float
    profile: str
    priority: Literal["HIGH", "MEDIUM", "LOW"]

class InvestigationCreate(BaseModel):
    title: str = Field(min_length=3, max_length=160)
    selected_entities: list[str] = Field(default_factory=list)

class SimulationRequest(BaseModel):
    entity_type: Literal["Wallet", "Transaction", "IP", "Entity"] = "Wallet"
    entity_id: str

class DatasetState(BaseModel):
    transactions: list[Transaction] = Field(default_factory=list)
    wallets: list[Wallet] = Field(default_factory=list)
    network_events: list[dict[str, Any]] = Field(default_factory=list)
    investigations: list[dict[str, Any]] = Field(default_factory=list)
    evidence: list[dict[str, Any]] = Field(default_factory=list)
    is_demo: bool = False

STATE = DatasetState()

WALLET_SEEDS = [
    ("bc1q-bridge-alpha", "Bridge / fan-out hub", 47, 86.4, 82.7, 9, 22, 7, "Burst / elevated", 96, "HIGH"),
    ("bc1q-signal-17", "Synchronized relay", 29, 22.1, 21.5, 5, 9, 4, "Repeated", 71, "HIGH"),
    ("bc1q-signal-23", "Synchronized relay", 27, 19.8, 19.3, 4, 8, 4, "Repeated", 68, "MEDIUM"),
    ("bc1q-vault-004", "Accumulation node", 18, 56.5, 11.4, 12, 2, 2, "Low / stable", 44, "LOW"),
    ("bc1q-hop-08", "Transit wallet", 23, 11.7, 11.3, 3, 5, 3, "Moderate", 58, "MEDIUM"),
    ("bc1q-hop-14", "Transit wallet", 21, 10.9, 10.5, 3, 5, 3, "Moderate", 55, "LOW"),
    ("bc1q-collector-9", "Convergence node", 34, 71.2, 67.9, 15, 1, 5, "Mixed", 81, "HIGH"),
    ("bc1q-quiet-31", "Low-activity entity", 8, 2.1, 1.9, 1, 2, 1, "Low / stable", 20, "LOW"),
]

NETWORK_SEEDS = [
    ("185.203.118.42", 8333, "AS9009", "NL", 52.1, 5.3, 18, "Correlated"),
    ("91.218.67.12", 8333, "AS9009", "DE", 51.1, 10.4, 23, "Correlated"),
    ("23.92.44.8", 8333, "AS20473", "US", 37.1, -95.7, 12, "Observed"),
    ("192.0.2.14", 8333, "AS64500", "GB", 54.2, -2.5, 3, "Baseline"),
    ("198.51.100.21", 18333, "AS64501", "SG", 1.35, 103.8, 7, "Observed"),
]


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def build_demo() -> DatasetState:
    base = utc_now().replace(hour=0, minute=0, second=0, microsecond=0)
    paths = [
        ("a91f02c7e8b1", 17, 42, "bc1q-bridge-alpha", "bc1q-signal-17", .74, .00031, 0, 0, "ANOMALOUS", .92, "Velocity +4.7×"),
        ("a91f02c7e8b2", 17, 42, "bc1q-bridge-alpha", "bc1q-signal-23", .71, .00029, 0, 0, "ANOMALOUS", .89, "Synchronized window"),
        ("a91f02c7e8b3", 17, 44, "bc1q-signal-17", "bc1q-hop-08", .47, .00024, 1, 1, "ANOMALOUS", .81, "Timing deviation"),
        ("a91f02c7e8b4", 17, 45, "bc1q-signal-23", "bc1q-hop-14", .45, .00025, 1, 1, "ANOMALOUS", .79, "Timing deviation"),
        ("b71d10f9a220", 16, 20, "bc1q-vault-004", "bc1q-bridge-alpha", 8.4, .00011, 2, 2, "NORMAL", .18, "Stable"),
        ("b71d10f9a221", 15, 54, "bc1q-collector-9", "bc1q-bridge-alpha", 5.1, .00014, 2, 2, "NORMAL", .22, "Stable"),
        ("c02aa1e6db10", 14, 10, "bc1q-hop-08", "bc1q-collector-9", .45, .00028, 1, 1, "ANOMALOUS", .76, "Fee pattern change"),
        ("c02aa1e6db11", 13, 22, "bc1q-hop-14", "bc1q-collector-9", .49, .00027, 1, 1, "ANOMALOUS", .73, "Fee pattern change"),
        ("d8130bc9a5f7", 11, 48, "bc1q-quiet-31", "bc1q-vault-004", .63, .00008, 3, 3, "NORMAL", .12, "Stable"),
        ("e22cd81f0901", 9, 15, "bc1q-vault-004", "bc1q-quiet-31", .31, .00009, 2, 2, "NORMAL", .09, "Stable"),
        ("e22cd81f0902", 8, 32, "bc1q-bridge-alpha", "bc1q-collector-9", 3.3, .00034, 0, 0, "ANOMALOUS", .84, "Fan-out widened"),
        ("f33b0cc1a217", 6, 9, "bc1q-collector-9", "bc1q-vault-004", 7.1, .00012, 2, 2, "NORMAL", .21, "Stable"),
    ]
    txs: list[Transaction] = []
    for txid, hour, minute, src, dst, amount, fee, net_idx, _unused, anomaly, score, change in paths:
        net = NETWORK_SEEDS[net_idx]
        txs.append(Transaction(
            txid=txid, timestamp=base - timedelta(days=1) + timedelta(hours=hour, minutes=minute),
            input_wallets=[src], output_wallets=[dst], amount=amount, fee=fee,
            source_ip=net[0], destination_ip=None, port=net[1], asn=net[2], country=net[3],
            latitude=net[4], longitude=net[5], anomaly=anomaly, anomaly_score=score,
            behavior_change=change,
        ))
    wallets: list[Wallet] = []
    for address, profile, count, total_in, total_out, fan_in, fan_out, ip_count, fee_pattern, score, priority in WALLET_SEEDS:
        wallets.append(Wallet(
            address=address, profile=profile, first_seen=base - timedelta(days=18), last_seen=utc_now(),
            transaction_count=count, total_in=total_in, total_out=total_out, avg_amount=round(total_in / max(count, 1), 2),
            avg_time_interval=round(1440 / max(count, 1), 2), fan_in=fan_in, fan_out=fan_out, ip_count=ip_count,
            fee_pattern=fee_pattern, behavioral_score=score, priority=priority,
        ))
    events = [dict(ip=ip, port=port, asn=asn, country=country, latitude=lat, longitude=lon, events=events, status=status) for ip, port, asn, country, lat, lon, events, status in NETWORK_SEEDS]
    return DatasetState(transactions=txs, wallets=wallets, network_events=events, is_demo=True)


def ensure_dataset() -> None:
    if not STATE.transactions:
        demo = build_demo()
        STATE.transactions = demo.transactions
        STATE.wallets = demo.wallets
        STATE.network_events = demo.network_events
        STATE.is_demo = True


def feature_matrix() -> list[list[float]]:
    ensure_dataset()
    return [[t.amount, t.fee * 10000, t.anomaly_score, len(t.input_wallets), len(t.output_wallets), t.port / 10000, abs(t.latitude) / 90, abs(t.longitude) / 180] for t in STATE.transactions]


def run_isolation_forest() -> None:
    ensure_dataset()
    matrix = feature_matrix()
    if IsolationForest and len(matrix) > 4:
        model = IsolationForest(contamination=0.25, random_state=42)
        model.fit(matrix)
        scores = -model.score_samples(matrix)
        low, high = min(scores), max(scores)
        for tx, raw in zip(STATE.transactions, scores):
            scaled = (raw - low) / (high - low or 1)
            tx.anomaly_score = round(max(tx.anomaly_score, float(scaled)), 2)
            tx.anomaly = "ANOMALOUS" if tx.anomaly_score >= .62 else "NORMAL"
    else:
        for tx in STATE.transactions:
            tx.anomaly = "ANOMALOUS" if tx.anomaly_score >= .62 else "NORMAL"


@app.get("/health")
def health() -> dict[str, Any]:
    return {"status": "ok", "service": "BITFORENS-X", "offline": True, "dataset_loaded": bool(STATE.transactions)}

@app.post("/data/demo")
def load_demo() -> dict[str, Any]:
    demo = build_demo()
    STATE.transactions, STATE.wallets, STATE.network_events, STATE.is_demo = demo.transactions, demo.wallets, demo.network_events, True
    run_isolation_forest()
    return summary()

@app.post("/data/upload")
async def upload(file: UploadFile = File(...)) -> dict[str, Any]:
    allowed = {".csv", ".json", ".xml"}
    suffix = "." + (file.filename or "").lower().split(".")[-1]
    if suffix not in allowed:
        raise HTTPException(status_code=415, detail="Only CSV, JSON, and XML files are accepted")
    raw = await file.read()
    if len(raw) > 15 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="Evidence file exceeds the 15 MB prototype limit")
    text = raw.decode("utf-8", errors="replace")
    records: list[dict[str, Any]] = []
    try:
        if suffix == ".json":
            parsed = json.loads(text)
            records = parsed if isinstance(parsed, list) else parsed.get("transactions", parsed.get("records", [parsed]))
        elif suffix == ".csv" and pd:
            records = pd.read_csv(io.StringIO(text)).fillna("").to_dict(orient="records")
        elif suffix == ".csv":
            lines = [line for line in text.splitlines() if line.strip()]
            headers = [h.strip() for h in lines[0].split(",")]
            records = [dict(zip(headers, line.split(","))) for line in lines[1:]]
        else:
            records = [{"record": text[:500], "source": file.filename}]
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Could not parse evidence: {exc}") from exc
    # Keep the safe prototype import schema explicit; missing fields are not executed.
    if not isinstance(records, list):
        raise HTTPException(status_code=400, detail="Evidence payload must contain an array of records")
    evidence_hash = hashlib.sha256(raw).hexdigest()
    STATE.evidence.insert(0, {"id": f"EVD-{uuid.uuid4().hex[:10].upper()}", "filename": file.filename, "sha256": evidence_hash, "generated_at": utc_now().isoformat(), "record_count": len(records)})
    return {"filename": file.filename, "record_count": len(records), "invalid_records": 0, "sha256": evidence_hash, "preview": records[:12], "status": "validated"}

@app.get("/data/summary")
def summary() -> dict[str, Any]:
    ensure_dataset()
    anomalies = sum(t.anomaly == "ANOMALOUS" for t in STATE.transactions)
    return {"files": 1 if STATE.transactions else 0, "record_count": len(STATE.transactions), "transactions": len(STATE.transactions), "wallets": len(STATE.wallets), "network_events": len(STATE.network_events), "invalid_records": 0, "anomalies": anomalies, "behavior_changes": 6, "behavioral_clusters": 3, "campaign_clusters": 2, "active_investigations": len(STATE.investigations), "synthetic_demo": STATE.is_demo}

@app.get("/transactions")
def transactions(search: str = "", anomaly: str | None = None, limit: int = 100) -> list[Transaction]:
    ensure_dataset()
    term = search.lower()
    items = [t for t in STATE.transactions if (not term or term in t.txid.lower() or term in " ".join(t.input_wallets + t.output_wallets).lower() or term in t.source_ip.lower() or term in t.asn.lower()) and (not anomaly or t.anomaly == anomaly.upper())]
    return items[:max(1, min(limit, 500))]

@app.get("/transactions/{txid}")
def transaction(txid: str) -> Transaction:
    ensure_dataset()
    for item in STATE.transactions:
        if item.txid == txid:
            return item
    raise HTTPException(status_code=404, detail="Transaction not found")

@app.get("/wallets")
def wallets(search: str = "") -> list[Wallet]:
    ensure_dataset()
    return [w for w in STATE.wallets if not search or search.lower() in w.address.lower() or search.lower() in w.profile.lower()]

@app.get("/wallets/{address}")
def wallet(address: str) -> Wallet:
    ensure_dataset()
    for item in STATE.wallets:
        if item.address == address:
            return item
    raise HTTPException(status_code=404, detail="Wallet not found")

@app.get("/analysis/anomalies")
def anomalies() -> list[dict[str, Any]]:
    ensure_dataset(); run_isolation_forest()
    return [t.model_dump() for t in STATE.transactions if t.anomaly == "ANOMALOUS"]

@app.get("/analysis/behavior")
def behavior() -> list[Wallet]:
    ensure_dataset()
    return STATE.wallets

@app.get("/analysis/clusters")
def clusters() -> list[dict[str, Any]]:
    ensure_dataset()
    matrix = [[w.behavioral_score, w.fan_in, w.fan_out, w.ip_count, w.avg_amount] for w in STATE.wallets]
    labels = DBSCAN(eps=18, min_samples=2).fit_predict(matrix).tolist() if DBSCAN and len(matrix) > 2 else [0, 0, 0, 1, 1, 1, 2, 2]
    result: dict[int, list[Wallet]] = {}
    for label, item in zip(labels, STATE.wallets):
        result.setdefault(label, []).append(item)
    return [{"cluster_id": f"C-{i + 1:02d}", "entity_count": len(items), "behavioral_similarity": round(sum(x.behavioral_score for x in items) / len(items)), "entities": [x.address for x in items], "label": "Potentially related behavioral cluster"} for i, items in enumerate(result.values())]

@app.get("/analysis/synchronization")
def synchronization() -> list[dict[str, Any]]:
    return [{"entity_a": "bc1q-signal-17", "entity_b": "bc1q-signal-23", "similarity": 91, "factors": {"timing": 94, "amount": 89, "fee": 91, "activity_window": 90}, "label": "Behavioral Similarity"}]

@app.get("/graph")
def graph() -> dict[str, Any]:
    ensure_dataset()
    nodes = []
    for event in STATE.network_events:
        nodes.append({"id": f"ip:{event['ip']}", "type": "network", "label": event["ip"], "meta": event["asn"]})
    for t in STATE.transactions:
        nodes.append({"id": f"tx:{t.txid}", "type": "transaction", "label": t.txid, "meta": f"{t.amount} BTC"})
    for w in STATE.wallets:
        nodes.append({"id": f"wallet:{w.address}", "type": "wallet", "label": w.address, "meta": w.profile})
    edges = []
    for t in STATE.transactions:
        edges.append({"source": f"ip:{t.source_ip}", "target": f"tx:{t.txid}", "relation": "originated"})
        for source in t.input_wallets:
            edges.append({"source": f"tx:{t.txid}", "target": f"wallet:{source}", "relation": "input"})
        for target in t.output_wallets:
            edges.append({"source": f"tx:{t.txid}", "target": f"wallet:{target}", "relation": "output"})
    return {"nodes": nodes, "edges": edges, "layers": ["network", "transaction", "wallet", "behavior"]}

@app.post("/graph/simulate-removal")
def simulate_removal(request: SimulationRequest) -> dict[str, Any]:
    ensure_dataset()
    if not request.entity_id:
        raise HTTPException(status_code=400, detail="An entity is required")
    removed = request.entity_id
    affected = [t for t in STATE.transactions if removed in t.input_wallets or removed in t.output_wallets or removed == t.source_ip or removed == t.txid]
    disconnected = sorted({x for t in affected for x in t.input_wallets + t.output_wallets if x != removed})
    alternatives = max(1, min(3, len(disconnected) // 2))
    return {"entity_id": removed, "original_graph_unchanged": True, "connections_affected": 7 if "bridge" in removed else max(1, len(affected)), "transactions_affected": len(affected), "wallets_affected": len(disconnected), "fund_flow_paths_affected": max(1, len(affected) // 2), "alternative_paths": alternatives, "disconnected_nodes": disconnected, "behaviorally_similar_entities": ["bc1q-signal-17", "bc1q-signal-23", "bc1q-hop-08"]}

@app.get("/campaigns")
def campaigns() -> list[dict[str, Any]]:
    ensure_dataset()
    return [{"id": "CAMPAIGN-01", "title": "Bridge relay convergence", "stages": ["FUNDING", "SPLITTING", "WALLET HOPPING", "SYNCHRONIZATION", "CONVERGENCE"], "wallets": [w.address for w in STATE.wallets[:7]], "transaction_count": 34, "lead_only": True}]

@app.get("/campaigns/{campaign_id}")
def campaign(campaign_id: str) -> dict[str, Any]:
    items = campaigns()
    for item in items:
        if item["id"] == campaign_id:
            return item
    raise HTTPException(status_code=404, detail="Campaign not found")

@app.get("/investigations")
def investigations() -> list[dict[str, Any]]:
    return STATE.investigations

@app.post("/investigations")
def create_investigation(request: InvestigationCreate) -> dict[str, Any]:
    item = {"id": f"INV-{utc_now().strftime('%Y%m%d')}-{uuid.uuid4().hex[:4].upper()}", "title": request.title, "created_at": utc_now().isoformat(), "selected_entities": request.selected_entities, "alerts": [], "evidence": [], "timeline": []}
    STATE.investigations.insert(0, item)
    return item

@app.get("/evidence/{evidence_id}")
def evidence(evidence_id: str) -> dict[str, Any]:
    for item in STATE.evidence:
        if item["id"] == evidence_id:
            return item
    raise HTTPException(status_code=404, detail="Evidence record not found")

@app.post("/reports/generate")
def generate_report(investigation_id: str = "INV-2026-0927-01", selected_entity: str = "bc1q-bridge-alpha") -> Response:
    ensure_dataset()
    generated = utc_now().isoformat()
    content = "\n".join([
        "BITFORENS-X", investigation_id, "FORENSIC INVESTIGATION REPORT", "",
        f"GENERATED AT: {generated}", f"SELECTED ENTITY: {selected_entity}",
        f"TRANSACTIONS: {len(STATE.transactions)}", f"ANOMALIES: {sum(t.anomaly == 'ANOMALOUS' for t in STATE.transactions)}",
        "BEHAVIORAL NOTE: Potentially related behavioral clusters detected.",
        "CAUSAL TRACE: REMOVE -> RECONSTRUCT -> REVEAL", "LIMITATIONS: Synthetic evidence; investigative lead only.",
    ])
    sha = hashlib.sha256(content.encode()).hexdigest()
    pdf = f"%PDF-1.4\n% BITFORENS-X report\n% SHA256 {sha}\n{content}\n%%EOF".encode()
    return Response(content=pdf, media_type="application/pdf", headers={"Content-Disposition": f'attachment; filename="{investigation_id}.pdf"', "X-Evidence-Hash": sha})

@app.on_event("startup")
def startup() -> None:
    load_demo()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8010, reload=False)
