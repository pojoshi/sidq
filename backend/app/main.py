import os
import secrets

from datetime import datetime, timezone
from typing import Literal

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from pgvector import Vector
from psycopg.types.json import Jsonb
from pydantic import BaseModel, Field

from . import db, text

app = FastAPI(title="Sidq API", version="0.1.0")

SIM_THRESHOLD = float(os.environ.get("SIM_THRESHOLD", "0.55"))
NEAR_DUPLICATE = float(os.environ.get("NEAR_DUPLICATE", "0.9"))
Verdict = Literal["scam", "careful", "ok"]


def operator_key(x_api_key: str | None = Header(default=None)):
    expected = os.environ.get("OPERATOR_API_KEY")
    if expected and not (x_api_key and secrets.compare_digest(x_api_key, expected)):
        raise HTTPException(401, "operator key required")


class ReportIn(BaseModel):
    text: str = Field(min_length=1, max_length=6000)
    sender: str | None = Field(default=None, max_length=120)
    channel: Literal["SMS", "WhatsApp", "Call", "Email", "Social"]
    verdict: Verdict
    score: int = Field(ge=0, le=100)
    signs: list[str] = Field(default_factory=list, max_length=30)
    observed_at: datetime | None = None


NAMES = [("remote", "Remote-access request"), ("credential", "Code or OTP request"),
         ("payment", "Fee or payment scam"), ("bait", "Prize or refund bait")]


def campaign_name(signs: list[str]) -> str:
    for sid, label in NAMES:
        if sid in signs:
            return label
    return "Suspicious messages"


@app.get("/healthz")
def healthz():
    with db.conn() as c:
        c.execute("SELECT 1")
    return {"ok": True}


@app.post("/reports", status_code=201)
def create_report(r: ReportIn):
    masked = text.mask(r.text)
    if not masked:
        raise HTTPException(422, "text is empty after cleaning")
    emb = Vector(text.embed(masked))
    ind = text.indicators(masked, r.sender)
    when = r.observed_at or datetime.now(timezone.utc)
    with db.conn() as c:
        campaign_id, evidence = None, None
        if r.verdict != "ok":
            near = c.execute(
                "SELECT campaign_id, 1 - (embedding <=> %s) AS sim FROM reports "
                "WHERE campaign_id IS NOT NULL ORDER BY embedding <=> %s LIMIT 1", (emb, emb)).fetchone()
            shared = c.execute(
                "SELECT campaign_id FROM reports WHERE campaign_id IS NOT NULL AND indicators && %s "
                "ORDER BY observed_at DESC LIMIT 1", (ind,)).fetchone() if ind else None
            # order matters: near-identical wording, then a shared indicator, then similar wording
            if near and near["sim"] >= NEAR_DUPLICATE:
                campaign_id, evidence = near["campaign_id"], f"near-identical wording ({near['sim']:.2f})"
            elif shared:
                campaign_id, evidence = shared["campaign_id"], "shared indicator"
            elif near and near["sim"] >= SIM_THRESHOLD:
                campaign_id, evidence = near["campaign_id"], f"similar wording ({near['sim']:.2f})"
            if campaign_id is None:
                campaign_id = c.execute(
                    "INSERT INTO campaigns (name, first_seen, last_seen) VALUES (%s,%s,%s) RETURNING id",
                    (campaign_name(r.signs), when, when)).fetchone()["id"]
                evidence = "new campaign"
            c.execute("UPDATE campaigns SET report_count = report_count + 1, "
                      "first_seen = LEAST(first_seen, %s), last_seen = GREATEST(last_seen, %s) WHERE id = %s",
                      (when, when, campaign_id))
        row = c.execute(
            "INSERT INTO reports (observed_at, channel, sender, verdict, score, signs, masked_text, indicators, embedding, campaign_id) "
            "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id",
            (when, r.channel, text.clean(r.sender or "")[:120] or None, r.verdict, r.score, r.signs, masked, ind, emb, campaign_id)).fetchone()
        c.commit()
    return {"id": row["id"], "campaign_id": campaign_id, "grouped_by": evidence, "stored_text": masked}


@app.get("/reports/{rid}/similar", dependencies=[Depends(operator_key)])
def similar(rid: int, k: int = Query(5, ge=1, le=25)):
    with db.conn() as c:
        me = c.execute("SELECT embedding FROM reports WHERE id = %s", (rid,)).fetchone()
        if not me:
            raise HTTPException(404, "report not found")
        rows = c.execute(
            "SELECT id, campaign_id, verdict, masked_text, 1 - (embedding <=> %s) AS similarity FROM reports "
            "WHERE id <> %s ORDER BY embedding <=> %s LIMIT %s", (me["embedding"], rid, me["embedding"], k)).fetchall()
    return [{**r, "similarity": round(float(r["similarity"]), 3)} for r in rows]


@app.get("/campaigns", dependencies=[Depends(operator_key)])
def campaigns():
    with db.conn() as c:
        rows = c.execute(
            "SELECT c.id, c.name, c.report_count, c.first_seen, c.last_seen, "
            "COALESCE((SELECT array_agg(DISTINCT i) FROM reports r, unnest(r.indicators) i WHERE r.campaign_id = c.id), '{}') AS indicators, "
            "(SELECT masked_text FROM reports r WHERE r.campaign_id = c.id ORDER BY observed_at LIMIT 1) AS example "
            "FROM campaigns c ORDER BY c.report_count DESC, c.id").fetchall()
    return rows


@app.get("/campaigns/{cid}", dependencies=[Depends(operator_key)])
def campaign(cid: int):
    with db.conn() as c:
        camp = c.execute("SELECT * FROM campaigns WHERE id = %s", (cid,)).fetchone()
        if not camp:
            raise HTTPException(404, "campaign not found")
        reps = c.execute("SELECT id, observed_at, channel, sender, verdict, score, masked_text FROM reports WHERE campaign_id = %s ORDER BY observed_at", (cid,)).fetchall()
    return {**camp, "reports": reps}


@app.get("/stats", dependencies=[Depends(operator_key)])
def stats():
    with db.conn() as c:
        return c.execute(
            "SELECT count(*) AS reports, count(*) FILTER (WHERE verdict='scam') AS scams, "
            "(SELECT count(*) FROM campaigns) AS campaigns, (SELECT count(*) FROM cases) AS cases FROM reports").fetchone()


QUESTIONS = {"code": "Did you share a code, password or card details?", "money": "Did you pay or transfer any money?",
             "app": "Did you install an app or give remote access?", "link": "Did you open the link or log in on a page?"}


class CaseIn(BaseModel):
    report_id: int


class AnswerIn(BaseModel):
    question: Literal["code", "money", "app", "link"]
    answer: Literal["yes", "no", "unsure"]
    channel: str = Field(default="App", max_length=30)


def priority(a: dict) -> str:
    if "yes" in (a.get("code"), a.get("money"), a.get("app")):
        return "P1 urgent"
    return "P2 soon" if a.get("link") == "yes" else "P3 routine"


def handoff(case: dict, rep: dict) -> str:
    a = case["answers"]
    known = [f"{QUESTIONS[k][:-1]}: {v}" for k, v in a.items()]
    ask = [q for k, q in QUESTIONS.items() if k not in a]
    steps = []
    if a.get("code") == "yes": steps.append("Hold SIM replacement and number porting; guide a password reset; customer calls their bank.")
    if a.get("money") == "yes": steps.append("Escalate to fraud with the bank partner; record payee details for recall.")
    if a.get("app") == "yes": steps.append("Customer removes the remote-access app now; check banking apps for activity.")
    if a.get("link") == "yes": steps.append("Change any password typed on the page; watch the line for unusual charges.")
    steps = steps or ["Add the indicators to the campaign. Customer only needs to block the sender."]
    lines = [f"CASE {case['id']} · {priority(a).upper()}", f"Rated: {rep['verdict']} ({rep['score']}/100) via {rep['channel']}",
             f"Sender: {rep['sender'] or 'not provided'}", f"Message (masked): {rep['masked_text'][:280]}", "",
             "Already answered, do not ask again:", *([f"  - {x}" for x in known] or ["  - nothing yet"]), "",
             "Only ask this:", *([f"  - {x}" for x in ask] or ["  - nothing: all answered"]), "", "Suggested next steps:", *[f"  - {s}" for s in steps]]
    return "\n".join(lines)


@app.post("/cases", status_code=201)
def open_case(body: CaseIn):
    cid = "SS-" + secrets.token_hex(3).upper()
    with db.conn() as c:
        if not c.execute("SELECT 1 FROM reports WHERE id = %s", (body.report_id,)).fetchone():
            raise HTTPException(404, "report not found")
        c.execute("INSERT INTO cases (id, report_id, timeline) VALUES (%s,%s,%s)",
                  (cid, body.report_id, Jsonb([{"t": datetime.now(timezone.utc).isoformat(), "who": "Customer", "text": "Opened this case from the app."}])))
        c.commit()
    return {"id": cid}


def _load_case(c, cid):
    case = c.execute("SELECT * FROM cases WHERE id = %s", (cid,)).fetchone()
    if not case:
        raise HTTPException(404, "case not found")
    rep = c.execute("SELECT * FROM reports WHERE id = %s", (case["report_id"],)).fetchone()
    return case, rep


@app.post("/cases/{cid}/answers")
def answer(cid: str, body: AnswerIn):
    with db.conn() as c:
        case, rep = _load_case(c, cid)
        a = {**case["answers"], body.question: body.answer}
        tl = case["timeline"] + [{"t": datetime.now(timezone.utc).isoformat(), "who": f"Customer ({body.channel})", "text": f"Answered: {QUESTIONS[body.question]} {body.answer}"}]
        c.execute("UPDATE cases SET answers = %s, timeline = %s WHERE id = %s", (Jsonb(a), Jsonb(tl), cid))
        c.commit()
    return {"priority": priority(a)}


@app.get("/cases/{cid}", dependencies=[Depends(operator_key)])
def get_case(cid: str, channel: str = Query("Call centre", max_length=30)):
    with db.conn() as c:
        case, rep = _load_case(c, cid)
        tl = case["timeline"] + [{"t": datetime.now(timezone.utc).isoformat(), "who": f"Agent ({channel})", "text": "Opened the case. The customer did not have to repeat anything."}]
        c.execute("UPDATE cases SET timeline = %s WHERE id = %s", (Jsonb(tl), cid))
        c.commit()
    return {"id": cid, "priority": priority(case["answers"]), "handoff": handoff(case, rep), "timeline": tl}
