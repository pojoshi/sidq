import os

A = {"text": "URGENT: Your bill payment failed and your line will be suspended in 2 hours. Update your card details now: http://operatorx-billing.top/pay",
     "sender": "+973 3999 1234", "channel": "SMS", "verdict": "scam", "score": 90, "signs": ["urgency", "shortlink"]}


def rep(client, **kw):
    r = client.post("/reports", json={**A, **kw})
    assert r.status_code == 201, r.text
    return r.json()


def test_health(client):
    assert client.get("/healthz").json() == {"ok": True}


def test_report_is_masked_before_storage(client):
    out = rep(client, text="Send the code 482913 to +973 3999 1234 or mail me at victim@example.com")
    assert "482913" not in out["stored_text"] and "3999" not in out["stored_text"] and "victim@" not in out["stored_text"]


def test_same_domain_groups_into_one_campaign(client):
    a = rep(client)
    b = rep(client, text="Final notice! Pay now at http://operatorx-billing.top/pay or lose your line", sender="@x")
    assert a["campaign_id"] == b["campaign_id"] and b["grouped_by"] == "shared indicator"


def test_similar_wording_groups_without_shared_domain(client):
    a = rep(client, text="Congratulations! You have won a free iPhone. Pay the small delivery fee to claim your prize today.", sender=None, signs=["bait"])
    b = rep(client, text="Congratulations you have won a free iPhone, pay the delivery fee to claim your prize now", sender=None, signs=["bait"])
    assert a["campaign_id"] == b["campaign_id"], b


def test_unrelated_scams_stay_separate(client):
    a = rep(client)
    b = rep(client, text="Hello I am from technical support please install AnyDesk and read me the code", sender="@help_line", signs=["remote"])
    assert a["campaign_id"] != b["campaign_id"]


def test_lookalike_letters_and_spacing_still_group(client):
    a = rep(client, text="Please read me the code we just sent you to confirm your identity today", sender=None, signs=["credential"])
    b = rep(client, text="Please rеad mе thе cоde we just sent you to confirm your identity today", sender=None, signs=["credential"])  # Cyrillic letters
    assert a["campaign_id"] == b["campaign_id"]


def test_arabic_reports_group(client):
    t = "عزيزي العميل، سيتم تعليق خدمتك خلال ساعة. أرسل رمز التحقق الذي وصلك الآن لتجنب إيقاف الخط"
    a = rep(client, text=t, sender=None, signs=["credential"])
    b = rep(client, text=t.replace("ساعة", "ساعتين"), sender=None, signs=["credential"])
    assert a["campaign_id"] == b["campaign_id"]


def test_genuine_reports_are_not_clustered(client):
    out = rep(client, text="Your plan renews on 3 December. No action is needed.", verdict="ok", score=0, signs=[], sender=None)
    assert out["campaign_id"] is None


def test_campaign_listing_and_counts(client):
    rep(client); rep(client, text="Pay now at http://operatorx-billing.top/pay please")
    c = client.get("/campaigns").json()
    assert len(c) == 1 and c[0]["report_count"] == 2 and "operatorx-billing.top" in c[0]["indicators"]
    assert client.get(f"/campaigns/{c[0]['id']}").json()["reports"][0]["channel"] == "SMS"


def test_similar_endpoint_orders_by_similarity(client):
    a = rep(client)
    rep(client, text="Totally different message about a parcel delivery to your home", sender="@p", signs=[])
    b = rep(client, text="URGENT: your bill payment failed, line will be suspended in 3 hours. Update card details: http://operatorx-billing.top/pay")
    sims = client.get(f"/reports/{a['id']}/similar?k=2").json()
    assert sims[0]["id"] == b["id"] and sims[0]["similarity"] > sims[1]["similarity"]


def test_case_flow_and_priority(client):
    r = rep(client)
    cid = client.post("/cases", json={"report_id": r["id"]}).json()["id"]
    assert client.get(f"/cases/{cid}").json()["priority"] == "P3 routine"
    assert client.post(f"/cases/{cid}/answers", json={"question": "link", "answer": "yes"}).json()["priority"] == "P2 soon"
    assert client.post(f"/cases/{cid}/answers", json={"question": "code", "answer": "yes", "channel": "WhatsApp"}).json()["priority"] == "P1 urgent"
    g = client.get(f"/cases/{cid}?channel=Call%20centre").json()
    assert "do not ask again" in g["handoff"] and "SIM replacement" in g["handoff"]
    assert "Only ask this" in g["handoff"] and "pay or transfer" in g["handoff"]
    assert any("Agent (Call centre)" in e["who"] for e in g["timeline"])


def test_validation(client):
    assert client.post("/reports", json={**A, "text": ""}).status_code == 422
    assert client.post("/reports", json={**A, "text": "x" * 6001}).status_code == 422
    assert client.post("/reports", json={**A, "score": 101}).status_code == 422
    assert client.post("/reports", json={**A, "channel": "Fax"}).status_code == 422
    assert client.post("/cases", json={"report_id": 999}).status_code == 404
    assert client.get("/cases/SS-NOPE").status_code == 404
    assert client.get("/campaigns/999").status_code == 404


def test_sql_injection_is_inert(client):
    rep(client, sender="'; DROP TABLE reports; --", text="x'); DROP TABLE cases; -- pay at http://a-b.top")
    assert client.get("/stats").json()["reports"] == 1


def test_operator_key_required_when_configured(client):
    rep(client)
    os.environ["OPERATOR_API_KEY"] = "s3cret"
    assert client.get("/campaigns").status_code == 401
    assert client.get("/campaigns", headers={"X-API-Key": "wrong"}).status_code == 401
    assert client.get("/campaigns", headers={"X-API-Key": "s3cret"}).status_code == 200
    assert client.post("/reports", json=A).status_code == 201  # customers can still report


def test_shortener_domain_alone_does_not_merge_campaigns(client):
    a = rep(client, text="Claim your free gift now at bit.ly/free-gb-win", sender=None, signs=["bait"])
    b = rep(client, text="Your parcel fee is unpaid, pay at bit.ly/parcel-fee-7", sender=None, signs=["payment"])
    assert a["campaign_id"] != b["campaign_id"]
    c = rep(client, text="Last chance: bit.ly/free-gb-win", sender=None, signs=["bait"])
    assert c["campaign_id"] == a["campaign_id"]


def test_official_sender_is_not_an_indicator(client):
    from app.text import indicators
    assert indicators("hello", "+973 1700 0000") == [] and indicators("hello", "OperatorX") == [] and indicators("hello", "@operatorx_support") == []
    assert indicators("hello", "@operatorx_suport") == ["sender:operatorx_suport"]


def test_identical_wording_wins_over_a_shared_sender(client):
    a = rep(client, text="Your parcel could not be delivered. Pay a delivery fee at www.parcel-track.co", sender="+973 3000 1111", signs=["payment"])
    other = rep(client, text="Install AnyDesk so we can fix your line", sender="+973 3000 2222", signs=["remote"])
    b = rep(client, text="Your parcel could not be delivered. Pay a delivery fee at www.parcel-track.co", sender="+973 3000 2222", signs=["payment"])
    assert b["campaign_id"] == a["campaign_id"] != other["campaign_id"]
