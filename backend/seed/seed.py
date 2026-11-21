import json
import pathlib
import sys

import httpx

base = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8000"
items = json.loads((pathlib.Path(__file__).parent / "mock_reports.json").read_text())
with httpx.Client(base_url=base, timeout=20) as c:
    for it in items:
        it = {k: v for k, v in it.items() if k != "truth" and v is not None}
        c.post("/reports", json=it).raise_for_status()
    camps = c.get("/campaigns").json()
    print(f"{len(items)} reports -> {len(camps)} campaigns")
    for k in camps:
        print(f"  #{k['id']} {k['name']:<24} {k['report_count']:>3} reports  {', '.join(k['indicators'][:3])}")
