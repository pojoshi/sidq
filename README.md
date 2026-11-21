# Sidq

Sidq (صدق, "truthfulness") helps telecom customers tell real support from fake support. You paste a message or a call transcript, and it says whether it looks like a scam and shows the exact phrases that gave it away. It reads English, Arabic and Arabic typed in Latin letters.

I built it for the Further in Tech AI Challenge 2026 (Challenge 03, the fake customer support trap), and borrowed the best parts of challenges 01 and 02: nobody should have to explain their problem twice, and it should work for people who can't easily read or type.

Live demo: https://pojoshi.github.io/sidq/ (one static page, the checker makes no network requests)

![Checking a fake traffic-fine text](docs/overview.png)

## What's in it

- **Check:** rating, highlighted phrases, reasons, and a link inspector that diffs each link against the official address.
- **Seal:** an operator can stamp genuine messages with a short HMAC code over the exact text. A fake can't carry one and an edited message fails.
- **Live call:** the transcript is re-scored after every line, so the warning comes during the call. The alert is visual, for customers with hearing loss.
- **Check the agent:** a code tied to the case that changes every 30 seconds. The agent reads it out, the customer types it in. Nobody is asked for a code.
- **Case file:** one case follows the customer across app, WhatsApp, call centre and store, with a status and a handoff for the next agent.
- **Learn:** short tips you can listen to, and a ten-message quiz that shows the checker's real answers.
- **Operator view:** mock reports grouped into campaigns, a review queue, and a red-team table showing how many disguised scams still get through.
- **Accessibility:** read aloud, simple view, high contrast, larger text, a four-question mode for people who can't paste.
- **Bahrain patterns:** fake traffic-fine, parcel and eGov/eKey texts, written from public warnings. The examples are invented.
- **Telecom cases:** call-forwarding codes, SIM-swap requests, callback scams, links that hide their real address.

## Run it

The demo is `index.html`. Open it in a browser. The sign-in is a demo with no accounts.

The backend in `backend/` is a FastAPI service on Postgres 16 with pgvector. It stores masked reports, groups them into campaigns and keeps cases.

```
docker compose up --build
python backend/seed/seed.py http://localhost:8000
```

Tests (need a Postgres with pgvector):

```
cd backend
pip install -r requirements.txt
TEST_DATABASE_URL=postgresql://postgres:dev@localhost:5432/sidq_test pytest -q
```

Campaign grouping order is near-identical wording, then a shared indicator, then similar wording. Operator endpoints need an `X-API-Key` header when `OPERATOR_API_KEY` is set.

## How the checking works

Pattern rules do most of the work, with a small Naive Bayes classifier on top. Both run in the browser and each result lists its reasons. The classifier is trained on about 40 invented examples, so treat its numbers as a demonstration. Text is cleaned first (look-alike letters, hidden characters, spaced-out words) and a red-team table in the Operator tab shows how much that helps.

## Limits

- The classifier is small and the metrics are on invented data.
- The seal and agent-code secrets are visible in the page source. A real version would use public-key signatures and check codes on the operator's side.
- Screenshots can be attached but their text isn't read. That needs an OCR service.
- The speech buttons use the browser's own speech service, which in Chrome sends audio to Google. The checker itself sends nothing.
- Live call takes typed, pasted or spoken lines. There is no on-device speech-to-text.
- Accessibility hasn't been tested with real users, and read-aloud voices may not include Arabic.
- A language-model layer is a design, not built. The case file in the demo lives in the page only.
- Cost figures in the plan tab are placeholders. The regulation notes (Bahrain PDPL, TRA guidelines for fraudulent SMS) are a summary, not legal advice.

## Licence

MIT. Pooja Rajendra Joshi.
