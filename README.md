# Agentic Honey-Pot – Hackathon Submission

## Overview
This repository contains a FastAPI-based honeypot service built for the GUVI "AI for Fraud Detection & User Safety" hackathon. The API detects scam intent, responds in a believable confused-victim persona, collects actionable intelligence, and reports the final engagement to GUVI’s evaluation callback (see memory requirement).

## Architecture
- **Framework:** FastAPI + Pydantic (@main.py#10-168)
- **Runtime:** Python 3.10+
- **State:** In-memory session tracker accumulating message count, detection flag, and extracted intelligence (@main.py#123-154, @main.py#318-324)
- **Outgoing integration:** HTTP callback to `https://hackathon.guvi.in/api/updateHoneyPotFinalResult` via `httpx` once engagement criteria are met (@main.py#220-236)

## Key Capabilities
1. **API key enforcement** using the `x-api-key` header; secret sourced from `HONEYPOT_API_KEY` environment variable (@main.py#21-76).
2. **Scam detection heuristics** combining keyword spotting and urgency-based scoring (@main.py#70-186).
3. **Agent persona replies** that remain cooperative, avoid revealing detection, and adapt to conversation history (@main.py#246-327).
4. **Intelligence extraction** for bank accounts, UPI IDs, phishing links, phone numbers, and suspicious keywords using regex-driven parser (@main.py#189-202).
5. **Final result callback** scheduling via FastAPI background tasks once minimum engagement depth and intelligence thresholds are satisfied (@main.py#203-324).

## API Specification
- **Endpoint:** `POST /honeypot`
- **Headers:**
  - `Content-Type: application/json`
  - `x-api-key: <your-secret>`
- **Request body:**

```json
{
  "sessionId": "abc123",
  "message": {
    "sender": "scammer",
    "text": "Your bank account will be blocked today. Verify immediately.",
    "timestamp": 1770005528731
  },
  "conversationHistory": [],
  "metadata": {
    "channel": "SMS",
    "language": "English",
    "locale": "IN"
  }
}
```

- **Success response:**

```json
{
  "status": "success",
  "reply": "Why is my account being blocked?"
}
```

Errors return standard FastAPI JSON (e.g., 400 for validation issues, 401 for invalid API key).

## Final Result Callback
Once a session meets the following criteria, the service posts to GUVI’s endpoint:
- Scam intent detected in any turn
- At least `MIN_MESSAGES_FOR_CALLBACK` messages (default: 4)
- Extracted intelligence includes actionable data (accounts, UPI, links, phones, or ≥2 suspicious keywords)

Payload example (@main.py#226-233):

```json
{
  "sessionId": "abc123-session-id",
  "scamDetected": true,
  "totalMessagesExchanged": 6,
  "extractedIntelligence": {
    "bankAccounts": ["6666666666"],
    "upiIds": ["scammer@upi"],
    "phishingLinks": ["http://fake-link.example"],
    "phoneNumbers": ["+919999999999"],
    "suspiciousKeywords": ["account blocked", "verify immediately"]
  },
  "agentNotes": "Keywords: account blocked, verify immediately | Requested UPI details"
}
```

## Local Setup
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
export HONEYPOT_API_KEY="your-secret"
uvicorn main:app --host 0.0.0.0 --port 10000
```

## Quick Functional Tests
Single-turn request:

```bash
curl -X POST http://localhost:10000/honeypot \
  -H "Content-Type: application/json" \
  -H "x-api-key: $HONEYPOT_API_KEY" \
  -d '{
    "sessionId": "demo-1",
    "message": {
      "sender": "scammer",
      "text": "Your bank account will be blocked today. Verify immediately.",
      "timestamp": 1770005528731
    },
    "conversationHistory": [],
    "metadata": {
      "channel": "SMS",
      "language": "English",
      "locale": "IN"
    }
  }'
```

Multi-turn request with intelligence:

```bash
curl -X POST http://localhost:10000/honeypot \
  -H "Content-Type: application/json" \
  -H "x-api-key: $HONEYPOT_API_KEY" \
  -d '{
    "sessionId": "demo-1",
    "message": {
      "sender": "scammer",
      "text": "Send payment to scammer@upi or click http://fake-link.in",
      "timestamp": 1770005528740
    },
    "conversationHistory": [
      {
        "sender": "scammer",
        "text": "Your bank account will be blocked today.",
        "timestamp": 1770005528731
      },
      {
        "sender": "user",
        "text": "Why will it be blocked?",
        "timestamp": 1770005528735
      }
    ],
    "metadata": {
      "channel": "SMS",
      "language": "English",
      "locale": "IN"
    }
  }'
```

Check application logs to confirm callback success (`Final result callback successful for session ...`).

## Deployment Notes
1. Containerize or deploy via Render/Railway with the command:
   ```bash
   uvicorn main:app --host 0.0.0.0 --port 10000
   ```
2. Set environment variables in the platform dashboard:
   - `HONEYPOT_API_KEY`
3. Allow outbound HTTPS requests so callbacks reach GUVI.
4. Monitor logs for callback failures (warnings will log and retry logic can be added if necessary).

## Submission Checklist
- [x] API key auth enforced
- [x] Scam detection & agent response implemented
- [x] Intelligence extraction and callback integration (memory: Hackathon honeypot requires callback)
- [x] Local functional verification via curl
- [x] README updated with setup, testing, deployment, and callback details
- [ ] Deploy service and validate with official hackathon tester (pending)