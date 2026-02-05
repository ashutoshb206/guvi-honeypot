import logging
import os
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

import httpx
from fastapi import (
    BackgroundTasks,
    Depends,
    FastAPI,
    Header,
    HTTPException,
    Request,
    status,
)
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

API_KEY = os.getenv("HONEYPOT_API_KEY", "replace-with-secure-key")
CALLBACK_URL = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"
MIN_MESSAGES_FOR_CALLBACK = 4

logger = logging.getLogger("honeypot")
if not logger.handlers:
    logging.basicConfig(level=logging.INFO)

app = FastAPI(
    title="Agentic Honeypot API",
    version="1.0.0",
    description=(
        "Hackathon-ready FastAPI service that detects potential scams and "
        "responds with a believable confused-victim persona."
    ),
)


class ConversationTurn(BaseModel):
    sender: str = Field(..., min_length=1)
    text: str = Field(..., min_length=1)
    timestamp: Optional[int] = None


class Metadata(BaseModel):
    channel: str = Field(..., min_length=1)
    language: str = Field(..., min_length=1)
    locale: str = Field(..., min_length=1)


class Message(BaseModel):
    sender: str = Field(..., min_length=1)
    text: str = Field(..., min_length=1)
    timestamp: int


class HoneypotEvent(BaseModel):
    sessionId: str = Field(..., min_length=1)
    message: Message
    conversationHistory: List[ConversationTurn] = Field(default_factory=list)
    metadata: Metadata


class HoneypotResponse(BaseModel):
    status: str
    reply: str


SCAM_KEYWORDS = {
    "account blocked",
    "verify immediately",
    "urgent action",
    "upi",
    "bank",
    "suspend",
    "freeze",
    "otp",
}

SUSPICIOUS_PAIRINGS = [
    ("verify", "account"),
    ("urgent", "verify"),
    ("immediately", "account"),
    ("share", "otp"),
    ("pay", "fee"),
]


@dataclass
class IntelligenceStore:
    bank_accounts: Set[str] = field(default_factory=set)
    upi_ids: Set[str] = field(default_factory=set)
    phishing_links: Set[str] = field(default_factory=set)
    phone_numbers: Set[str] = field(default_factory=set)
    suspicious_keywords: Set[str] = field(default_factory=set)

    def merge(self, other: "IntelligenceStore") -> None:
        self.bank_accounts.update(other.bank_accounts)
        self.upi_ids.update(other.upi_ids)
        self.phishing_links.update(other.phishing_links)
        self.phone_numbers.update(other.phone_numbers)
        self.suspicious_keywords.update(other.suspicious_keywords)

    def to_payload(self) -> Dict[str, List[str]]:
        return {
            "bankAccounts": sorted(self.bank_accounts),
            "upiIds": sorted(self.upi_ids),
            "phishingLinks": sorted(self.phishing_links),
            "phoneNumbers": sorted(self.phone_numbers),
            "suspiciousKeywords": sorted(self.suspicious_keywords),
        }

    def has_actionable_data(self) -> bool:
        return bool(
            self.bank_accounts
            or self.upi_ids
            or self.phishing_links
            or self.phone_numbers
            or len(self.suspicious_keywords) >= 2
        )


@dataclass
class SessionState:
    total_messages: int = 0
    scam_detected: bool = False
    intelligence: IntelligenceStore = field(default_factory=IntelligenceStore)
    callback_sent: bool = False
    callback_in_progress: bool = False

    def agent_notes(self) -> str:
        notes: List[str] = []
        if self.intelligence.suspicious_keywords:
            notes.append(
                "Keywords: " + ", ".join(sorted(self.intelligence.suspicious_keywords))
            )
        if self.intelligence.phishing_links:
            notes.append("Shared phishing links")
        if self.intelligence.upi_ids:
            notes.append("Requested UPI details")
        if self.intelligence.bank_accounts:
            notes.append("Requested bank account information")
        if self.intelligence.phone_numbers:
            notes.append("Requested phone contact")
        return " | ".join(notes) or "No significant intelligence gathered yet."


SESSIONS: Dict[str, SessionState] = {}


BANK_ACCOUNT_PATTERN = re.compile(r"\b\d{9,18}\b")
UPI_PATTERN = re.compile(r"\b[\w.\-]{2,}@[\w]{2,}\b")
LINK_PATTERN = re.compile(r"https?://\S+")
PHONE_PATTERN = re.compile(r"\b\+?\d{10,13}\b")


def authorize_request(x_api_key: str = Header(..., alias="x-api-key")) -> str:
    if x_api_key != API_KEY:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized",
        )
    return x_api_key


def detect_scam_intent(message_text: str, history: List[ConversationTurn]) -> bool:
    corpus_parts: List[str] = [message_text]
    corpus_parts.extend(
        turn.text for turn in history if turn.sender.lower() == "scammer"
    )
    normalized = " ".join(corpus_parts).lower()

    if any(keyword in normalized for keyword in SCAM_KEYWORDS):
        return True

    tokens = set(normalized.split())
    score = 0
    for first, second in SUSPICIOUS_PAIRINGS:
        if first in tokens and second in tokens:
            score += 1
    if "urgent" in tokens or "immediately" in tokens:
        score += 1
    if "verify" in tokens and ("now" in tokens or "today" in tokens):
        score += 1

    return score >= 2


def extract_intelligence(text_blocks: List[str]) -> IntelligenceStore:
    store = IntelligenceStore()
    for block in text_blocks:
        lower_block = block.lower()
        store.bank_accounts.update(BANK_ACCOUNT_PATTERN.findall(block))
        store.upi_ids.update(match.lower() for match in UPI_PATTERN.findall(block))
        store.phishing_links.update(
            link.rstrip(".,") for link in LINK_PATTERN.findall(block)
        )
        store.phone_numbers.update(PHONE_PATTERN.findall(block))
        for keyword in SCAM_KEYWORDS:
            if keyword in lower_block:
                store.suspicious_keywords.add(keyword)
    return store


def should_trigger_callback(state: SessionState) -> bool:
    if state.callback_sent or state.callback_in_progress:
        return False
    return (
        state.scam_detected
        and state.total_messages >= MIN_MESSAGES_FOR_CALLBACK
        and state.intelligence.has_actionable_data()
    )


def schedule_callback(
    background_tasks: BackgroundTasks, session_id: str, state: SessionState
) -> None:
    state.callback_in_progress = True
    background_tasks.add_task(send_final_result_callback, session_id)


def send_final_result_callback(session_id: str) -> None:
    state = SESSIONS.get(session_id)
    if not state:
        logger.warning("Session %s not found when attempting callback", session_id)
        return

    payload = {
        "sessionId": session_id,
        "scamDetected": state.scam_detected,
        "totalMessagesExchanged": state.total_messages,
        "extractedIntelligence": state.intelligence.to_payload(),
        "agentNotes": state.agent_notes(),
    }

    try:
        response = httpx.post(CALLBACK_URL, json=payload, timeout=5)
        response.raise_for_status()
        state.callback_sent = True
        logger.info("Final result callback successful for session %s", session_id)
    except Exception as exc:  # pragma: no cover - logging path
        state.callback_in_progress = False
        logger.warning(
            "Callback failed for session %s: %s", session_id, exc
        )


def build_confused_reply(event: HoneypotEvent, scam_detected: bool) -> str:
    current_text = event.message.text.strip()
    lower_text = current_text.lower()

    def _add_prompt(prompts: List[str], prompt: str) -> None:
        if prompt:
            prompts.append(prompt)

    prompts: List[str] = []
    if "bank" in lower_text:
        _add_prompt(prompts, "Which bank is this from?")
    if any(term in lower_text for term in ("block", "blocked", "suspend", "freeze")):
        _add_prompt(prompts, "Why would my account be blocked?")
    if "verify" in lower_text or "otp" in lower_text:
        _add_prompt(prompts, "What exactly do you need me to verify?")
    if "upi" in lower_text or "transfer" in lower_text:
        _add_prompt(prompts, "Is this about my UPI or some money transfer?")
    if "link" in lower_text or "click" in lower_text:
        _add_prompt(prompts, "Do I need to click something? I'm not very good with links.")

    if not prompts:
        if scam_detected:
            _add_prompt(prompts, "I'm confused about what you're asking me to do.")
        else:
            _add_prompt(prompts, "Can you explain what this is about?")

    previous_victim_lines = {
        turn.text.strip().lower()
        for turn in event.conversationHistory
        if turn.sender.lower() != "scammer" and turn.text
    }
    filtered_prompts = [
        prompt for prompt in prompts if prompt.lower() not in previous_victim_lines
    ]
    if not filtered_prompts:
        filtered_prompts = [prompts[0]]

    lead_in = "I'm feeling a bit lost here."
    if not scam_detected:
        lead_in = "I'm trying to understand this."

    follow_ups = filtered_prompts[:2]
    return " ".join([lead_in] + follow_ups)


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(
    request: Request, exc: RequestValidationError
) -> JSONResponse:
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={"detail": "Invalid request payload"},
    )


@app.post(
    "/honeypot",
    response_model=HoneypotResponse,
    status_code=status.HTTP_200_OK,
    summary="Accept scam message events and respond as a believable victim.",
)
async def honeypot_endpoint(
    event: HoneypotEvent,
    background_tasks: BackgroundTasks,
    _: str = Depends(authorize_request),
) -> HoneypotResponse:
    scam_detected = detect_scam_intent(event.message.text, event.conversationHistory)

    messages_for_intel = [turn.text for turn in event.conversationHistory]
    messages_for_intel.append(event.message.text)
    intelligence_snapshot = extract_intelligence(messages_for_intel)

    state = SESSIONS.setdefault(event.sessionId, SessionState())
    state.total_messages = len(event.conversationHistory) + 1
    state.scam_detected = state.scam_detected or scam_detected
    state.intelligence.merge(intelligence_snapshot)

    if should_trigger_callback(state):
        schedule_callback(background_tasks, event.sessionId, state)

    reply = build_confused_reply(event, scam_detected)
    return HoneypotResponse(status="success", reply=reply)
