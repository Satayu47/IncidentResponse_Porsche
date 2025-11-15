# src/dialogue_state.py

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import List, Optional, Dict


class DialogueState(Enum):
    """High-level conversation state for the incident."""
    GATHERING_INFO = auto()       # user just started, vague input
    CLARIFYING = auto()           # we asked for more info
    INCIDENT_SUSPECTED = auto()   # some confidence, but not firm
    INCIDENT_CONFIRMED = auto()   # high confidence + clear type
    READY_FOR_PHASE2 = auto()     # safe to trigger playbook
    GENERAL_QUESTION = auto()     # "how to prevent X", "what is Y"
    USER_CONFUSED = auto()        # user says "idk", "wtf", etc.
    IDLE = auto()                 # no active incident


@dataclass
class DialogueContext:
    """Tracks conversation context across turns."""
    turns: int = 0
    last_label: str = "other"
    last_confidence: float = 0.0
    last_user_text: str = ""
    user_level: str = "novice"  # novice / intermediate / expert
    state: DialogueState = DialogueState.IDLE
    clarification_needed: bool = False
    frustration_score: int = 0
    hypotheses: List[Dict] = field(default_factory=list)

    def is_ready_for_phase2(self, thresh: float = 0.7) -> bool:
        return self.last_confidence >= thresh and self.state in {
            DialogueState.INCIDENT_CONFIRMED,
            DialogueState.READY_FOR_PHASE2,
        }


FRUSTRATION_KEYWORDS = [
    "wtf", "fuck", "fuk", "shit", "stupid", "useless",
    "idk", "i don't know", "i dont know", "no idea"
]


def detect_frustration(text: str) -> int:
    t = text.lower()
    score = 0
    for w in FRUSTRATION_KEYWORDS:
        if w in t:
            score += 1
    return score


def infer_state(
    user_text: str,
    label: str,
    confidence: float,
    user_level: str,
    asked_followup: bool,
    is_general_question: bool,
    explicit_override: bool,
    prev_state: Optional[DialogueState] = None,
    current_turns: int = 0,
    thresh_low: float = 0.6,
    thresh_go: float = 0.7,
) -> DialogueState:
    """Decide the new dialogue state based on latest info."""

    if is_general_question:
        return DialogueState.GENERAL_QUESTION

    # User clearly knows the attack → treat as confirmed incident
    if explicit_override:
        if confidence >= thresh_go:
            return DialogueState.READY_FOR_PHASE2
        return DialogueState.INCIDENT_CONFIRMED

    # MINIMUM TURNS REQUIREMENT: Force at least 2 turns before confirming
    # This creates natural conversation flow even for clear cases
    if current_turns < 2:
        # First turn → always gather info
        if current_turns == 0:
            return DialogueState.GATHERING_INFO
        # Second turn → clarifying or suspected
        if confidence >= thresh_low:
            return DialogueState.INCIDENT_SUSPECTED
        return DialogueState.CLARIFYING

    # Extremely vague input
    text_lower = user_text.lower()
    if any(x in text_lower for x in ["help", "something broken", "it broke"]) and confidence < thresh_low:
        return DialogueState.GATHERING_INFO

    # If we just asked a follow-up, we are clarifying
    if asked_followup and confidence < thresh_go:
        return DialogueState.CLARIFYING

    # Confidence mapping (after minimum turns)
    if confidence >= thresh_go:
        # High confidence incident
        if prev_state in {DialogueState.INCIDENT_CONFIRMED, DialogueState.READY_FOR_PHASE2}:
            return prev_state
        return DialogueState.INCIDENT_CONFIRMED

    if confidence >= thresh_low:
        return DialogueState.INCIDENT_SUSPECTED

    # Very low confidence → still gathering info
    return DialogueState.GATHERING_INFO


def update_context(
    ctx: DialogueContext,
    user_text: str,
    label: str,
    confidence: float,
    user_level: str,
    candidates: List[Dict],
    asked_followup: bool,
    is_general_question: bool,
    explicit_override: bool,
    thresh_low: float = 0.6,
    thresh_go: float = 0.7,
) -> DialogueContext:
    """Update dialogue context after each user turn."""
    ctx.turns += 1
    ctx.last_label = label
    ctx.last_confidence = confidence
    ctx.last_user_text = user_text
    ctx.user_level = user_level
    ctx.hypotheses = candidates or []

    # Update frustration
    ctx.frustration_score += detect_frustration(user_text)

    # Compute new state
    ctx.state = infer_state(
        user_text=user_text,
        label=label,
        confidence=confidence,
        user_level=user_level,
        asked_followup=asked_followup,
        is_general_question=is_general_question,
        explicit_override=explicit_override,
        prev_state=ctx.state,
        current_turns=ctx.turns,
        thresh_low=thresh_low,
        thresh_go=thresh_go,
    )

    # Clarification needed?
    ctx.clarification_needed = (
        ctx.state in {DialogueState.GATHERING_INFO, DialogueState.CLARIFYING}
        and confidence < thresh_go
    )

    return ctx
