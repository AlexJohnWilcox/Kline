import structlog

from siem.ai.client import OllamaError, get_ollama_client
from siem.models.suppression import Suppression

logger = structlog.get_logger()

SYSTEM_PROMPT = (
    "You are a security analyst deciding if a new SIEM alert matches a known exception. "
    "Answer YES or NO followed by a brief explanation. "
    "Be conservative: if unsure, answer NO."
)


def parse_ai_match_response(response: str) -> bool:
    """Parse an AI response to determine if it's a YES match."""
    first_word = response.strip().split()[0].upper().rstrip(".,!-:") if response.strip() else ""
    return first_word == "YES"


async def ai_match_suppression(
    suppression: Suppression,
    alert_context: dict,
    alert_rule_name: str,
    alert_description: str,
) -> bool:
    """Ask the AI if a new alert matches an existing suppression.

    Returns True if the AI thinks it's the same kind of expected activity.
    Returns False on any error or ambiguity (fail-open: create the alert).
    """
    prompt = (
        f"Known exception (suppression rule):\n"
        f"  Rule: {suppression.rule_id}\n"
        f"  Reason: {suppression.reason}\n"
        f"  Match fields: {suppression.match_fields}\n\n"
        f"New alert:\n"
        f"  Rule: {alert_rule_name}\n"
        f"  Description: {alert_description}\n"
        f"  Context: {alert_context}\n\n"
        f"Is this new alert the same kind of expected activity described "
        f"in the suppression reason? Answer YES or NO with a brief explanation."
    )

    try:
        client = get_ollama_client()
        response = await client.generate(prompt, system=SYSTEM_PROMPT, temperature=0.1)
        result = parse_ai_match_response(response)
        logger.info(
            "ai_suppression_match",
            suppression_id=suppression.id,
            result=result,
            response=response[:100],
        )
        return result
    except OllamaError:
        logger.debug("ai_suppression_match_unavailable", suppression_id=suppression.id)
        return False
    except Exception:
        logger.exception("ai_suppression_match_error", suppression_id=suppression.id)
        return False
