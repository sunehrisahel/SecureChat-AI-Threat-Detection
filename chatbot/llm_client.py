"""Client for the Anthropic Claude API."""

from __future__ import annotations

from anthropic import (
    APIConnectionError,
    APIError,
    APITimeoutError,
    Anthropic,
    RateLimitError,
)

from config import ANTHROPIC_API_KEY, ANTHROPIC_MODEL, MAX_TOKENS


def _split_history(conversation_history: list) -> tuple[str, list[dict[str, str]]]:
    """Separate the system prompt from user/assistant messages for Claude."""
    system = ""
    messages = []
    for msg in conversation_history:
        if msg["role"] == "system":
            system = msg["content"]
        else:
            messages.append({"role": msg["role"], "content": msg["content"]})
    return system, messages


def get_response(conversation_history: list) -> str:
    """
    Send the conversation history to Claude and return the assistant reply.

    conversation_history is a list of {"role": ..., "content": ...} dicts.
    """
    if not ANTHROPIC_API_KEY:
        return "Error: Anthropic API key is not set. Set the ANTHROPIC_API_KEY environment variable."

    system, messages = _split_history(conversation_history)

    try:
        client = Anthropic(api_key=ANTHROPIC_API_KEY)
        response = client.messages.create(
            model=ANTHROPIC_MODEL,
            max_tokens=MAX_TOKENS,
            system=system,
            messages=messages,
        )
        return response.content[0].text
    except RateLimitError:
        return "Error: Claude rate limit exceeded. Please try again in a moment."
    except APIConnectionError:
        return "Error: Could not connect to Anthropic. Check your internet connection."
    except APITimeoutError:
        return "Error: Claude request timed out. Please try again."
    except APIError as exc:
        return f"Error: Anthropic API error — {exc}"
    except Exception as exc:
        return f"Error: Unexpected failure while calling Claude — {exc}"
