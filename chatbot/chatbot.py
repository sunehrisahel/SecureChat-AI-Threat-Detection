"""Terminal chatbot with prompt injection protection."""

from __future__ import annotations

from config import BLOCKED_VERDICTS, MAX_HISTORY, SYSTEM_PROMPT
from detector_client import check_detector_health, check_message
from llm_client import get_response


def _build_initial_history() -> list[dict[str, str]]:
    return [{"role": "system", "content": SYSTEM_PROMPT}]


def _trim_history(history: list[dict[str, str]]) -> list[dict[str, str]]:
    """Keep the system message and at most MAX_HISTORY subsequent messages."""
    if len(history) <= MAX_HISTORY + 1:
        return history
    return [history[0]] + history[-(MAX_HISTORY):]


def _print_banner(detector_online: bool) -> None:
    print("=== AI Chatbot with Injection Protection ===")
    status = "ONLINE" if detector_online else "OFFLINE"
    print(f"Injection detector: {status}")
    print("Type 'exit' to quit, 'clear' to reset, 'history' to see recent messages.")
    print()


def _print_history(history: list[dict[str, str]]) -> None:
    recent = [msg for msg in history if msg["role"] != "system"][-5:]
    if not recent:
        print("No messages in history yet.")
        return
    print("--- Recent messages ---")
    for msg in recent:
        role = msg["role"].capitalize()
        print(f"{role}: {msg['content']}")
    print("-----------------------")


def _handle_blocked(verdict: str, risk_score: int, matched_patterns: list[str]) -> None:
    print(f"⚠️  Message blocked (verdict={verdict}, score={risk_score})")
    if matched_patterns:
        print(f"Matched patterns: {', '.join(matched_patterns)}")
    else:
        print("Matched patterns: none")
    print("Your message was not sent to the AI.")


def main() -> None:
    detector_online = check_detector_health()
    _print_banner(detector_online)

    history = _build_initial_history()

    while True:
        try:
            user_input = input("You: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nGoodbye!")
            break

        if not user_input:
            continue

        lowered = user_input.lower()
        if lowered in {"exit", "quit"}:
            print("Goodbye!")
            break

        if lowered == "history":
            _print_history(history)
            continue

        if lowered == "clear":
            history = _build_initial_history()
            print("Conversation history cleared.")
            continue

        result = check_message(user_input)
        verdict = result.get("verdict", "safe")
        risk_score = result.get("risk_score", 0)
        print(f"[Detector] verdict={verdict} score={risk_score}")

        if verdict in BLOCKED_VERDICTS:
            matched_patterns = result.get("matched_patterns") or []
            _handle_blocked(verdict, risk_score, matched_patterns)
            continue

        history.append({"role": "user", "content": user_input})
        reply = get_response(history)
        print(f"Assistant: {reply}")
        history.append({"role": "assistant", "content": reply})
        history = _trim_history(history)


if __name__ == "__main__":
    main()
