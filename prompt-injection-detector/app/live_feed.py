"""Live attack feed helpers: prediction wrapper and SSE broadcast."""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from typing import Any

from fastapi.responses import StreamingResponse

from app.pipeline import analyze_text

# Connected SSE clients waiting for live attack events.
sse_clients: list[asyncio.Queue] = []


def predict_text(text: str) -> dict[str, Any]:
    """Run the existing analyzer pipeline and map to live-feed fields."""
    result = analyze_text(text, source="fire-attack")
    categories = result.get("threat_categories") or result.get("matched_categories") or []
    verdict = result.get("verdict", "safe")

    if categories:
        predicted_label = str(categories[0])
    elif verdict == "suspicious":
        predicted_label = "suspicious"
    elif verdict == "safe":
        predicted_label = "safe"
    else:
        predicted_label = "prompt_injection"

    confidence = float(
        result.get("threat_confidence")
        or result.get("intent_confidence")
        or 0.0
    )

    return {
        "predicted_label": predicted_label,
        "confidence": confidence,
        "risk_score": int(result.get("risk_score", 0)),
    }


def normalize_inject_verdict(predicted_label: str) -> str:
    """Map detector labels to SecureChat badge verdicts."""
    if predicted_label == "safe":
        return "safe"
    if predicted_label == "suspicious":
        return "suspicious"
    return "prompt_injection"


async def broadcast_event(data: dict[str, Any]) -> None:
    """Push a live-feed event to every connected SSE client."""
    for queue in list(sse_clients):
        await queue.put(data)


async def live_feed_stream() -> StreamingResponse:
    """Stream Server-Sent Events for live attack results."""

    async def event_generator():
        queue: asyncio.Queue = asyncio.Queue()
        sse_clients.append(queue)
        try:
            while True:
                data = await queue.get()
                yield f"data: {json.dumps(data)}\n\n"
        except asyncio.CancelledError:
            if queue in sse_clients:
                sse_clients.remove(queue)
            raise

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


def utc_timestamp() -> str:
    """Return an ISO timestamp for live-feed payloads."""
    return datetime.now(timezone.utc).isoformat()
