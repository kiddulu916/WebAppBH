import uuid
from datetime import datetime, timezone
from typing import Optional


class CallbackStore:
    """In-memory storage for registered callbacks and their interactions."""

    def __init__(self):
        self._callbacks: dict[str, dict] = {}

    def register(self, protocols: list[str] | None = None) -> str:
        cb_id = str(uuid.uuid4())[:12]
        self._callbacks[cb_id] = {
            "id": cb_id,
            "protocols": protocols or ["http"],
            "interactions": [],
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        return cb_id

    def get(self, cb_id: str) -> Optional[dict]:
        return self._callbacks.get(cb_id)

    def record_interaction(self, cb_id: str, interaction: dict) -> bool:
        cb = self._callbacks.get(cb_id)
        if cb is None:
            return False
        interaction["timestamp"] = datetime.now(timezone.utc).isoformat()
        cb["interactions"].append(interaction)
        return True

    def cleanup(self, cb_id: str) -> bool:
        return self._callbacks.pop(cb_id, None) is not None
