"""
CyberRemedy — Safe JSON utilities.
Converts bytes→hex, sets→lists so any event/alert dict can be passed to
json.dumps() or returned from a FastAPI endpoint without crashing.
"""
import json
from typing import Any


class SafeEncoder(json.JSONEncoder):
    def default(self, obj: Any) -> Any:
        if isinstance(obj, (bytes, bytearray, memoryview)):
            return bytes(obj).hex()
        if isinstance(obj, set):
            return sorted(obj)
        return super().default(obj)


def safe_dumps(obj: Any, **kwargs) -> str:
    return json.dumps(obj, cls=SafeEncoder, **kwargs)


def sanitize(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {k: sanitize(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [sanitize(v) for v in obj]
    if isinstance(obj, (bytes, bytearray, memoryview)):
        return bytes(obj).hex()
    if isinstance(obj, set):
        return sorted(sanitize(v) for v in obj)
    return obj
