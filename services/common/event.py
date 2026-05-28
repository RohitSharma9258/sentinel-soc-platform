import json
import uuid
from jsonschema import validate, ValidationError

# Central event schema (simplified for Phase 1)
EVENT_SCHEMA = {
    "type": "object",
    "properties": {
        "event_id": {"type": "string", "format": "uuid"},
        "timestamp": {"type": "string", "format": "date-time"},
        "source_service": {"type": "string"},
        "event_type": {"type": "string", "enum": ["packet_event", "packet_batch_event", "flow_event", "device_event", "alert_event"]},
        "payload": {"type": "object"},
        "severity": {"type": "integer", "minimum": 0, "maximum": 100}
    },
    "required": ["event_id", "timestamp", "source_service", "event_type", "payload"]
}

def create_event(event_type: str, source_service: str, payload: dict, severity: int = None) -> dict:
    """Create a validated event dict.
    Args:
        event_type: one of the allowed event types.
        source_service: name of the producing service.
        payload: the actual data payload.
        severity: optional integer severity (0‑100).
    Returns:
        A dict ready to be serialized to JSON.
    Raises:
        ValidationError if the resulting event does not match the schema.
    """
    event = {
        "event_id": str(uuid.uuid4()),
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "source_service": source_service,
        "event_type": event_type,
        "payload": payload,
    }
    if severity is not None:
        event["severity"] = severity
    # Validate against schema – will raise if invalid
    validate(instance=event, schema=EVENT_SCHEMA)
    return event

# Helper for packet batch payload validation (schema defined later in processor)
