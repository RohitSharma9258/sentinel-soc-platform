"""
Smart WiFi Intruder Detection System - Event Bus
Central event distribution system for decoupled module communication.
"""

import logging
import threading
from collections import defaultdict

logger = logging.getLogger("event_bus")

class EventBus:
    """Thread-safe internal event bus for pub/sub communication."""
    
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(EventBus, cls).__new__(cls)
                cls._instance._subscribers = defaultdict(list)
                cls._instance._event_lock = threading.Lock()
        return cls._instance

    def subscribe(self, event_type, callback):
        """Subscribe a callback function to an event type."""
        with self._event_lock:
            self._subscribers[event_type].append(callback)
            logger.debug(f"Subscribed {callback.__name__} to {event_type}")

    def emit(self, event_type, data=None):
        """Emit an event to all subscribers."""
        with self._event_lock:
            subscribers = list(self._subscribers[event_type])
            # Also notify wildcards
            subscribers.extend(self._subscribers["*"])
        
        for callback in subscribers:
            try:
                # Run callbacks in separate threads to avoid blocking the emitter
                threading.Thread(
                    target=self._run_callback, 
                    args=(callback, event_type, data),
                    daemon=True
                ).start()
            except Exception as e:
                logger.error(f"Error emitting {event_type} to {callback.__name__}: {e}")

    def _run_callback(self, callback, event_type, data):
        try:
            callback(event_type, data)
        except Exception as e:
            logger.error(f"Event handler error ({event_type}): {e}")

# Global singleton
bus = EventBus()
