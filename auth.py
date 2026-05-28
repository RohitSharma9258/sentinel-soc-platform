import os
import secrets
import logging
from functools import wraps
from flask import request, jsonify
from database import db

# Setup logger for auth
logger = logging.getLogger("auth")

def require_api_key(f):
    """
    Decorator to require API key authentication if IDS_API_KEY is configured.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        api_key = os.environ.get("IDS_API_KEY")
        if not api_key:
            return f(*args, **kwargs)

        # Retrieve provided key from Authorization or X-API-Key headers
        auth_header = request.headers.get("Authorization")
        provided_key = None

        if auth_header:
            if auth_header.lower().startswith("bearer "):
                provided_key = auth_header[7:].strip()
            else:
                provided_key = auth_header.strip()
        else:
            provided_key = request.headers.get("X-API-Key")

        # Compare keys in a timing-safe manner
        if not provided_key or not secrets.compare_digest(provided_key, api_key):
            ip_addr = request.remote_addr or "Unknown"
            path = request.path
            msg = f"Unauthorized access attempt from IP: {ip_addr} on path: {path}"
            
            # Log to system logger and database audit log
            logger.warning(msg)
            db.add_log("WARNING", "auth", f"AUDIT: {msg}", is_audit=1)
            
            return jsonify({
                "success": False,
                "error": "Unauthorized: Invalid or missing API Key"
            }), 401

        return f(*args, **kwargs)

    return decorated


def require_local_or_api_key(f):
    """
    Decorator that allows access if request is from localhost (127.0.0.1 or ::1)
    without any key, but requires API key authentication from all other IPs.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        ip_addr = request.remote_addr or "Unknown"
        
        # Check if local request
        if ip_addr in ("127.0.0.1", "::1", "localhost"):
            return f(*args, **kwargs)

        # Non-local, check if API key is set
        api_key = os.environ.get("IDS_API_KEY")
        if not api_key:
            # Safe fallback: if API key is not configured, we allow it (no-op)
            return f(*args, **kwargs)

        # Retrieve provided key from Authorization or X-API-Key headers
        auth_header = request.headers.get("Authorization")
        provided_key = None

        if auth_header:
            if auth_header.lower().startswith("bearer "):
                provided_key = auth_header[7:].strip()
            else:
                provided_key = auth_header.strip()
        else:
            provided_key = request.headers.get("X-API-Key")

        # Compare keys in a timing-safe manner
        if not provided_key or not secrets.compare_digest(provided_key, api_key):
            path = request.path
            msg = f"Unauthorized non-local access attempt from IP: {ip_addr} on path: {path}"
            
            # Log to system logger and database audit log
            logger.warning(msg)
            db.add_log("WARNING", "auth", f"AUDIT: {msg}", is_audit=1)
            
            return jsonify({
                "success": False,
                "error": "Unauthorized: Local request or valid API Key required"
            }), 401

        return f(*args, **kwargs)

    return decorated
