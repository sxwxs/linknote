"""
Email magic-link authentication for LinkNote (Flask).

This package is intentionally usable independently from `linknote` by registering
its blueprint into any Flask app that uses sessions.
"""

from .flask_blueprint import create_email_auth_blueprint

__all__ = ["create_email_auth_blueprint"]

