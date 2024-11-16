#!/usr/bin/env python3
"""Manages session expiration"""

from api.v1.auth.session_auth import SessionAuth
import datetime
import os


class SessionExpAuth(SessionAuth):
    """Base class that manages session expiration
    """
    def __init__(self) -> None:
        """Initialize the session expiration with duration from env"""
        super().__init__()
        session_duration = os.getenv('SESSION_DURATION', '0')
        try:
            self.session_duration = int(session_duration)
        except (TypeError, ValueError):
            self.session_duration = 0  # default to 0 if not valid

    def create_session(self, user_id: str = None) -> str:
        """Create a session ID with expiration logic"""
        session_id = super().create_session(user_id)
        if not session_id:
            return None

        # Create a session dictionary and store it
        session_data = {
            "user_id": user_id,
            # store the current datetime
            "created_at": datetime.datetime.utcnow()
        }
        self.user_id_by_session_id[session_id] = session_data

        return session_id

    def user_id_for_session_id(self, session_id: str = None) -> str:
        """Retrieve user_id if session is valid and not expired"""
        if not session_id:
            return None

        # Check if session exists
        session_data = self.user_id_by_session_id.get(session_id)
        if not session_data:
            return None

        # If session_duration is 0 or less, return the user_id immediately
        if self.session_duration <= 0:
            return session_data.get("user_id")

        # Check if the session has expired
        created_at = session_data.get("created_at")
        if not created_at:
            return None

        # Calculate expiration time
        expiration_time = created_at + datetime.timedelta(
            seconds=self.session_duration)
        if datetime.datetime.now() > expiration_time:
            return None  # session has expired

        return session_data.get("user_id")
