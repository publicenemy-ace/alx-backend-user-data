#!/usr/bin/env python3
"""Sessikon Authentication"""

from typing import TypeVar
import uuid
from api.v1.auth.auth import Auth
from models.user import User


class SessionAuth(Auth):
    """Base class for configuring session authentication"""
    user_id_by_session_id = {}

    def create_session(self, user_id: str = None) -> str:
        """creates a session id for a user_id

        Args:
            user_id (str, optional): The user ID to create session for.
            Defaults to None.

        Returns:
            str: returns the session ID as a string
        """
        if not user_id or not isinstance(user_id, str):
            return None
        sessionId = str(uuid.uuid4())
        self.user_id_by_session_id[sessionId] = user_id
        return sessionId

    def user_id_for_session_id(self, session_id: str = None) -> str:
        """returns a user_ID based on given session ID

        Args:
            session_id (str, optional): The user session ID.
            Defaults to None.

        Returns:
            str: the user ID
        """
        if not session_id or not isinstance(session_id, str):
            return None
        user_id = self.user_id_by_session_id.get(session_id)
        return user_id

    def current_user(self, request=None) -> TypeVar('User'):
        """returns a User instance based on a cookie value

        Args:
            request (flask http request, optional):
            flask http request. Defaults to None.

        Return:
            returns User instance
        """
        cookie_value = self.session_cookie(request)
        user_id = self.user_id_by_session_id.get(cookie_value)
        # Handle case where user_id is a dictionary
        if isinstance(user_id, dict):
            user_id = user_id.get('user_id')
            if not isinstance(user_id, str):
                print(f"Error: Expected user_id to be a string, but got: {user_id}")
                return None
        
        # Ensure user_id is a string
        if not isinstance(user_id, str):
            print(f"Error: Expected user_id to be a string, but got: {user_id}")
            return None

        user = User.get(user_id)
        return user

    def destroy_session(self, request=None):
        """Deletes a user session or /logout"""
        # If request is None, return False
        if request is None:
            return False

        # Retrieve the session ID from the request's cookie
        session_id = self.session_cookie(request)
        if not session_id:
            return False

        # Get the user ID linked to the session ID
        user_id = self.user_id_for_session_id(session_id)
        if not user_id:
            return False

        # Delete the session ID from the dictionary self.user_id_by_session_id
        del self.user_id_by_session_id[session_id]

        # Return True to indicate the session was successfully destroyed
        return True
