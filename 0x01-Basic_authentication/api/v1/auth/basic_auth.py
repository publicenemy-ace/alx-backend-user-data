#!/usr/bin/env python3
"""Setup the basic authentication classs
inherits from Auth class
"""
from typing import TypeVar
import base64
from api.v1.auth.auth import Auth
from models.base import DATA
from models.user import User


class BasicAuth(Auth):
    """Class for implementing basic authentication"""
    def extract_base64_authorization_header(self,
                                            authorization_header: str) -> str:
        """Returns a base64 part of the Authorization header
        for Basic Authentication

        Args:
            authorization_header (str): The authorization header

        Returns:
            str: The authorization header string
        """
        if not authorization_header:
            return None
        if type(authorization_header) != str:
            return None
        if not authorization_header.startswith('Basic '):
            return None
        # Otherwise, return the value after Basic (after the space)
        return authorization_header.split('Basic ')[1]

    def decode_base64_authorization_header(self,
                                           base64_authorization_header:
                                           str) -> str:
        """Decodes a base64 authorization header string

        Args:
            base64_authorization_header (str): the authorization str
            from header

        Returns:
            str: the decoded string
        """
        if not base64_authorization_header:
            return None
        if type(base64_authorization_header) != str:
            return None
        try:
            decoded_bytes = base64.b64decode(base64_authorization_header,
                                             validate=True)
            return decoded_bytes.decode('utf-8')
        except Exception:
            return None

    def extract_user_credentials(self,
                                 decoded_base64_authorization_header:
                                 str) -> (str, str):
        """Extracts users credentials,
        email and password from base64 decoded value

        Args:
            decoded_base64_authorization_header(str):
            the decoded authorization header to extract credentials from

        Returns:
            A tuple of str, email and password
        """
        if not decoded_base64_authorization_header:
            return None, None
        if type(decoded_base64_authorization_header) != str:
            return None, None
        if ':' not in decoded_base64_authorization_header:
            return None, None
        email, password = decoded_base64_authorization_header.split(':', 1)
        return email, password

    def user_object_from_credentials(self, user_email: str,
                                     user_pwd:
                                     str) -> TypeVar('User'):
        """Returns the user instace based on his email and password

        Args:
            user_email (str): The user email address
            user_pwd (str): the user password

        Returns:
            User (class): The User Object
        """
        # Check for valid email and password
        if not isinstance(user_email, str) or not isinstance(user_pwd, str):
            return None

        # Check if DATA is properly initialized
        if DATA is None:
            return None

        try:
            # Search for users with the provided email
            user_list = User.search({"email": user_email})
            if user_list:
                # Assuming emails are unique, get the first match
                user = user_list[0]
                # Check if the password is correct
                if user.is_valid_password(user_pwd):
                    return user
        except Exception as e:
            return None

        return None

    def current_user(self, request=None) -> TypeVar('User'):
        """Overloads Auth and retrieves the User instace for a request
        Args:
            request (Flask request): flask http request

        Returns:
            The User object as a payload json object
        """
        if request is None:
            return None

        # Step 1: Get the authorization header
        auth_header = self.authorization_header(request)
        if not auth_header:
            return None

        # Step 2: Extract the base64 authorization header
        base64_auth_header = self.extract_base64_authorization_header(
            auth_header)
        if not base64_auth_header:
            return None

        # Step 3: Decode the base64 authorization header
        decoded_str = self.decode_base64_authorization_header(
            base64_auth_header)
        if not decoded_str:
            return None

        # Step 4: Extract user credentials
        user_email, user_pwd = self.extract_user_credentials(decoded_str)
        if not user_email or not user_pwd:
            return None

        # Step 5: Get the user object from credentials
        user = self.user_object_from_credentials(user_email, user_pwd)
        if user:
            return user

        return None
