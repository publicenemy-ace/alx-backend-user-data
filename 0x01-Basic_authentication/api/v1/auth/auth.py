#!/usr/bin/env python3
"""Auth Class to Manage Basic Authentication"""

import fnmatch
from flask import request
from typing import List, TypeVar


class Auth:
    """Auth Class for basic authentication
    """
    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """Method that defines path tha requires authentication

        Args:
            path (str): path that require authentication
            excluded_paths (List[str]): Paths that are excluded

        Returns:
            bool: Returns a boolean
        """
        if not path:
            return True
        if not excluded_paths:
            return True

        # Normalize the path
        normalized_path = path.rstrip('/')

        for excluded_path in excluded_paths:
            # Normalize the excluded path
            normalized_excluded_path = excluded_path.rstrip('/')

            # Check if the path matches the excluded path pattern
            if fnmatch.fnmatch(normalized_path, normalized_excluded_path):
                return False

        return True

    def authorization_header(self, request=None) -> str:
        """Manages authrization header

        Args:
            request (object, optional): http request object. Defaults to None.

        Returns:
            str: returns the authorization header as string
        """
        if request is None:
            return None

        # Check if 'Authorization' header exists in the request headers
        return request.headers.get('Authorization', None)

    def current_user(self, request=None) -> TypeVar('User'):
        """returns the current user session

        Args:
            request (object, optional): http request objet. Defaults to None.

        Returns:
            User: returns the user object
        """
        return None
