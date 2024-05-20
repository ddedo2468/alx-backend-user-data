#!/usr/bin/env python3
"""auth module for the api app"""

from flask import request
from typing import List, TypeVar


class Auth:
    """Auth Class"""

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """cheking if the path req an authintaction"""
        return False

    def authorization_header(self, request=None) -> str:
        """get the auth field from the header request"""
        return None

    def current_user(self, request=None) -> TypeVar("User"):
        """getting current user from the request"""
        return None