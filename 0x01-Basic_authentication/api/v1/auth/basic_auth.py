#!/usr/bin/env python3
"""basic auth class"""

from api.v1.auth.auth import Auth


class BasicAuth(Auth):
    """BasicAuth Class inherits from Auth"""
    def extract_base64_authorization_header(
            self, authorization_header: str) -> str:
        """ eturns the Base64 part of the Authorization
        header for a Basic Authentication
        """
        if authorization_header is None:
            return None
        if type(authorization_header) != str:
            return None
        if authorization_header.startswith('Basic '):
            return None
        return authorization_header[len('Basic '):]
