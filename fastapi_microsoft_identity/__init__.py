"""fastapi_microsoft_identity - Azure AD authentication for Fast API"""

__version__ = "0.1.5"
__author__ = "Christos Matskas <christos.matskas@microsoft.com>"
__all__ = []
from .auth_service import (
    initialize,
    validate_scope,
    requires_auth,
    requires_b2c_auth,
    get_token_claims,
)
from .model import AuthError
