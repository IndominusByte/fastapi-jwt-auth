class AuthJWTException(Exception):
    """
    Base except which all fastapi_jwt_auth errors extend
    """
    
    def __init__(self, status_code: int, message: str):
        self.status_code = status_code
        self.message = message


class InvalidHeaderError(AuthJWTException):
    """
    An error getting jwt in header or jwt header information from a request
    """

    pass


class JWTDecodeError(AuthJWTException):
    """
    An error decoding a JWT
    """

    pass


class CSRFError(AuthJWTException):
    """
    An error with CSRF protection
    """

    pass


class MissingTokenError(AuthJWTException):
    """
    Error raised when token not found
    """

    pass


class RevokedTokenError(AuthJWTException):
    """
    Error raised when a revoked token attempt to access a protected endpoint
    """

    pass


class AccessTokenRequired(AuthJWTException):
    """
    Error raised when a valid, non-access JWT attempt to access an endpoint
    protected by jwt_required, jwt_optional, fresh_jwt_required
    """

    pass


class RefreshTokenRequired(AuthJWTException):
    """
    Error raised when a valid, non-refresh JWT attempt to access an endpoint
    protected by jwt_refresh_token_required
    """

    pass


class FreshTokenRequired(AuthJWTException):
    """
    Error raised when a valid, non-fresh JWT attempt to access an endpoint
    protected by fresh_jwt_required
    """

    pass
