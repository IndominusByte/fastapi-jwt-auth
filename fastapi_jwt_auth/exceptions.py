class AuthJWTException(Exception):
    """
    Base except which all fastapi_jwt_auth errors extend
    """
    pass

class InvalidHeaderError(AuthJWTException):
    """
    An error getting jwt in header or jwt header information from a request
    """
    def __init__(self,status_code: int, message: str):
        self.status_code = status_code
        self.message = message

class JWTDecodeError(AuthJWTException):
    """
    An error decoding a JWT
    """
    def __init__(self,status_code: int, message: str):
        self.status_code = status_code
        self.message = message

class CSRFError(AuthJWTException):
    """
    An error with CSRF protection
    """
    def __init__(self,status_code: int, message: str):
        self.status_code = status_code
        self.message = message

class MissingTokenRequired(AuthJWTException):
    """
    Error raised when token not found or invalid type
    """
    def __init__(self,status_code: int, message: str):
        self.status_code = status_code
        self.message = message

class RevokedTokenError(AuthJWTException):
    """
    Error raised when a revoked token attempt to access a protected endpoint
    """
    def __init__(self,status_code: int, message: str):
        self.status_code = status_code
        self.message = message
