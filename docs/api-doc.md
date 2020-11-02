In here you will find the API for everything exposed in this extension.

### Configuring FastAPI JWT Auth

**load_config**(callback)
:   *This decorator sets the callback function to overwrite state on AuthJWT class so
    when you initialize an instance in dependency injection default value will be overwritten.*

    **Hint**: *The callback must be a function that returns a list of tuple or pydantic object.*

**token_in_denylist_loader**(callback)
:   *This decorator sets the callback function that will be called when
    a protected endpoint is accessed and will check if the JWT has
    been revoked. By default, this callback is not used.*

    **Hint**: *The callback must be a function that takes `one` argument, which is the decoded JWT (python dictionary),
    and returns `True` if the token has been revoked, or `False` otherwise.*

### Protected Endpoint

**jwt_required**()
:   *If you call this function, it will ensure that the requester has a valid access token before
    executing the code below your router. This does not check the freshness of the access token.*

**jwt_optional**()
:   *If an access token present in the request, this will call the endpoint with `get_jwt_identity()`
    having the identity of the access token. If no access token is present in the request, this endpoint
    will still be called, but `get_jwt_identity()` will return None instead.*

    *If there is an invalid access token in the request (expired, tampered with, etc),
    this will still call the appropriate error handler.*

**jwt_refresh_token_required**()
:   *If you call this function, it will ensure that the requester has a valid refresh token before
    executing the code below your router.*

**fresh_jwt_required**()
:   *If you call this function, it will ensure that the requester has a valid and fresh access token before
    executing the code below your router.*

### Utilities

**create_access_token**(subject, fresh=False, algorithm=None, headers=None, expires_time=None, audience=None, user_claims={})
:   *Create a new access token.*

    * Parameters:
        * **subject**: Identifier for who this token is for example id or username from database
        * **fresh**: Identify token is fresh or non-fresh
        * **algorithm**: Algorithm allowed to encode the token
        * **headers**: Valid dict for specifying additional headers in JWT header section
        * **expires_time**: Set the duration of the JWT
        * **audience**: Expected audience in the JWT
        * **user_claims**: Custom claims to include in this token. This data must be dictionary
    * Returns: An encoded access token

**create_refresh_token**(subject, algorithm=None, headers=None, expires_time=None, audience=None, user_claims={})
:   *Creates a new refresh token.*

    * Parameters:
        * **subject**: Identifier for who this token is for example id or username from database
        * **algorithm**: Algorithm allowed to encode the token
        * **headers**: Valid dict for specifying additional headers in JWT header section
        * **expires_time**: Set the duration of the JWT
        * **audience**: Expected audience in the JWT
        * **user_claims**: Custom claims to include in this token. This data must be dictionary
    * Returns: An encoded refresh token

**set_access_cookies**(encoded_access_token, response=None, max_age=None)
:   *Configures the response to set access token in a cookie. This will also set the CSRF double submit values
    in a separate cookie.*

    * Parameters:
        * **encoded_access_token**: The encoded access token to set in the cookies
        * **response**: The FastAPI response object to set the access cookies in
        * **max_age**: The max age of the cookie value should be `integer` the number of seconds
    * Returns: None

**set_refresh_cookies**(encoded_refresh_token, response=None, max_age=None)
:   *Configures the response to set refresh token in a cookie. This will also set the CSRF double submit values
    in a separate cookie.*

    * Parameters:
        * **encoded_refresh_token**: The encoded refresh token to set in the cookies
        * **response**: The FastAPI response object to set the refresh cookies in
        * **max_age**: The max age of the cookie value should be `integer` the number of seconds
    * Returns: None

**unset_jwt_cookies**(response=None)
:   *Unset (delete) all jwt stored in a cookies.*

    * Parameters:
        * **response**: The FastAPI response object to delete the JWT cookies in
    * Returns: None

**unset_access_cookies**(response=None)
:   *Remove access token and access CSRF double submit from the response cookies.*

    * Parameters:
        * **response**: The FastAPI response object to delete the access cookies in
    * Returns: None

**unset_refresh_cookies**(response=None)
:   *Remove refresh token and refresh CSRF double submit from the response cookies.*

    * Parameters:
        * **response**: The FastAPI response object to delete the refresh cookies in
    * Returns: None

**get_raw_jwt**()
:   *This will return the python dictionary which has all of the claims of the JWT that is accessing the endpoint.
    If no JWT is currently present, return `None` instead.*

**get_jti**(encoded_token)
:   *Returns the JTI (unique identifier) of an encoded JWT*

    * Parameters:
        * **encoded_token**: The encoded JWT from parameter
    * Returns: String of JTI

**get_jwt_subject**()
:   *This will return the subject of the JWT that is accessing the endpoint.
    If no JWT is present, `None` is returned instead.*

**get_unverified_jwt_headers**(encoded_token=None)
:   *Returns the Headers of an encoded JWT without verifying the actual signature of JWT.*

    * Parameters:
        * **encoded_token**: The encoded JWT to get the Header from protected endpoint or from parameter
    * Returns: JWT header parameters as a dictionary
