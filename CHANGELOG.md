## 0.4.0
* Support set and unset cookies when returning a **Response** directly

## 0.3.0
* **(Deprecated)** environment variable support
* Change name function **load_end()** -> **load_config()**
* Change name function **get_jwt_identity()** -> **get_jwt_subject()**
* Change name identity claims to standard claims sub *(Thanks to @rassie for suggestion)*
* Additional headers in claims
* Get additional headers claims from request or parsing token directly
* Leeway exp claim decode token
* Dynamic token expires time
* Change name **blacklist** -> **denylist**
* Denylist custom check refresh and access tokens
* Issuer claim
* Audience claim
* Jwt decode algorithms
* Dynamic algorithm create token
* Token multiple location
* Support RSA encryption *(Thanks to @jet10000 for make issues)*
* Custom header name and type
* Custom error message key and status code
* JWT in cookies *(Thanks to @m4nuC for make issues)*
* Add Additional claims
* Add Documentation *(#9 by @paulussimanjuntak)*

## 0.2.0

* Call create_token and get_jti function must be from dependency injection
* Improve blacklist loader
* Can load env from pydantic
* Add docs on readme how to use without dependency injection and example on multiple files
* Fix raise jwt exception PR #1 by @ironslob 

## 0.1.0

* Initial release.
