`authjwt_token_location`
:   Where to look for a JWT when processing a request. The options are `headers` or `cookies`.
    You can pass in a sequence to set more than one location `('headers','cookies')`. Defaults to `{'headers'}`
    if you pass headers and cookies, headers are precedence.

`authjwt_secret_key`
:   The secret key needed for symmetric based signing algorithms, such as `HS*`. Defaults to `None`

`authjwt_public_key`
:   The public key needed for asymmetric based signing algorithms, such as `RS*` or `ES*`. PEM format expected.
    Defaults to `None`

`authjwt_private_key`
:   The private key needed for asymmetric based signing algorithms, such as `RS*` or `ES*`. PEM format expected.
    Defaults to `None`

`authjwt_algorithm`
:   Which algorithm to sign the JWT with. <a href="https://pyjwt.readthedocs.io/en/latest/algorithms.html" class="external-link" target="_blank">See here</a>
    for the options. Defaults to `HS256`

`authjwt_decode_algorithms`
:   Which algorithms are allowed to decode a JWT. Defaults to a list with only the algorithm set in `authjwt_algorithm`

`authjwt_decode_leeway`
:   Define the leeway part of the expiration time definition, which means you can validate an expiration
    time which is in the past but not very far. Defaults to `0`

`authjwt_encode_issuer`
:   Define the issuer to set the issuer in JWT claims, only access token have issuer claim. Defaults to `None`

`authjwt_decode_issuer`
:   Define the issuer to check the issuer in JWT claims, only access token have issuer claim. Defaults to `None`

`authjwt_decode_audience`
:   The audience or list of audiences you expect in a JWT when decoding it. Defaults to `None`

`authjwt_access_token_expires`
:   How long an access token should live before it expires. This takes value `integer` *(seconds)* or
    `datetime.timedelta`, and defaults to **15 minutes**. Can be set to `False` to disable expiration.

`authjwt_refresh_token_expires`
:   How long an refresh token should live before it expires. This takes value `integer` *(seconds)* or
    `datetime.timedelta`, and defaults to **30 days**. Can be set to `False` to disable expiration.
