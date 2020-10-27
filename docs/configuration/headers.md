These are only applicable if `authjwt_token_location` is use headers.

`authjwt_header_name`
:   What header to look for the JWT in a request. Defaults to `Authorization`

`authjwt_header_type`
:   What type of header the JWT is in. Defaults to `Bearer`. This can be an empty string,
    in which case the header contains only the JWT instead like `HeaderName: Bearer <JWT>`
