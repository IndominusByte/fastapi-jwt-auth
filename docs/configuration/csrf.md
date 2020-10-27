`authjwt_cookie_csrf_protect`
:   Enable/disable CSRF protection when using cookies. Defaults to `True`

`authjwt_access_csrf_cookie_key`
:   Key of the CSRF access cookie. Defaults to `'csrf_access_token'`

`authjwt_refresh_csrf_cookie_key`
:   Key of the CSRF refresh cookie. Defaults to `'csrf_refresh_token'`

`authjwt_access_csrf_cookie_path`
:   Path for the CSRF access cookie. Defaults to `'/'`

`authjwt_refresh_csrf_cookie_path`
:   Path for the CSRF refresh cookie. Defaults to `'/'`

`authjwt_access_csrf_header_name`
:   Name of the header that should contain the CSRF double submit value for access tokens. Defaults to `X-CSRF-TOKEN`

`authjwt_refresh_csrf_header_name`
:   Name of the header that should contains the CSRF double submit value for refresh tokens. Defaults to `X-CSRF-TOKEN`

`authjwt_csrf_methods`
:   The request methods that will use CSRF protection. Defaults to `{'POST','PUT','PATCH','DELETE'}` 
