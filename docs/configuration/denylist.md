`authjwt_denylist_enabled`
:   Enable/disable token revoking. Defaults to `False`

`authjwt_denylist_token_checks`
:   What token types to check against the denylist. The options are `access` or `refresh`.
    You can pass in a sequence to check more than one type. Defaults to `{'access', 'refresh'}`.
    Only used if deny listing is enabled. 
