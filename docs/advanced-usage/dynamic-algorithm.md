You can specify which algorithm you would like to use to sign the JWT by using the **algorithm** parameter in **create_access_token()** or **create_refresh_token()**. Also you need to specify which algorithms you would like to permit when validating in protected endpoint by settings `authjwt_decode_algorithms` which take a *sequence*. If the JWT doesn't have algorithm in `authjwt_decode_algorithms` the token will be rejected.

```python hl_lines="16 35-36"
{!../examples/dynamic_algorithm.py!}
```
