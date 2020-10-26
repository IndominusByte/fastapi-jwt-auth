These are long-lived tokens which can be used to create new access tokens once an old access token has expired. refresh tokens cannot access an endpoint that is protected with <b>jwt_required()</b>, <b>jwt_optional()</b>, and <b>fresh_jwt_required()</b> and access tokens cannot access an endpoint that is protected with <b>jwt_refresh_token_required()</b>.

Utilizing refresh tokens we can help reduce the damage that can be done if an access token is stolen. however, if an attacker gets a refresh token they can keep generating new access tokens and accessing protected endpoints as though he was that user. we can help combat this by using the fresh token pattern, discussed in the next section.

Here is an example of using access and refresh tokens:

```python
{!../examples/refresh.py!}
```
