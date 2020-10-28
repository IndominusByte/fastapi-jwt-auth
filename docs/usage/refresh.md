These are long-lived tokens which can be used to create a new access tokens once an old access token has expired. Refresh tokens cannot access an endpoint that is protected with **jwt_required()**, **jwt_optional()**, and **fresh_jwt_required()** and access tokens cannot access an endpoint that is protected with **jwt_refresh_token_required()**.

Utilizing refresh tokens we can help reduce the damage that can be done if an access tokens is stolen. However, if an attacker gets a refresh tokens they can keep generating new access tokens and accessing protected endpoints as though he was that user. We can help combat this by using the fresh tokens pattern, discussed in the next section.

Here is an example of using access and refresh tokens:

```python hl_lines="35 46"
{!../examples/refresh.py!}
```
