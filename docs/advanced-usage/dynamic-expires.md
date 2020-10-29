You can also change the expires time for a token via parameter **expires_time** in the **create_access_token()** or **create_refresh_token()** function. This takes a *datetime.timedelta*, *integer*, or even *boolean* and overrides the `authjwt_access_token_expires` and `authjwt_refresh_token_expires` settings. This can be useful if you have different use cases for different tokens.

```python
@app.post('/create-dynamic-token')
def create_dynamic_token(Authorize: AuthJWT = Depends()):
    expires = datetime.timedelta(days=1)
    token = Authorize.create_access_token(subject="test",expires_time=expires)
    return {"token": token}
```

You can even disable expiration by setting **expires_time** to *False*:

```python
@app.post('/create-token-disable')
def create_dynamic_token(Authorize: AuthJWT = Depends()):
    token = Authorize.create_access_token(subject="test",expires_time=False)
    return {"token": token}
```
