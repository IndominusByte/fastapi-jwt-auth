In some cases you want to use one endpoint for both, protected and unprotected. in this situation you can use function <b>jwt_optional()</b>. this will allow the endpoint to be accessed regardless of if a JWT is sent in the request or not. if a JWT get tampering or expired an error will be returned instead of calling the endpoint.

```python
{!../examples/optional.py!}
```
