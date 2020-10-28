In some cases you want to use one endpoint for both, protected and unprotected. In this situation you can use function **jwt_optional()**. This will allow the endpoint to be accessed regardless of if a JWT is sent in the request or not. If a JWT get tampering or expired an error will be returned instead of calling the endpoint.

```python hl_lines="37"
{!../examples/optional.py!}
```
