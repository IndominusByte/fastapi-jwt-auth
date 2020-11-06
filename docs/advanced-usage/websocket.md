The WebSocket protocol doesn’t handle authorization or authentication. Practically, this means that a WebSocket opened from a page behind auth doesn’t "automatically" receive any sort of auth. You need to take steps to also secure the WebSocket connection.

Since you cannot customize WebSocket headers from JavaScript, you’re limited to the "implicit" auth (i.e. Basic or cookies) that’s sent from the browser. The more common approach to generates a token from your normal HTTP server and then have the client send the token (either as a query string in the WebSocket path or as the first WebSocket message). The WebSocket server then validates that the token is valid.

**Note**: *Change all IP address to your localhost*

Here is an example of how you authorize from query URL:
```python hl_lines="42-52 65-66 71 73"
{!../examples/websocket.py!}
```
You will see a simple page like this:

<figure>
  <img src="https://bit.ly/3k2BpaM"/>
</figure>

You can copy the token from endpoint **/login** and then send them:

<figure>
  <img src="https://bit.ly/3k4Y9XC"/>
</figure>

And your WebSocket route will respond back if the token is valid or not:

<figure>
  <img src="https://bit.ly/36ajZ7d"/>
</figure>


Here is an example of how you authorize from cookie:
```python hl_lines="30-47 60-61 66 68"
{!../examples/websocket_cookie.py!}
```

You will see a simple page like this:

<figure>
  <img src="https://bit.ly/2TXs8Gi"/>
</figure>

You can get the token from URL **/get-cookie**:

<figure>
  <img src="https://bit.ly/2I9qtLG"/>
</figure>

And click button send then your WebSocket route will respond back if the
cookie and csrf token is match or cookie is valid or not:

<figure>
  <img src="https://bit.ly/3l3D8hB"/>
</figure>
