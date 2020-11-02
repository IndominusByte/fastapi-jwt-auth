Highly recommended using JWT in cookies, if your frontend interacts with the backend, your frontend may be storing JWT in the browser localStorage or sessionStorage. There is nothing wrong with this, but if you have any sort of XSS vulnerability on your site, an attacker will be able to trivially steal your tokens. If you want some additional security on your site, you can save your JWT in an httponly cookies. Which keeps javascript cannot be able to access the cookies.

Here is a basic example of how to store JWT in cookies:

!!! note
    You can also create cookies or unset cookies when returning a `Response` directly in your code.
    To do that, you can create a response then set the response in set cookies or unset cookies

    ``` python
    ...
    response = JSONResponse(content={"msg":"Successfully login"})
    # Set the JWT and CSRF double submit cookies in the response
    Authorize.set_access_cookies(access_token,response)
    Authorize.set_refresh_cookies(refresh_token,response)
    return response
    ```

```python hl_lines="21 23 46-47 57 69"
{!../examples/jwt_in_cookies.py!}
```

This isn't the full story. However now we can keep our cookies from being stolen via XSS attacks, but session cookies vulnerable to CSRF attacks. To combat CSRF attacks we are going to use a technique called double submit cookie pattern. Double submitting cookies is defined as sending a random value in both a cookie and as a request parameter, with the server verifying if the cookie value and request value are equal.

<figure>
  <img src="https://miro.medium.com/max/648/1*WP_VXYjJxUyqfrul8K-4uw.png"/>
  <figcaption>
    <a href="https://medium.com/@kaviru.mihisara/double-submit-cookie-pattern-820fc97e51f2" target="_blank">
      Double Submit Cookie Pattern
    </a>
  </figcaption>
</figure>

This tokens is saved in a cookie with httponly set to True, so it cannot be accessed via javascript. We will then create a secondary cookie that contains an only random string, but has httponly set to False so that it can be accessed via javascript running on your website.

Now in order to access a protected endpoint, you will need to add a custom header that contains the random string in it, and if that header doesn’t exist or it doesn’t match the string that is stored in the JWT, the requester will be kicked out as unauthorized.

To break this down, if an attacker attempts to perform a CSRF attack they will send the JWT *(via cookie)* to protected endpoint, but without the random string in the request headers, they won't be able to access the endpoint. They cannot access the random string unless they can run javascript on your website *likely via an XSS attack*, and if they are able to perform an XSS attack, they will not be able to steal the actual access and refresh JWT, as javascript is still not able to access those httponly cookies.

No system is safe. If an attacker can perform an XSS attack they can still access protected endpoints from people who visit your site. However, it is better than if they were able to steal the access and refresh tokens from local/session storage, and use them whenever they wanted.

Here is an example of using cookies with CSRF protection:

```python hl_lines="23 25 27 29 56-57 67 79"
{!../examples/csrf_protection_cookies.py!}
```
