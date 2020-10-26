<h1 align="left" style="margin-bottom: 20px; font-weight: 500; font-size: 50px; color: black;">
  FastAPI JWT Auth
</h1>

[![Build Status](https://travis-ci.org/IndominusByte/fastapi-jwt-auth.svg?branch=master)](https://travis-ci.org/IndominusByte/fastapi-jwt-auth)
[![Coverage Status](https://coveralls.io/repos/github/IndominusByte/fastapi-jwt-auth/badge.svg?branch=master)](https://coveralls.io/github/IndominusByte/fastapi-jwt-auth?branch=master)
[![PyPI version](https://badge.fury.io/py/fastapi-jwt-auth.svg)](https://badge.fury.io/py/fastapi-jwt-auth)
[![Downloads](https://pepy.tech/badge/fastapi-jwt-auth)](https://pepy.tech/project/fastapi-jwt-auth)

---

## Features
FastAPI extension that provides JWT Auth support (secure, easy to use and lightweight), if you were familiar with flask-jwt-extended this extension suitable for you because this extension inspired by flask-jwt-extended.

- Access token and refresh token
- Token freshness
- Token revoking
- Support for adding custom claims to JSON Web Tokens
- Support RSA encryption
- Storing tokens in cookies and CSRF protection

## Installation
The easiest way to start working with this extension with pip

```bash
pip install fastapi-jwt-auth
```

If you want to use asymmetric (public/private) key signing algorithms, include the <b>asymmetric</b> extra requirements.
```bash
pip install 'fastapi-jwt-auth[asymmetric]'
```

## License
This project is licensed under the terms of the MIT license.
