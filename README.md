<h1 align="left" style="margin-bottom: 20px; font-weight: 500; font-size: 50px; color: black;">
  FastAPI JWT Auth
</h1>

![Tests](https://github.com/IndominusByte/fastapi-jwt-auth/workflows/Tests/badge.svg)
[![Coverage Status](https://coveralls.io/repos/github/IndominusByte/fastapi-jwt-auth/badge.svg?branch=master)](https://coveralls.io/github/IndominusByte/fastapi-jwt-auth?branch=master)
[![PyPI version](https://badge.fury.io/py/fastapi-jwt-auth.svg)](https://badge.fury.io/py/fastapi-jwt-auth)
[![Downloads](https://static.pepy.tech/personalized-badge/fastapi-jwt-auth?period=total&units=international_system&left_color=grey&right_color=brightgreen&left_text=Downloads)](https://pepy.tech/project/fastapi-jwt-auth)

---

**Documentation**: <a href="https://indominusbyte.github.io/fastapi-jwt-auth" target="_blank">https://indominusbyte.github.io/fastapi-jwt-auth</a>

**Source Code**: <a href="https://github.com/IndominusByte/fastapi-jwt-auth" target="_blank">https://github.com/IndominusByte/fastapi-jwt-auth</a>

---

## Features
FastAPI extension that provides JWT Auth support (secure, easy to use and lightweight), if you were familiar with flask-jwt-extended this extension suitable for you, cause this extension inspired by flask-jwt-extended 😀

- Access tokens and refresh tokens
- Freshness Tokens
- Revoking Tokens
- Support for adding custom claims to JSON Web Tokens
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
