# fastapi-jwt-auth

[![Build Status](https://travis-ci.org/IndominusByte/fastapi-jwt-auth.svg?branch=master)](https://travis-ci.org/IndominusByte/fastapi-jwt-auth)
[![Coverage Status](https://coveralls.io/repos/github/IndominusByte/fastapi-jwt-auth/badge.svg?branch=master)](https://coveralls.io/github/IndominusByte/fastapi-jwt-auth?branch=master)
[![PyPI version](https://badge.fury.io/py/fastapi-jwt-auth.svg)](https://badge.fury.io/py/fastapi-jwt-auth)
![GitHub](https://img.shields.io/github/license/IndominusByte/fastapi-jwt-auth)

## Features
FastAPI extension that provides JWT Auth support (secure, easy to use and lightweight), if you were familiar with flask-jwt-extended this extension suitable for you because this extension inspired by flask-jwt-extended.
<ul>
  <li>Access token and refresh token</li>
  <li>Token freshness will only allow fresh tokens to access endpoint</li>
  <li>Token revoking/blacklisting</li>
  <li>Custom token revoking</li>
</ul>

## Installation
```bash
pip install fastapi-jwt-auth
```

## Usage


## Examples
Examples are available on [examples](/examples) folder.
There are:
- [Basic](/examples/basic.py)
- [Blacklist Token](/examples/blacklist.py)
- [Blacklist Token Use Redis](/examples/blacklist_redis.py)
- [Token Optional](/examples/optional_protected_endpoints.py)
- [Refresh Token](/examples/refresh_tokens.py)
- [Token Fresh](/examples/token_freshness.py)

## License
This project is licensed under the terms of the MIT license.
