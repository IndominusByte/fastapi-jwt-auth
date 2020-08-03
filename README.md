# fastapi-jwt-auth
FastAPI extension that provides JWT Auth support (secure, easy to use and lightweight), if you were familiar with flask-jwt-extended this extension suitable for you because this extension inspired by flask-jwt-extended.

## Features
<ul>
  <li>Access Token and Refresh Token</li>
  <li>Token freshness will only allow fresh tokens to access endpoint</li>
  <li>Token revoking/blacklisting using Redis</li>
</ul>

## TODO
<ul>
  <li>Custom config like token expired, etc <i>(On Going)</i></li>
  <li>Custom config redis host and port <i>(On Going)</i></li>
  <li>Support for adding custom claims to JSON Web Tokens</li>
  <li>Migrate to pip package</li>
</ul>

## Usage
