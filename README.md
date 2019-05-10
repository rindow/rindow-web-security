Apply authentication, access control, etc. to the web
=====================================================
Master: [![Build Status](https://travis-ci.com/rindow/rindow-web-security.png?branch=master)](https://travis-ci.com/rindow/rindow-web-security)

Components that apply basic security functions to the web.

- Basic authentication using PSR-7 middleware
- PHP session-based forms authentication using PSR-7 middleware
- Cookie-based RememberMe mechanism
- CSRF token mechanism
- CORS mechanism

It aims to be framework independent code, but now relies in part on Rindow-Security-Core and Rindow-Web-Mvc.
