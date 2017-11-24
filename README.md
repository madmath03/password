# Java Passwords

[![Build
Status](https://secure.travis-ci.org/madmath03/password.png)](https://travis-ci.org/madmath03/password)
[![codecov](https://codecov.io/gh/madmath03/password/branch/master/graph/badge.svg)](https://codecov.io/gh/madmath03/password)

A simple utility class to hash passwords and check passwords VS hashed values.

## Summary

It uses a combination of hashing and unique salt. The algorithm used is **PBKDF2WithHmacSHA512** which, although not the best for hashing password (vs. *bcrypt*) is still considered robust and recommended by NIST. The hashed value has 512 bits. 

This utility is inspired from the following links: 

*   [How do I generate a SALT in Java for Salted-Hash?](https://stackoverflow.com/a/18143616)
*   [How can I hash a password in Java?](https://stackoverflow.com/a/2861125)
*   [Do any security experts recommend bcrypt for password storage?](https://stackoverflow.com/a/18143616)
*   [Salted Password Hashing - Doing it Right](https://crackstation.net/hashing-security.htm)


## Contributing
See [CONTRIBUTING](https://github.com/madmath03/password/blob/master/CONTRIBUTING.md) file.

## License
This product is distributed under the MIT Licence.
See the complete license in the bundle:

[Read the license](https://github.com/madmath03/password/blob/master/LICENSE)
