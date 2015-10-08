Change Log
----------

1.2
~~~~~
- BREAKING CHANGE: `@hmac.auth` decorator now needs to be called as `@hmac.auth()`
- New `only` argument for `@hmac.auth()` to only allow specific clients access

1.1.2
~~~~~
- Swaps `urlsafe_b64encode` for `b64encode`

1.1.1
~~~~~
- Support multiple keys

0.1.1
~~~~~~~~~
- Able to change secret key in `make_hmac` method
- Method `validate_signature` created which can be used outside of `Hmac` class
- Custom exceptions

0.0.1
~~~~~~~~~
- Initial release including the core feature set
