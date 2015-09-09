
class HmacException(Exception):
    pass


class SecretKeyIsNotSet(HmacException):
    pass


class InvalidSignature(HmacException):
    pass
