'''
    flask-HMAC
    ----------

    Use HMAC tokens and a decorator to authenticate access to routes
'''

# Standard Libs
import base64
import binascii
import hashlib
import hmac
from functools import wraps

# Third Party Libs
import six
from flask import abort, request

from .exceptions import InvalidSignature, SecretKeyIsNotSet, UnknownKeyName


def encode_string(value):
    """ Encode unicode to string: unicode -> str, str -> str
    Arguments:
        value (str/unicode): string to encode
    Returns:
        encoded value (string)
    """
    return value.encode('utf-8') if isinstance(value, six.text_type) else value


def decode_string(value):
    """ Decode string: bytes -> str, str -> str
    Arguments:
        value (bytes/str): string to decode
    Returns:
        decoded value (strings)
    """
    return value if isinstance(value, six.string_types) else value.decode('utf-8')


class Hmac(object):

    def __init__(self, app=None, header=None, digestmod=None):
        self.header = header or 'Signature'
        self.digestmod = digestmod or hashlib.sha256
        if app:
            self.init_app(app)

    def get_signature(self, request):
        try:
            return six.b(request.headers[self.header])
        except KeyError:
            raise SecretKeyIsNotSet()

    def init_app(self, app):
        self.hmac_key = app.config.get('HMAC_KEY', None)
        self.hmac_keys = app.config.get('HMAC_KEYS', None)
        self.hmac_disarm = app.config.get('HMAC_DISARM', False)
        self.hmac_error_code = app.config.get('HMAC_ERROR_CODE', six.moves.http_client.FORBIDDEN)

    def auth(self, only=None):
        ''' Route decorator. Validates an incoming request can access the
        route function.

        Keyword Args:
            only (list): Optional list of clients that can access the view

        .. sourcecode:: python

            @app.route("/hmac_auth_view")
            @hmac.auth() # decorate view
            def hmac_auth_view():
                return "hmac_auth_view"

        .. sourcecode:: python

            @app.route("/hmac_auth_view")
            @hmac.auth(only=["foo"])  # decorate view
            def hmac_auth_view():
                return "hmac_auth_view"

        '''

        def real_decorator(route):
            @wraps(route)
            def decorated_view_function(*args, **kwargs):
                try:
                    self.validate_signature(request, only=only)
                except (SecretKeyIsNotSet, InvalidSignature):
                    return self.abort()
                return route(*args, **kwargs)
            return decorated_view_function
        return real_decorator

    def abort(self):
        abort(self.hmac_error_code)

    def _hmac_factory(self, data, key=None):
        key = key if key else self.hmac_key
        return hmac.new(six.b(key), data, digestmod=self.digestmod)

    def make_hmac(self, data='', key=None):
        hmac_token_server = self._hmac_factory(encode_string(data), key).digest()
        hmac_token_server = base64.b64encode(hmac_token_server)
        return hmac_token_server

    def make_hmac_for(self, name, data=''):
        ''' Generates HMAC key for named key
        Arguments:
            name (str): key name from HMAC_SECRETS dict
            data (str): HMAC message
        '''
        try:
            key = self.hmac_keys[name]
        except KeyError as ex:
            raise UnknownKeyName(ex)
        valuekey = '{0}:{1}'.format(name, decode_string(self.make_hmac(data, key)))
        token = base64.b64encode(six.b(valuekey))
        return token

    def _parse_multiple_signature(self, signature):
        try:
            valuekey = base64.urlsafe_b64decode(encode_string(signature))
            return decode_string(valuekey).split(':')
        except (TypeError, binascii.Error):
            raise InvalidSignature()

    def validate_signature(self, request, only=None):
        '''Validates a requests HMAC Signature against one generated server side
        from the same client secret key.

        Arguments:
            request (Request): flask request

        Raise:
            InvalidSignature: when signatures don't match
        '''

        if self.hmac_disarm:
            return

        signature = self.get_signature(request)
        hmac_server_tokens = []

        if self.hmac_key is not None:
            token = self.make_hmac(request.data)
            hmac_server_tokens.append(token)

        if self.hmac_keys is not None:
            try:
                client, sig = self._parse_multiple_signature(signature)
                if only is not None:
                    if client in only:
                        token = self.make_hmac_for(client, request.data)
                        hmac_server_tokens.append(token)
                else:
                    token = self.make_hmac_for(client, request.data)
                    hmac_server_tokens.append(token)
            except ValueError:
                # We fall here if the signature does is not vlaid on it's own
                # and does not contain a client id - we don't care since the
                # token will not be added to the list of keys to validate the
                # signature against
                pass

        if signature not in hmac_server_tokens:
            raise InvalidSignature
