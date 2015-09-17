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
        self.hmac_key = app.config.get('HMAC_KEY', '')
        self.hmac_keys = app.config.get('HMAC_KEYS', {})
        self.hmac_disarm = app.config.get('HMAC_DISARM', False)

    def auth(self, route):
        ''' Route decorator

        .. sourcecode:: python

            @app.route("/hmac_auth_view")
            @hmac.auth  # decorate view
            def hmac_auth_view():
                return "hmac_auth_view"
        '''
        @wraps(route)
        def decorated_view_function(*args, **kwargs):
            try:
                self.validate_signature(request)
            except (SecretKeyIsNotSet, InvalidSignature):
                return self.abort()
            return route(*args, **kwargs)
        return decorated_view_function

    def abort(self):
        abort(403)

    def _hmac_factory(self, data, key=None):
        key = key if key else self.hmac_key
        return hmac.new(six.b(key), data, digestmod=self.digestmod)

    def make_hmac(self, data='', key=None):
        hmac_token_server = self._hmac_factory(encode_string(data), key).digest()
        hmac_token_server = base64.urlsafe_b64encode(hmac_token_server)
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
        token = base64.urlsafe_b64encode(six.b(valuekey))
        return token

    def validate_signature(self, request):
        ''' Generates HMAC key

        Arguments:
            request (Request): flask request

        Raise:
            InvalidSignature: when signatures don't match
        '''
        if self.hmac_disarm:
            return True
        hmac_token_client = self.get_signature(request)
        hmac_token_server = self.make_hmac(request.data)
        if hmac_token_client != hmac_token_server:
            raise InvalidSignature('Signatures are different: {0} {1}'.format(
                hmac_token_client, hmac_token_server
            ))
        return True

    def _parse_multiple_signature(self, signature):
        try:
            valuekey = base64.urlsafe_b64decode(encode_string(signature))
            return decode_string(valuekey).split(':')
        except (TypeError, binascii.Error):
            raise InvalidSignature()

    def validate_service_signature(self, request):
        if self.hmac_disarm:
            return True
        signature = self.get_signature(request)
        key_name, hmac_token_client = self._parse_multiple_signature(signature)

        hmac_token_server = self.make_hmac_for(key_name, request.data)
        if signature != hmac_token_server:
            raise InvalidSignature('Signatures are different: {0} {1}'.format(
                signature, hmac_token_server
            ))
        return True
