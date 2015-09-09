'''
    flask-HMAC
    ----------

    Use HMAC tokens and a decorator to authenticate access to routes
'''

# Standard Libs
import base64
import hashlib
import hmac
from functools import wraps

# Third Party Libs
import six
from flask import abort, request

# First Party Libs
from .exceptions import InvalidSignature, SecretKeyIsNotSet


def encode_string(value):
    return value.encode('utf-8') if isinstance(value, six.text_type) else value


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
        self.hmac_key = six.b(app.config['HMAC_KEY'])
        self.hmac_disarm = app.config.get('HMAC_DISARM', False)

    def auth(self, route):
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

    def _hmac_factory(self, data, digestmod=None):
        return hmac.new(self.hmac_key, data, digestmod=self.digestmod)

    def make_hmac(self, data=''):
        hmac_token_server = self._hmac_factory(encode_string(data)).digest()
        hmac_token_server = base64.urlsafe_b64encode(hmac_token_server)
        return hmac_token_server

    def validate_signature(self, request):
        if self.hmac_disarm:
            return True
        hmac_token_client = self.get_signature(request)
        hmac_token_server = self.make_hmac(request.data)
        if hmac_token_client != hmac_token_server:
            raise InvalidSignature('Signatures are different: {0} {1}'.format(
                hmac_token_client, hmac_token_server
            ))
        return True
