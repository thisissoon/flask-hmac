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
from flask import jsonify, request
import six


def encode_string(value):
    return value.encode('utf-8') if isinstance(value, six.text_type) else value


class Hmac(object):

    def __init__(self, header=None, digestmod=None):
        self.header = header or 'Signature'
        self.digestmod = digestmod or hashlib.sha256

    def get_signature(self, request):
        return request.headers[self.header]

    def init_app(self, app):
        self.hmac_key = six.b(app.config['HMAC_KEY'])
        self.hmac_disarm = app.config.get('HMAC_DISARM', False)

    def auth(self, route_view_function):
        @wraps(route_view_function)
        def decorated_view_function(*args, **kwargs):
            if self.hmac_disarm:
                return route_view_function(*args, **kwargs)
            else:
                try:
                    hmac_token = self.get_signature(request)
                except:
                    message = {'status': '403', 'message': 'not authorized'}
                    response = jsonify(message)
                    response.status_code = 403
                    return response

                if self.compare_hmacs(request.data, hmac_token):
                    # The magic is here. If the hmac comparison passes, return the
                    # decorated function and proceed as expected.
                    return route_view_function(*args, **kwargs)
                else:
                    # Otherwise spit out a 403 response and leave it to the client
                    # to figure out why their request failed.
                    message = {'status': '403', 'message': 'not authorized'}
                    response = jsonify(message)
                    response.status_code = 403
                    return response
        return decorated_view_function

    def _hmac_factory(self, data, digestmod=None):
        return hmac.new(self.hmac_key, data, digestmod=self.digestmod)

    def make_hmac(self, data=''):
        hmac_token_server = self._hmac_factory(encode_string(data)).digest()
        hmac_token_server = base64.urlsafe_b64encode(hmac_token_server)
        return hmac_token_server

    def compare_hmacs(self, data, hmac_token_client):
        hmac_token_server = self.make_hmac(data)
        return six.b(hmac_token_client) == hmac_token_server
