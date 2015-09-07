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


class Hmac(object):

    def __init__(self, app=None):
        if app is not None:
            self.init_app(app)

    def init_app(self, app):
        self.hmac_key = app.config['HMAC_KEY']
        self.hmac_disarm = app.config.get('HMAC_DISARM', False)

    def auth(self, route_view_function):
        @wraps(route_view_function)
        def decorated_view_function(*args, **kwargs):
            if self.hmac_disarm:
                return route_view_function(*args, **kwargs)
            else:
                try:
                    hmac_token = request.headers['HMAC']
                except:
                    message = {'status': '403', 'message': 'not authorized'}
                    response = jsonify(message)
                    response.status_code = 403
                    return response

                if self.compare_hmacs(self.hmac_key, request.path, hmac_token):
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

    def hmac_factory(self, secret, data, digestmod=None):
        if digestmod is None:
            digestmod = hashlib.sha256
        try:
            hmac_token = hmac.new(secret, data, digestmod=digestmod)
            return hmac_token
        except TypeError as err:
            raise err

    def make_hmac(self, secret, data):
        hmac_token_server = self.hmac_factory(secret, data).digest()
        hmac_token_server = base64.urlsafe_b64encode(hmac_token_server).replace('=', '')
        return hmac_token_server

    def compare_hmacs(self, secret, data, hmac_token_client):
        hmac_token_server = self.make_hmac(secret, data)
        return hmac_token_client == hmac_token_server
