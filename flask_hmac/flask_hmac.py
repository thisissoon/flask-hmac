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
    ''' This module provides three functions to authenticate calls to a Flask route.
        The intended use case is for use with REST APIs. This module is not intended
        to do any kind of login or session management, it is simply designed to check
        that a client is entitled to access a particular route in a Flask application,
        based on the fact that it must possess a copy of the shared/secret key.

        To use this module, add an 'HMAC_KEY' to your application's config object. For
        example: HMAC_KEY = 2a21c5b3bff0299c0161470468f355e5b4afcf17a5f593ab68394e

        Next, in your client code, send a base64 url safe encoded header of the HMAC
        like this: "HMAC: UKW-EaC9diBPuRTgwaUprw4pf4h1nTJyClCT48dbhQo"
        Ensure that any trailing = characters are stripped.

        The three provided methods are:
        1. check_wrapper() decorator function, which wraps a route with a call to:
        2. check_hmac() function, which compares a client supplied token with a server
        generated token. If the two match, return the decorated function. If not,
        return a 403 response.
        3. render_hmac() function, which, you guessed it, generates an hmac.

        To use this module, instantiate it like this:

        import flask_hmac
        app = Flask(__name__)
        Hmac = flask_hmac.Hmac(app)

        Now you can decorate a route with the @Hmac.check decorator like so:

        @app.route('/path/to/api/endpoint', METHODS = ['PUT', 'POST'])
        @Hmac.check_hmac

        Lastly, you can temporarily disable the check_hmac validation with a config value.
        Make a variable HMAC_DISARM = True in your app.config. This setting is useful for
        testing as it allows you to leave all decorator calls in place for routes/blueprints.

        TODO: allow passing custom status messages and codes on __init__
    '''

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
