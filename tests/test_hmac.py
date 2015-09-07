# Standard Libs
import unittest

# Third Party Libs
import httplib
from flask import Flask

# First Party Libs
from flask_hmac import Hmac


hmac = Hmac()


def create_app():
    app = Flask(__name__)
    app.config['TESTING'] = True
    app.config['HMAC_KEY'] = 's3cr3tk3y'
    hmac.init_app(app)

    @app.route("/no_auth_view")
    def no_auth_view():
        return "no_auth_view"

    @hmac.auth
    @app.route("/hmac_auth_view")
    def hmac_auth_view():
        return "hmac_auth_view"

    return app


class TestHmacSignature(unittest.TestCase):

    def setUp(self):
        app = create_app()
        self.app = app.test_client()

    def test_no_auth(self):
        response = self.app.get('/no_auth_view')
        assert httplib.OK == response.status_code
