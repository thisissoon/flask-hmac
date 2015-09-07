# Standard Libs
import unittest

# Third Party Libs
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

    @app.route("/hmac_auth_view")
    @hmac.auth
    def hmac_auth_view():
        return "hmac_auth_view"

    return app


class TestHmacSignature(unittest.TestCase):

    def setUp(self):
        app = create_app()
        self.app = app.test_client()

    def test_no_auth_view_should_be_ok(self):
        response = self.app.get('/no_auth_view')
        assert 200 == response.status_code

    def test_auth_without_signature_should_return_403(self):
        response = self.app.get('/hmac_auth_view')
        assert 403 == response.status_code
