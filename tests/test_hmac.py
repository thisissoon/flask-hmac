# Standard Libs
import json
import unittest

# Third Party Libs
from flask import Flask, abort, request

# First Party Libs
from flask_hmac import Hmac
from flask_hmac.exceptions import HmacException, UnknownKeyName


hmac = Hmac()


def create_app(disable_hmac=None):
    app = Flask(__name__)
    app.config['TESTING'] = True
    app.config['HMAC_KEY'] = 's3cr3tk3y'
    if disable_hmac:
        app.config['HMAC_DISARM'] = disable_hmac
    hmac.init_app(app)

    @app.route('/no_auth_view')
    def no_auth_view():
        return 'no_auth_view'

    @app.route('/hmac_auth_view', methods=['GET', 'POST'])
    @hmac.auth
    def hmac_auth_view():
        return 'hmac_auth_view'

    return app


class TestHmacSignature(unittest.TestCase):

    def setUp(self):
        app = create_app()
        app.config['HMAC_KEYS'] = {'a': 'aa', 'b': 'bb'}
        self.app = app.test_client()
        hmac.init_app(app)

    def test_signature_shouldnt_be_empty(self):
        assert hmac.make_hmac()

    def test_signature_for_different_client(self):
        assert hmac.make_hmac_for('a') != hmac.make_hmac_for('b')
        assert hmac.make_hmac_for('a') == hmac.make_hmac_for('a')

    def test_raise_exception_when_unknown_service_is_given(self):
        self.assertRaises(UnknownKeyName, hmac.make_hmac_for, '?')


class TestDisabledHmacSignatureViews(unittest.TestCase):

    def setUp(self):
        app = create_app(disable_hmac=True)
        self.app = app.test_client()

    def test_no_auth_view_should_be_ok(self):
        response = self.app.get('/no_auth_view')
        assert 200 == response.status_code

    def test_auth_without_signature_should_return_200(self):
        response = self.app.get('/hmac_auth_view')
        assert 200 == response.status_code

    def test_auth_with_invalid_signature_should_return_200(self):
        response = self.app.get('/hmac_auth_view', headers={hmac.header: '00'})
        assert 200 == response.status_code

    def test_auth_with_valid_signature_should_return_200(self):
        sig = hmac.make_hmac()
        response = self.app.get('/hmac_auth_view', headers={hmac.header: sig})
        assert 200 == response.status_code


class TestHmacSignatureViews(unittest.TestCase):

    def setUp(self):
        app = create_app()
        self.app = app.test_client()
        app.config['HMAC_KEY'] = 's3cr3tk3y'
        app.config['HMAC_KEYS'] = {'a': 'aa', 'b': 'bb'}
        hmac.init_app(app)

    def test_no_auth_view_should_be_ok(self):
        response = self.app.get('/no_auth_view')
        assert 200 == response.status_code

    def test_auth_without_signature_should_return_403(self):
        response = self.app.get('/hmac_auth_view')
        assert 403 == response.status_code

    def test_auth_with_invalid_signature_should_return_403(self):
        response = self.app.get('/hmac_auth_view', headers={hmac.header: '00'})
        assert 403 == response.status_code

    def test_auth_with_valid_signature_should_return_200(self):
        sig = hmac.make_hmac()
        response = self.app.get('/hmac_auth_view', headers={hmac.header: sig})
        assert 200 == response.status_code

    def test_signature_with_request_data(self):
        data = json.dumps({'foo': 'boo'})

        sig = hmac.make_hmac(data)
        response = self.app.post(
            '/hmac_auth_view',
            data=data,
            headers={hmac.header: sig}
        )
        assert 200 == response.status_code

    def test_signature_with_changed_request_data(self):
        data = json.dumps({'foo': 'boo'})

        sig = hmac.make_hmac(data)
        response = self.app.post(
            '/hmac_auth_view',
            data=json.dumps({'foo': 'bla'}),
            headers={hmac.header: sig}
        )
        assert 403 == response.status_code


class TestHmacSignatureFlaskBeforeQuest(unittest.TestCase):

    def setUp(self):
        app = Flask(__name__)
        app.config['TESTING'] = True
        app.config['HMAC_KEY'] = 's3cr3tk3y'
        self.hmac = Hmac(app)

        @app.route('/autodecorated')
        def autodecorated():
            return 'autodecorated'

        @app.before_request
        def before_request():
            try:
                self.hmac.validate_signature(request)
            except HmacException:
                return abort(400)

        self.app = app.test_client()

    def test_signature_hook(self):
        response = self.app.get('/autodecorated')
        assert 400 == response.status_code


class TestHmacSignatureFlaskBeforeQuestClientSecrets(unittest.TestCase):

    def setUp(self):
        app = Flask(__name__)
        app.config['TESTING'] = True
        app.config['HMAC_KEYS'] = {'a': 'aa', 'b': 'bb'}
        self.hmac = Hmac(app)

        self.app = app.test_client()

        @app.route('/autodecorated')
        def autodecorated():
            return 'autodecorated'

        @app.before_request
        def before_request():
            try:
                self.hmac.validate_client_signature(request)
            except HmacException:
                return abort(400)

    def test_signature_hook(self):
        response = self.app.get('/autodecorated')
        assert 400 == response.status_code

    def test_valid_signature(self):
        sig = self.hmac.make_hmac_for('a')
        response = self.app.get('/autodecorated', headers={self.hmac.header: sig})
        assert 200 == response.status_code

    def test_invalid_generated_signature(self):
        sig = self.hmac.make_hmac_for('a', 'some data')
        response = self.app.get('/autodecorated', headers={self.hmac.header: sig})
        assert 400 == response.status_code

    def test_invalid_signature(self):
        response = self.app.get('/autodecorated', headers={self.hmac.header: '00'})
        assert 400 == response.status_code
