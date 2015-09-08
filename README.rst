Flask-HMAC
==========

|circle| |downloads| |version| |license|

This module provides an authentication to Flask routes. The intended use case
is for use with REST APIs. It's simply designed to check that a client is
entitled to access a particular route in a Flask application, based on the fact
that it must possess a copy of the secret key.


Usage
-----

Server
~~~~~~

.. sourcecode:: python

    app = Flask(__name__)
    app.config['HMAC_KEY'] = 's3cr3tk3y'  # define the secret key in an app config


    @app.route("/no_auth_view")
    def no_auth_view():
        return "no_auth_view"


    @app.route("/hmac_auth_view")
    @hmac.auth  # decorate view
    def hmac_auth_view():
        return "hmac_auth_view"


Call without payload
~~~~~~~~~~~~~~~~~~~~

.. sourcecode:: python

    sig = hmac.make_hmac()  # generate signature
    response = requests.get(
        '/hmac_auth_view',
        headers={hmac.header: sig}
    )


Call with payload
~~~~~~~~~~~~~~~~~

Request payload has to be used as a data for HMAC generation.

.. sourcecode:: python

    data = json.dumps({'foo': 'boo'})

    sig = hmac.make_hmac(data)  # generate signature
    response = requests.post(
        '/hmac_auth_view',
        data=data,
        headers={hmac.header: sig}
    )


.. |circle| image:: https://img.shields.io/circleci/project/thisissoon/flask-hmac.svg
    :target: https://circleci.com/gh/thisissoon/flask-hmac

.. |downloads| image:: http://img.shields.io/pypi/dm/flaskhmac.svg
    :target: https://pypi.python.org/pypi/flaskhmac

.. |version| image:: http://img.shields.io/pypi/v/flaskhmac.svg
    :target: https://pypi.python.org/pypi/flaskhmac

.. |license| image:: http://img.shields.io/pypi/l/flaskhmac.svg
    :target: https://pypi.python.org/pypi/flaskhmac
