flask-HMAC
----------

This module provides three functions to authenticate calls to a Flask route. The
intended use case is for use with REST APIs. This module is not intended to do
any kind of login or session management, it is simply designed to check that a
client is entitled to access a particular route in a Flask application, based on
the fact that it must possess a copy of the shared/secret key.

Usage
#####

Usage consists of a server decorator or calling the render_hmac function, and a
client (or function in the server application) passing a base64 encoded HMAC.

Server/Application Usage
========================

To use this module in your application, add an 'HMAC_KEY' to your application's
config object. For example:

``HMAC_KEY = 2a21c5b3bff0299c0161470468f355e5b4afcf17a5f593ab68394e``

The three provided methods are:

1. ``check_wrapper()`` decorator function, which wraps a route with a call to:

2. ``compare_hmacs()`` function, which compares a client supplied token with a
server generated token. If the two match, return the decorated function. If not,
return a 403 response.

3. ``render_hmac()`` function, which, you guessed it, generates an hmac.

To use this module, instantiate it like this:

.. code:: python

    from flask_hmac import Hmac
    app = Flask(__name__)
    hm = Hmac(app)

Now you can decorate a route with the @hm.check_hmac decorator like so:

.. code:: python

    @app.route('/path/to/api/endpoint', METHODS = ['PUT', 'POST'])
    @hm.check_hmac

Lastly, you can temporarily disable the check_hmac validation with a config
value. Make a variable ``HMAC_DISARM = True`` in your app.config object. This
setting is useful for testing as it allows you to leave all decorator calls in
place for routes/blueprints.

Client usage
============

To pass an HMAC from your client, send a base64 url safe encoded header of the
HMAC like this:

``"HMAC: UKW-EaC9diBPuRTgwaUprw4pf4h1nTJyClCT48dbhQo"``

Ensure that any trailing = characters are stripped and you should be all set.

TODO
####
1. Allow using any kind of rendered HMAC like hexdigest instead of only base64
url safe.

2. Create self.status_code and self.message variables for use on __init__ to
allow custom responses on HMAC comparison failure.
