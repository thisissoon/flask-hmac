Flask-HMAC
----------

This module provides three functions to authenticate calls to a Flask route. The
intended use case is for use with REST APIs. It's simply designed to check that a
client is entitled to access a particular route in a Flask application, based on
the fact that it must possess a copy of the secret key.


## Usage

### Server
```python
app = Flask(__name__)
app.config['HMAC_KEY'] = 's3cr3tk3y'  # define the secret key in an app config


@app.route("/no_auth_view")
def no_auth_view():
    return "no_auth_view"


@app.route("/hmac_auth_view")
@hmac.auth  # decorate view
def hmac_auth_view():
    return "hmac_auth_view"
```

### Call without payload
```python
sig = hmac.make_hmac()  # generate signature
response = requests.get(
    '/hmac_auth_view',
    headers={hmac.header: sig}
)
```

### Call with payload

Request payload has to be used as a data for HMAC generation.

```python
data = json.dumps({'foo': 'boo'})

sig = hmac.make_hmac(data)  # generate signature
response = requests.post(
    '/hmac_auth_view',
    data=data,
    headers={hmac.header: sig}
)
```
