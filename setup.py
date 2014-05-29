"""
Flask-HMAC

"""
from setuptools import setup

with open('README.rst') as file:
    long_description = file.read()

setup(
    name='Flask-HMAC',
    version='0.1.1',
    url='http://github.com/jamonation/flask-hmac',
    license='WTFPL',
    author='Jamon Camisso',
    author_email='jamonation+flask@gmail.com',
    description='Flask HMAC generator, checker, and route decorator',
    long_description=long_description,
    py_modules=['flask_hmac'],
    zip_safe=False,
    include_package_data=True,
    platforms='any',
    install_requires=['Flask'],
    classifiers=[
        'Environment :: Web Environment',
        'Framework :: Flask',
        'Intended Audience :: Developers',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
        'Topic :: Security :: Cryptography',
        'Topic :: Software Development :: Libraries :: Python Modules'
    ]
)
