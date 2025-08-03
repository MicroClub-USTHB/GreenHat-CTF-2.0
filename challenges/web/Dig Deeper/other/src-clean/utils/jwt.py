import jwt


def sign_jwt(payload, secret):
    """
    Sign a JWT with the given payload and secret.
    """
    return jwt.encode(payload, secret, algorithm='HS256')


def decode_jwt(token, secret):
    """
    Decode a JWT with the given token and secret.
    """
    try:
        return jwt.decode(token, secret, algorithms=['HS256'])
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None
