from flask import request, jsonify
import sensitive
from utils.database import get_user_by_id
from utils.util import normalize_string
import utils.jwt

JWT_SECRET = sensitive.get_jwt_secret()


class User:

    def __init__(self, *args, **kwargs):
        data = {
            key: normalize_string(value) if value is not None else None
            for key, value in kwargs.items()
        }

        self.id = data.get("id")
        self.first_name = data.get("first_name")
        self.last_name = data.get("last_name")
        self.email = data.get("email")
        self.password = data.get("password")
        self.role = data.get("role")
        self.bio = data.get("bio")
        self.created_at = data.get("created_at")

    def __str__(user):
        return f"{user.first_name} {user.last_name}"


def authenticate(admin_required=False):
    """Decorator to authenticate a user based on JWT token.
    If admin_required is True, it checks if the user has admin privileges.
    """
    def decorator(f):
        def wrapper(*args, **kwargs):
            token = request.headers.get("Authorization")
            if not token:
                return jsonify({"error": "Token is missing"}), 401

            if token.startswith("Bearer "):
                token = token[7:]

            try:
                payload = utils.jwt.decode_jwt(token, JWT_SECRET)
                if not payload:
                    return jsonify({"error": "Invalid token"}), 401
            except Exception as e:
                return jsonify({"error": "Invalid token"}), 401

            user_id = payload.get("id")
            if not user_id:
                return jsonify({"error": "User ID not found in token"}), 401

            user = get_user_by_id(user_id)
            if not user:
                return jsonify({"error": "User not found"}), 404

            if admin_required:
                user_role = payload.get("role")
                if user_role != "admin":
                    return jsonify({"error": "Admin privileges required"}), 403

            request.user = User(
                first_name=user.get("first_name"),
                last_name=user.get("last_name"),
                email=user.get("email"),
                role=user.get("role"),
                id=user.get("id"),
                bio=user.get("bio"),
                created_at=user .get("created_at")
            )

            return f(*args, **kwargs)

        wrapper.__name__ = f.__name__
        return wrapper
    return decorator
