
from flask import Flask, request, jsonify, render_template, redirect, url_for, flash, session
from os import environ
from re import compile

import utils.jwt as jwt_utils
import utils.database as db_utils
import sensitive

from secrets import randbelow as random_int
from utils.auth import authenticate
from utils.util import generate_fake_flag

app = Flask(__name__)

SECRET_KEY = environ.get("SECRET_KEY")
app.secret_key = SECRET_KEY
PORT = int(environ.get("PORT"))
JWT_SECRET = sensitive.get_jwt_secret()
DECRYPTION_KEY = environ.get("DECRYPTION_KEY")

db_utils.init_db()


@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")


@app.route("/register", methods=["GET"])
def register_page():
    return render_template("register.html")


@app.route("/login", methods=["GET"])
def login_page():
    return render_template("login.html")


@app.route("/dashboard", methods=["GET"])
def dashboard():
    return render_template("dashboard.html")


@app.route("/admin", methods=["GET"])
def admin_panel():
    return render_template("admin.html")


@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"}), 200


@app.route("/api/register", methods=["POST"])
def register():
    data = request.json
    first_name = data.get("first_name")
    last_name = data.get("last_name")
    email = data.get("email")
    password = data.get("password")

    if not first_name or not last_name:
        return jsonify({"error": "First name and last name are required"}), 400

    name_regex = r"[^\.\{\}\<\>\[\]\\\/]+"

    if not compile(name_regex).match(first_name) or not compile(name_regex).match(last_name):
        return jsonify({"error": "Invalid characters in name"}), 400

    if not email or not password:
        return jsonify({"error": "Email and password are required"}), 400

    email_regex = compile(r"[^@]+@[^@]+\.[^@]+")
    if not email_regex.match(email):
        return jsonify({"error": "Invalid email format"}), 400

    password_regex = compile(r"^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$")
    if not password_regex.match(password):
        return jsonify({"error": "Password must be at least 8 characters long and contain at least one letter and one number"}), 400

    existing_user = db_utils.get_user_by_email(email)

    if existing_user:
        return jsonify({"error": "User already exists"}), 400

    added = db_utils.add_user(first_name, last_name, email, password)

    if not added:
        return jsonify({"error": "Failed to register user"}), 500

    return jsonify({"message": "User registered successfully"}), 201


@app.route("/api/login", methods=["POST"])
def login():

    data = request.json
    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        return jsonify({"error": "Email and password are required"}), 400

    user = db_utils.get_user_by_email(email)

    if not user or user["password"] != password:
        return jsonify({"error": "Invalid email or password"}), 401

    payload = {
        "id": user["id"],
        "role": user["role"]
    }

    token = jwt_utils.sign_jwt(payload, JWT_SECRET)

    return jsonify({"token": token}), 200


@app.route("/api/profile", methods=["GET", "POST"])
@authenticate()
def profile():
    user = request.user
    if not user:
        return jsonify({"error": "User not found"}), 404

    if request.method == "GET":

        return jsonify({
            "full_name": str(user).format(user=user),
            "id": user.id,
            "email": user.email,
            "is_admin": user.role == "admin",
            "bio": user.bio if hasattr(user, 'bio') else None,
            "created_at": user.created_at
        }), 200

    elif request.method == "POST":

        data = request.json
        bio = data.get("bio", "")

        if not isinstance(bio, str) or len(bio) > 500 or len(bio) < 20:
            return jsonify({"error": "Invalid bio"}), 400

        db_utils.update_user_profile(user.id, bio)

        return jsonify({
            "success": True,
            "message": "Profile updated successfully",
        }), 200


@app.route("/api/create_article", methods=["POST"])
@authenticate()
def create_article():
    data = request.json
    title = data.get("title")
    content = data.get("content")

    if not title or not content:
        return jsonify({"error": "Title and content are required"}), 400

    user = request.user
    if not user:
        return jsonify({"error": "User not found"}), 404

    article_id = db_utils.create_article(title, content, user.id)

    if not article_id:
        return jsonify({"error": "Failed to create article"}), 500

    return jsonify({"message": "Article created successfully", "article_id": article_id}), 201


@app.route("/api/my_articles", methods=["GET"])
@authenticate()
def my_articles():
    user = request.user
    if not user:
        return jsonify({"error": "User not found"}), 404

    articles = db_utils.get_articles_by_author(user.id)

    if articles is None:
        return jsonify({"error": "No articles found"}), 404

    return jsonify({"articles": articles}), 200


@app.route("/api/admin/flag", methods=["GET"])
@authenticate(admin_required=True)
def flag():
    has_luck = random_int(1000) == 0 # Maybe you will need some luck today :)

    if has_luck:

        FLAG = sensitive.FlagSystem(decryption_key=DECRYPTION_KEY).get_flag()
    else:
        FLAG = generate_fake_flag()

    return jsonify({"flag": FLAG, "has_luck": has_luck}), 200


@app.route("/api/admin/create_admin_article", methods=["POST"])
@authenticate(admin_required=True)
def create_admin_article():
    data = request.json
    title = data.get("title")
    content = data.get("content")

    if not title or not content:
        return jsonify({"error": "Title and content are required"}), 400

    user = request.user
    if not user:
        return jsonify({"error": "User not found"}), 404

    article_id = db_utils.create_article(
        title, content, user.id, admin_only=True)

    if not article_id:
        return jsonify({"error": "Failed to create article"}), 500

    return jsonify({"message": "Admin article created successfully", "article_id": article_id}), 201


@app.route("/api/admin/articles", methods=["GET"])
@authenticate(admin_required=True)
def get_all_articles():
    articles = db_utils.get_all_articles()

    if articles is None:
        return jsonify({"error": "No articles found"}), 404

    return jsonify({"articles": articles}), 200


@app.route("/api/admin/users", methods=["GET"])
@authenticate(admin_required=True)
def get_all_users():
    users = db_utils.get_all_users_contacts()

    if users is None:
        return jsonify({"error": "No users found"}), 404

    return jsonify({"users": users}), 200


@app.errorhandler(404)
def not_found(error):
    return jsonify({"error": "Not found"}), 404


@app.errorhandler(500)
def internal_error(error):

    print(f"Internal server error: {error}")
    return jsonify({"error": "Internal server error"}), 500


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=PORT)
