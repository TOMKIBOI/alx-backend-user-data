#!/usr/bin/env python3
"""app module"""
from flask import Flask, jsonify, request, abort, redirect
from auth import Auth
from typing import Dict, Union, Tuple


app = Flask(__name__)
AUTH = Auth()


@app.route("/", methods=["GET"])
def welcome() -> str:
    """Returns a JSON payload with a welcome message"""
    return jsonify({"message": "Bienvenue"})


@app.route("/users", methods=["POST"])
def register_user() -> Union[Dict[str, str], Tuple[Dict[str, str], int]]:
    """Registers a new user"""
    try:
        email = request.form.get("email")
        password = request.form.get("password")
        AUTH.register_user(email, password)
        return jsonify({"email": email, "message": "user created"})
    except ValueError:
        return jsonify({"message": "email already registered"}), 400


@app.route("/sessions", methods=["POST"])
def login() -> Union[Dict[str, str], Tuple[Dict[str, str], int]]:
    """Logs in a user"""
    try:
        email = request.form.get("email")
        password = request.form.get("password")
        if not AUTH.valid_login(email, password):
            abort(401)
        session_id = AUTH.create_session(email)
        response = jsonify({"email": email, "message": "logged in"})
        response.set_cookie("session_id", session_id)
        return response
    except ValueError:
        abort(401)


@app.route("/sessions", methods=["DELETE"])
def logout() -> Union[Dict[str, str], Tuple[Dict[str, str], int]]:
    """Logs out a user"""
    session_id = request.cookies.get("session_id", None)
    if session_id is None:
        abort(403)
    user = AUTH.get_user_from_session_id(session_id)
    if user is None:
        abort(403)
    AUTH.destroy_session(user.id)

    return redirect("/")


@app.route("/profile", methods=["GET"])
def profile() -> Union[Dict[str, str], Tuple[Dict[str, str], int]]:
    """Returns the user profile"""
    session_id = request.cookies.get("session_id", None)
    if session_id is None:
        abort(403)
    user = AUTH.get_user_from_session_id(session_id)
    if user is None:
        abort(403)
    return jsonify({"email": user.email}), 200


@app.route("/reset_password", methods=["POST"])
def get_reset_password_token(
) -> Union[Dict[str, str], Tuple[Dict[str, str], int]]:
    """Generates a reset password token"""
    try:
        email = request.form.get("email")
    except ValueError:
        abort(403)
    try:
        token = AUTH.get_reset_password_token(email)
    except ValueError:
        abort(403)


@app.route("/reset_password", methods=["PUT"])
def update_password() -> Union[Dict[str, str], Tuple[Dict[str, str], int]]:
    """Updates the user password"""
    try:
        email = request.form.get("email")
        reset_token = request.form.get("reset_token")
        new_password = request.form.get("new_password")
        AUTH.update_password(reset_token, new_password)
        return jsonify({"email": email, "message": "Password updated"}), 200
    except ValueError:
        abort(403)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
