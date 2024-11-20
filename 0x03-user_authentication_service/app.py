#!/usr/bin/env python3
""" A simple flask app"""
from flask import (jsonify, Flask, request,
                   abort, make_response, redirect, url_for)
from auth import Auth


app = Flask(__name__)
AUTH = Auth()


@app.route("/", methods=['GET'], strict_slashes=False)
def index():
    """return the index page"""
    return jsonify({"message": "Bienvenue"})


@app.route("/users", methods=['POST'], strict_slashes=False)
def users():
    """creates a user from the post request"""
    email = request.form.get('email')

    # Validation
    if not email:
        return jsonify({"error": "email is required!"}), 400
    password = request.form.get('password')
    if not password:
        return jsonify({"error": "password is required"}), 400

    try:
        user = AUTH.register_user(email=email, password=password)
        return jsonify({"email": user.email, "message": "user created"})
    except ValueError:
        return jsonify({"message": "email already registered"}), 400


@app.route("/sessions", methods=['POST'], strict_slashes=False)
def login():
    """responds to the sessions route
    """
    email = request.form.get('email')
    # Validation
    if not email:
        abort(401)
    password = request.form.get('password')
    if not password:
        abort(401)

    if AUTH.valid_login(email, password):
        user_session = AUTH.create_session(email)
        resp = jsonify({"email": email, "message": "logged in"})
        resp.set_cookie("session_id", user_session)
        return resp
    abort(401)


@app.route("/sessions", methods=['DELETE'], strict_slashes=False)
def logout():
    """Logs out a user via session"""
    user_session = request.cookies.get('session_id')

    if user_session:
        user = AUTH.get_user_from_session_id(user_session)
        if user:
            # Destroy the session
            AUTH.destroy_session(user.id)
            # Redirect to the home page or the main page
            return redirect(url_for('index'))
    # If session_id is not provided or user is not found, respond with 403
    abort(403)


@app.route("/reset_password", methods=['POST'], strict_slashes=False)
def get_reset_password_token():
    """Gets reset password token for user
    expects the email field from the user
    """
    # Extract email from form data
    req_email = request.form.get('email')

    if not req_email:
        # If email is not provided in the form data
        return jsonify({"error": "email is required"}), 400

    try:
        # Find the user by email using public methods of AUTH
        user = AUTH.get_user_by(email=req_email)

        if not user:
            # If no user is found with the provided email, respond with 403
            return abort(403)

        # Generate the reset password token
        token = AUTH.get_reset_password_token(req_email)
        # Return the response with the reset token and user's email
        return jsonify({"email": req_email, "reset_token": token}), 200
    except Exception as e:
        return abort(403)


@app.route("/profile", methods=['GET'], strict_slashes=False)
def profile():
    """Handles user profile"""
    user_session = request.cookies.get('session_id')
    if user_session:
        user = AUTH.get_user_from_session_id(user_session)
        if user:
            return jsonify({"email": user.email}), 200
        abort(403)
    abort(403)


@app.route("/reset_password", methods=['PUT'], strict_slashes=False)
def update_password():
    """handles the reset_password endpoint
    """
    email = request.form.get('email')
    if not email:
        # If email is not provided in the form data
        return jsonify({"error": "email is required"}), 400

    reset_token = request.form.get('reset_token')
    if not reset_token:
        return jsonify({"error": "reset_token is required"}), 400
    new_password = request.form.get('new_password')
    if not new_password:
        return jsonify({"error": "new_password is required"}), 400

    # Check if the reset token is valid and update the password
    try:
        # First, check if the user exists with the given email
        user = AUTH.get_user_by(email=email)
        if user is None:
            return jsonify({"error": "Invalid email"}), 400

        # Attempt to update the password using the reset token
        AUTH.update_password(reset_token, new_password)

        # If successful, return a 200 status with a success message
        return jsonify({"email": email, "message": "Password updated"}), 200

    except ValueError:
        # If the token is invalid or the password update fails,
        # return a 403 error
        return jsonify({"error": "Invalid reset token"}), 403


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
