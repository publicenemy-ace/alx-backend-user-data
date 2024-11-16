#!/usr/bin/env python3
""" Module for session views
"""
from os import getenv
from flask import abort, jsonify, request, make_response
from api.v1.views import app_views
from models.user import User


@app_views.route('/auth_session/login',
                 methods=['POST'], strict_slashes=False)
def login():
    """
    POST /api/v1/auth_session/login:
    Handles session authentication
    """
    email = request.form.get('email')
    password = request.form.get('password')

    # Check if email is provided
    if email is None or email == "":
        return jsonify({"error": "email missing"}), 400

    # Check if password is provided
    if password is None or password == "":
        return jsonify({"error": "password missing"}), 400

    # Retrieve the User instance based on email
    users = User.search({'email': email})
    if len(users) == 0:
        return jsonify({"error": "no user found for this email"}), 404

    user = users[0]

    # Check if password is valid
    if not user.is_valid_password(password):
        return jsonify({"error": "wrong password"}), 401

    from api.v1.app import auth
    # Create a Session ID for the user and save it
    session_id = auth.create_session(user.id)

    # Generate the response with user's data
    response = jsonify(user.to_json())

    # Set the cookie in the response
    session_name = getenv('SESSION_NAME')
    response.set_cookie(session_name, session_id)

    return response


@app_views.route('/auth_session/logout', methods=['DELETE'],
                 strict_slashes=False)
def logout():
    """Handles the user logout"""
    from api.v1.app import auth
    # Attempt to destroy the session using auth.destroy_session
    if not auth.destroy_session(request):
        # If destroy_session returns False, abort with a 404 error
        abort(404)

    # If successful, return an empty JSON dictionary with a 200 status code
    return jsonify({}), 200
