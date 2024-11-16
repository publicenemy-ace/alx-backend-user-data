#!/usr/bin/env python3
"""
Route module for the API
"""
from os import getenv
from api.v1.views import app_views
from flask import Flask, jsonify, abort, request
from flask_cors import (CORS, cross_origin)
from api.v1.auth.auth import Auth
from api.v1.auth.basic_auth import BasicAuth
from api.v1.auth.session_auth import SessionAuth
from api.v1.auth.session_exp_auth import SessionExpAuth


app = Flask(__name__)
app.register_blueprint(app_views)
CORS(app, resources={r"/api/v1/*": {"origins": "*"}})

auth = None
# Load auth type from environment variable
auth_env = getenv('AUTH_TYPE')

# Initialize the auth instance based on the environment variable
if auth_env:
    auth_env = auth_env.lower()
    if auth_env == 'auth':
        auth = Auth()
    elif auth_env == 'basic_auth':
        auth = BasicAuth()
    elif auth_env == 'session_auth':
        auth = SessionAuth()
    elif auth_env == 'session_exp_auth':
        auth = SessionExpAuth()


@app.before_request
def before_request():
    """Handles request before any other"""
    if auth is None:
        return

    # Excluded paths that do not require authentication
    excluded_paths = ['/api/v1/status/',
                      '/api/v1/unauthorized/',
                      '/api/v1/forbidden/',
                      '/api/v1/auth_session/login/']

    # Check if the path requires authentication
    if not auth.require_auth(request.path, excluded_paths):
        return

    # Check for valid authorization or session
    if auth.authorization_header(request) is None \
            and auth.session_cookie(request) is None:
        abort(401)

    # Check for current user (which will validate the session or token)
    if auth.current_user(request) is None:
        abort(403)

    # If user is authenticated, set request current user
    request.current_user = auth.current_user(request)


@app.errorhandler(404)
def not_found(error) -> str:
    """ Not found handler
    """
    return jsonify({"error": "Not found"}), 404


@app.errorhandler(401)
def unauthorized(error) -> str:
    """Unauthorized request"""
    return jsonify({"error": "Unauthorized"}), 401


@app.errorhandler(403)
def forbidden(error) -> str:
    """Forbidden request"""
    return jsonify({"error": "Forbidden"}), 403


if __name__ == "__main__":
    host = getenv("API_HOST", "0.0.0.0")
    port = getenv("API_PORT", "5000")
    app.run(host=host, port=port)
