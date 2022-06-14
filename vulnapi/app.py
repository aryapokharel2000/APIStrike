"""
VulnAPI Testbed - Deliberately Misconfigured RESTful API
=========================================================
Controlled target environment for APIStrike evaluation.
All data is entirely synthetic. No real user data is stored or processed.

INTENTIONAL VULNERABILITIES (research purposes only):
    VULN-01  CORS origin reflection without allowlist validation
    VULN-02  Verbose server headers disclosing framework version strings
    VULN-03  BOLA/IDOR on /api/users/<id>    (no authorization check)
    VULN-04  BOLA/IDOR on /api/products/<id> (no authorization check)
    VULN-05  Unauthenticated administrative endpoint at /api/admin/users

ETHICAL DECLARATION:
    This application is designed exclusively for localhost security research.
    It must never be deployed on a public network interface.
    All resource identifiers and personal data fields are fabricated.

USAGE:
    pip install flask==2.3.2
    python app.py

DOCKER:
    docker compose up --build
"""

import os
from flask import Flask, jsonify, request

app = Flask(__name__)


# ---------------------------------------------------------------------------
# Synthetic data store - all entries are fabricated for research purposes
# ---------------------------------------------------------------------------

USERS: dict = {
    1: {
        "id": 1, "username": "alice", "email": "alice@vulnapi.local",
        "role": "admin", "api_key": "sk-test-ALICE001AAAA",
    },
    2: {
        "id": 2, "username": "bob", "email": "bob@vulnapi.local",
        "role": "user", "api_key": "sk-test-BOB002BBBB",
    },
    3: {
        "id": 3, "username": "charlie", "email": "charlie@vulnapi.local",
        "role": "user", "api_key": "sk-test-CHARLIE003",
    },
    4: {
        "id": 4, "username": "diana", "email": "diana@vulnapi.local",
        "role": "moderator", "api_key": "sk-test-DIANA004DD",
    },
    5: {
        "id": 5, "username": "eve", "email": "eve@vulnapi.local",
        "role": "user", "api_key": "sk-test-EVE005EEEE",
    },
}

PRODUCTS: dict = {
    1: {"id": 1, "name": "Security Widget Alpha",  "price": 49.99,  "stock": 200},
    2: {"id": 2, "name": "API Gateway Pro",         "price": 199.99, "stock": 50},
    3: {"id": 3, "name": "Auth Module Lite",        "price": 29.99,  "stock": 500},
    4: {"id": 4, "name": "CORS Configurator",       "price": 9.99,   "stock": 1000},
}


# ---------------------------------------------------------------------------
# VULN-01 + VULN-02: Applied globally via after_request hook
# ---------------------------------------------------------------------------

@app.after_request
def apply_deliberate_misconfigurations(response):
    """
    VULN-01 (CORS): Reflects any incoming Origin header value without
    validating it against a permitted-origins allowlist.

    VULN-02 (Verbose Headers): Injects explicit version strings into
    Server, X-Powered-By, and X-Runtime response headers.
    """
    # VULN-01: Origin reflection with credentials enabled
    incoming_origin = request.headers.get("Origin")
    if incoming_origin:
        response.headers["Access-Control-Allow-Origin"] = incoming_origin
        response.headers["Access-Control-Allow-Credentials"] = "true"
    else:
        response.headers["Access-Control-Allow-Origin"] = "*"

    response.headers["Access-Control-Allow-Methods"] = (
        "GET, POST, PUT, DELETE, OPTIONS"
    )
    response.headers["Access-Control-Allow-Headers"] = (
        "Content-Type, Authorization, X-Requested-With"
    )

    # VULN-02: Verbose server identification headers
    response.headers["Server"] = "Werkzeug/2.3.0 Python/3.10.12"
    response.headers["X-Powered-By"] = "Flask/2.3.2"
    response.headers["X-Runtime"] = "CPython"

    return response


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.route("/api/health", methods=["GET", "OPTIONS"])
def health_check():
    """Public health check. No authentication required by design."""
    return jsonify({
        "status": "healthy",
        "service": "VulnAPI Testbed",
        "version": "1.0.0",
    }), 200


@app.route("/api/users/<int:user_id>", methods=["GET", "OPTIONS"])
def get_user(user_id: int):
    """
    VULN-03 (BOLA/IDOR): Returns any user object identified by user_id
    without verifying that the requesting entity owns or is permitted
    to access that specific object.
    """
    user = USERS.get(user_id)
    if user is None:
        return jsonify({"error": "User not found"}), 404
    return jsonify(user), 200


@app.route("/api/users", methods=["GET"])
def list_users():
    """Returns the full user list. No authentication required."""
    return jsonify({"count": len(USERS), "users": list(USERS.values())}), 200


@app.route("/api/products/<int:product_id>", methods=["GET", "OPTIONS"])
def get_product(product_id: int):
    """
    VULN-04 (BOLA/IDOR): Returns any product object by ID without any
    ownership or role-based access control verification.
    """
    product = PRODUCTS.get(product_id)
    if product is None:
        return jsonify({"error": "Product not found"}), 404
    return jsonify(product), 200


@app.route("/api/admin/users", methods=["GET"])
def admin_users():
    """
    VULN-05: Administrative endpoint with no authentication or
    authorization guard. Returns the full user list including API keys.
    """
    return jsonify({
        "total_users": len(USERS),
        "users": list(USERS.values()),
    }), 200


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    host = os.environ.get("VULNAPI_HOST", "127.0.0.1")
    port = int(os.environ.get("VULNAPI_PORT", "5000"))
    print(f"[VulnAPI] Starting deliberately vulnerable testbed on {host}:{port}.")
    print("[VulnAPI] FOR AUTHORIZED RESEARCH USE ONLY - DO NOT EXPOSE PUBLICLY.")
    app.run(host=host, port=port, debug=False)
