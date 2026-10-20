#!/usr/bin/python
# Security Incident Detection and Response Management System - Flask backend
# Services 1-3 (Users and Identity, Asset Management, Incident Management): Maya Zeaiter
# Services 4-6 (Threat Intelligence, Security Audit Logging, Security Reports): Zeinab Harb
# Services 7-9 (Vulnerability Management, Notifications and Alerts, Security Playbooks): Omar Obeid
import os
import sqlite3

from flask import Flask, jsonify
from flask_cors import CORS
from werkzeug.exceptions import HTTPException

from assets_service import assets_bp
from common import STUDENT_NAME, ApiError, error_body
from database import init_db
from incidents_service import incidents_bp
from logs_service import logs_bp
from notifications_service import notifications_bp
from playbooks_service import playbooks_bp
from reports_service import reports_bp
from threats_service import threats_bp
from users_service import users_bp
from vulnerabilities_service import vulnerabilities_bp


def create_app():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-secret-change-me")
    app.json.sort_keys = False
    CORS(app)

    app.register_blueprint(users_bp)
    app.register_blueprint(assets_bp)
    app.register_blueprint(incidents_bp)
    app.register_blueprint(threats_bp)  # Zeinab Harb
    app.register_blueprint(logs_bp)  # Zeinab Harb
    app.register_blueprint(reports_bp)  # Zeinab Harb
    app.register_blueprint(vulnerabilities_bp)  # Omar Obeid
    app.register_blueprint(notifications_bp)  # Omar Obeid
    app.register_blueprint(playbooks_bp)  # Omar Obeid

    @app.errorhandler(ApiError)
    def handle_api_error(e):
        return jsonify(error_body(e.message, e.errors)), e.status_code

    @app.errorhandler(sqlite3.IntegrityError)
    def handle_integrity_error(e):
        return jsonify(error_body("Operation violates a database constraint "
                                  "(the record is still referenced by other records)", {"detail": str(e)})), 409

    @app.errorhandler(HTTPException)
    def handle_http_error(e):
        return jsonify(error_body(e.description)), e.code

    @app.errorhandler(Exception)
    def handle_unexpected(e):
        app.logger.exception(e)
        return jsonify(error_body("Internal server error")), 500

    # Maya Zeaiter
    @app.route("/", methods=["GET"])
    def health():
        return jsonify({"status": "success", "message": "Security Incident Response backend is running",
                        "developer": STUDENT_NAME})

    return app


init_db()
app = create_app()

if __name__ == "__main__":
    app.run(debug=True, port=5050)  # 5000 is taken by macOS AirPlay Receiver
