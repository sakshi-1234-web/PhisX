from flask import Flask, request, jsonify, send_from_directory
from analyzer.threat_engine import analyze_email
import os


# =========================================================
# FLASK APP CONFIGURATION
# =========================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FRONTEND_DIR = os.path.join(BASE_DIR, "frontend")

app = Flask(__name__, static_folder=FRONTEND_DIR)


# =========================================================
# FRONTEND ROUTES
# =========================================================

@app.route("/")
def home():
    """
    Serve the main NEON GUARD frontend.
    """
    return send_from_directory(FRONTEND_DIR, "index.html")


@app.route("/style.css")
def serve_css():
    """
    Serve the frontend stylesheet.
    """
    return send_from_directory(FRONTEND_DIR, "style.css")


@app.route("/script.js")
def serve_javascript():
    """
    Serve the frontend JavaScript.
    """
    return send_from_directory(FRONTEND_DIR, "script.js")


# =========================================================
# EMAIL ANALYSIS API
# =========================================================

@app.route("/api/analyze", methods=["POST"])
def analyze():
    """
    Analyze an email for phishing and threat indicators.

    Expected JSON format:

    {
        "sender": "support@example.com",
        "subject": "Urgent account verification",
        "body": "Your account will be suspended..."
    }
    """

    try:

        # -------------------------------------------------
        # Check that JSON was sent
        # -------------------------------------------------

        if not request.is_json:
            return jsonify({
                "success": False,
                "error": "Invalid request format.",
                "message": "Please send the email data as JSON."
            }), 400


        data = request.get_json(silent=True)

        if data is None:
            return jsonify({
                "success": False,
                "error": "Invalid JSON.",
                "message": "The request body could not be read."
            }), 400


        # -------------------------------------------------
        # Extract fields
        # -------------------------------------------------

        sender = str(data.get("sender", "")).strip()
        subject = str(data.get("subject", "")).strip()
        body = str(data.get("body", "")).strip()


        # -------------------------------------------------
        # Validate required fields
        # -------------------------------------------------

        if not sender:
            return jsonify({
                "success": False,
                "error": "Missing sender.",
                "message": "Please provide the sender email address."
            }), 400


        if not subject:
            return jsonify({
                "success": False,
                "error": "Missing subject.",
                "message": "Please provide the email subject."
            }), 400


        if not body:
            return jsonify({
                "success": False,
                "error": "Missing email body.",
                "message": "Please provide an email body before starting the scan."
            }), 400


        # -------------------------------------------------
        # Prevent excessively large requests
        # -------------------------------------------------

        MAX_BODY_LENGTH = 100_000

        if len(body) > MAX_BODY_LENGTH:
            return jsonify({
                "success": False,
                "error": "Email body too large.",
                "message": "The email body exceeds the maximum allowed size."
            }), 413


        # -------------------------------------------------
        # Run threat analysis
        # -------------------------------------------------

        result = analyze_email(
            sender=sender,
            subject=subject,
            body=body
        )


        # -------------------------------------------------
        # Return successful result
        # -------------------------------------------------

        return jsonify({
            "success": True,
            **result
        }), 200


    except Exception as error:

        # Log the real error in the terminal for debugging
        app.logger.exception(
            "Unexpected error while analyzing email: %s",
            error
        )

        # Do not expose internal traceback details to users
        return jsonify({
            "success": False,
            "error": "Analysis failed.",
            "message": "An unexpected error occurred while analyzing the email."
        }), 500


# =========================================================
# 404 ERROR HANDLER
# =========================================================

@app.errorhandler(404)
def not_found(error):

    return jsonify({
        "success": False,
        "error": "Not found.",
        "message": "The requested resource does not exist."
    }), 404


# =========================================================
# 405 ERROR HANDLER
# =========================================================

@app.errorhandler(405)
def method_not_allowed(error):

    return jsonify({
        "success": False,
        "error": "Method not allowed.",
        "message": "This endpoint does not support the requested HTTP method."
    }), 405


# =========================================================
# START APPLICATION
# =========================================================

if __name__ == "__main__":

    print("=" * 55)
    print(" NEON GUARD - AI POWERED EMAIL THREAT DETECTOR")
    print("=" * 55)
    print(" Server running at:")
    print(" http://127.0.0.1:5000")
    print("=" * 55)

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )