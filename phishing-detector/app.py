"""
app.py - Main Flask application for the Phishing URL Detection System.

Routes:
    GET  /            - Home page with URL input form
    POST /analyze     - Run phishing analysis on a submitted URL
    GET  /history     - Scan history dashboard
    GET  /awareness   - Cybersecurity awareness content
    POST /clear       - Clear all scan history
    POST /delete/<id> - Delete a single scan record
    GET  /api/stats   - JSON endpoint for dashboard statistics
    GET  /export/csv  - Download all scan history as a CSV file
"""

import csv
import io
import os
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, Response

from analyzer import analyze_url
from database import init_db, save_scan, get_all_scans, get_scan_stats, delete_scan, clear_all_scans

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "phishing-detector-dev-key-2024")

# Initialise the SQLite database on startup
with app.app_context():
    init_db()


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    """Render the home page with the URL input form."""
    stats = get_scan_stats()
    return render_template("index.html", stats=stats)


@app.route("/analyze", methods=["POST"])
def analyze():
    """
    Accept a URL from the form, run the analysis engine,
    persist the result, and render the results page.
    """
    url = request.form.get("url", "").strip()

    # --- Input validation ---
    if not url:
        flash("Please enter a URL to analyze.", "warning")
        return redirect(url_for("index"))

    if len(url) > 2048:
        flash("URL is too long (maximum 2048 characters).", "danger")
        return redirect(url_for("index"))

    # Block obviously non-URL inputs
    if " " in url and not url.startswith(("http://", "https://")):
        flash("Invalid URL format. Please enter a valid web address.", "danger")
        return redirect(url_for("index"))

    # --- Run analysis ---
    result = analyze_url(url)

    # --- Persist to database ---
    save_scan(
        url=result["url"],
        risk_score=result["risk_score"],
        status=result["status"],
        reasons=result["reasons"],
    )

    return render_template("result.html", result=result)


@app.route("/history")
def history():
    """Show all previously scanned URLs in a sortable table."""
    scans = get_all_scans()
    stats = get_scan_stats()
    return render_template("history.html", scans=scans, stats=stats)


@app.route("/awareness")
def awareness():
    """Render the cybersecurity awareness educational page."""
    return render_template("awareness.html")


@app.route("/clear", methods=["POST"])
def clear_history():
    """Delete every record from the scan history table."""
    count = clear_all_scans()
    flash(f"Scan history cleared — {count} record(s) deleted.", "info")
    return redirect(url_for("history"))


@app.route("/delete/<int:scan_id>", methods=["POST"])
def delete_record(scan_id):
    """Delete a single scan record by its database id."""
    deleted = delete_scan(scan_id)
    if deleted:
        flash("Scan record deleted.", "info")
    else:
        flash("Record not found.", "warning")
    return redirect(url_for("history"))


@app.route("/export/csv")
def export_csv():
    """
    Stream all scan history records as a downloadable CSV file.
    Columns: URL, Risk Score, Classification, Scan Date and Time.
    """
    scans = get_all_scans()

    output = io.StringIO()
    writer = csv.writer(output)

    # Header row
    writer.writerow(["URL", "Risk Score", "Classification", "Scan Date and Time"])

    # Data rows
    for scan in scans:
        writer.writerow([
            scan["url"],
            scan["risk_score"],
            scan["status"],
            scan["scanned_at"],
        ])

    csv_content = output.getvalue()
    output.close()

    return Response(
        csv_content,
        mimetype="text/csv",
        headers={
            "Content-Disposition": "attachment; filename=phishguard_scan_history.csv",
            "Content-Type": "text/csv; charset=utf-8",
        },
    )


@app.route("/api/stats")
def api_stats():
    """Return scan statistics as JSON (useful for front-end charts)."""
    stats = get_scan_stats()
    return jsonify(stats)


# ---------------------------------------------------------------------------
# Error handlers
# ---------------------------------------------------------------------------

@app.errorhandler(404)
def not_found(e):
    return render_template("404.html"), 404


@app.errorhandler(500)
def server_error(e):
    return render_template("500.html"), 500


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    debug = os.environ.get("FLASK_ENV", "production") != "production"
    app.run(host="0.0.0.0", port=port, debug=debug)
