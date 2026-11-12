"""Blueprints: one public page, one login-protected page. Replace with your own."""
from flask import Blueprint, render_template

from rhymes_with_soot.access import requires
from rhymes_with_soot.auth.session import login_required, get_current_user

site_template_bp = Blueprint("site_template", __name__)


@site_template_bp.route("/")
def index():
    return render_template("index.html")


@site_template_bp.route("/dashboard")
@login_required
def dashboard():
    # get_current_user() is cached per request; safe to call anywhere in a view.
    return render_template("dashboard.html", username=get_current_user().username)


@site_template_bp.route("/api/feature", methods=["POST"])
@login_required
@requires("area.feature")
def feature():
    # Example of a gated route: 403 for authenticated users without the
    # access. Hiding the UI control does not protect this route.
    return {"ok": True}
