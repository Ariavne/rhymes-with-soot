"""Blueprints: one public page, one login-protected page. Replace with your own."""
from flask import Blueprint, render_template

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
