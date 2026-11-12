"""Error handlers. A site can override a page by dropping a same-named template
in its ``templates/`` directory."""
from flask import render_template, request, jsonify


def _wants_json():
    # Only JSON when the client explicitly prefers it.
    return request.accept_mimetypes.best == "application/json" or request.is_json


def register_error_handlers(app):
    # 429 is not handled here; rate limiting is enforced upstream.
    @app.errorhandler(400)
    def bad_request(e):
        if _wants_json():
            return jsonify({"error": "Bad request"}), 400
        return render_template("errors/400.html"), 400

    @app.errorhandler(401)
    def unauthorized(e):
        if _wants_json():
            return jsonify({"error": "Unauthorized"}), 401
        return render_template("errors/401.html"), 401

    @app.errorhandler(403)
    def forbidden(e):
        if _wants_json():
            return jsonify({"error": "Forbidden"}), 403
        return render_template("errors/403.html"), 403

    @app.errorhandler(404)
    def not_found(e):
        if _wants_json():
            return jsonify({"error": "Not found"}), 404
        return render_template("errors/404.html"), 404

    @app.errorhandler(405)
    def method_not_allowed(e):
        if _wants_json():
            return jsonify({"error": "Method not allowed"}), 405
        return render_template("errors/405.html"), 405

    @app.errorhandler(410)
    def gone(e):
        if _wants_json():
            return jsonify({"error": "Gone"}), 410
        return render_template("errors/410.html"), 410

    @app.errorhandler(413)
    def file_too_large(e):
        custom = e.description != e.__class__.description
        if _wants_json():
            return jsonify(
                {"error": e.description if custom else "File too large"}
            ), 413
        return render_template(
            "errors/413.html",
            detail=e.description if custom else None,
        ), 413

    @app.errorhandler(416)
    def range_not_satisfiable(e):
        if _wants_json():
            return jsonify({"error": "Range not satisfiable"}), 416
        return render_template("errors/416.html"), 416

    @app.errorhandler(418)
    def im_a_teapot(e):
        if _wants_json():
            return jsonify({"error": "I'm a teapot"}), 418
        return render_template("errors/418.html"), 418

    @app.errorhandler(500)
    def server_error(e):
        if _wants_json():
            return jsonify({"error": "Internal server error"}), 500
        return render_template("errors/500.html"), 500
