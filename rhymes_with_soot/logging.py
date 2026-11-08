"""Logging: 4xx/5xx responses logged as one line with client IP.
Sites reuse the 'rhymes_with_soot' logger."""
import logging

from flask import request

LOGGED_STATUS_CODES = {400, 401, 403, 404, 410, 413, 429}


def register_logging(app):
    logger = logging.getLogger("rhymes_with_soot")
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(
            logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
        )
        logger.addHandler(handler)
    logger.setLevel(logging.INFO)

    @app.after_request
    def _log_errors(response):
        code = response.status_code
        if code in LOGGED_STATUS_CODES or code >= 500:
            logger.warning(
                '%s "%s %s" → %d',
                request.remote_addr,
                request.method,
                request.path,
                code,
            )
        return response
