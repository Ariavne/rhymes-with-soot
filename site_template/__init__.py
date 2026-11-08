"""Site template: copy this directory to sites/<name>/ and rename.

This is a copy source, not a live site. Duplicate it, then rename every
`site_template` reference to your site name (package, config class, blueprint,
ENV_PREFIX, url_for targets).

What each file is for:

- config.py    -> BaseConfig subclass (env-var prefix)
- models.py    -> domain models on the shared Base
- routes.py    -> your blueprints (public + login-protected)
- templates/   -> overrides framework templates by filename (base.html, index.html)
- static/      -> site CSS (shadows framework assets by filename)
- users.json   -> provisioning file (gitignored; see users.json.example)
"""
from rhymes_with_soot import create_app

from site_template.config import SiteTemplateConfig
from site_template.routes import site_template_bp


def create():
    app = create_app(SiteTemplateConfig, blueprints=[site_template_bp])

    from rhymes_with_soot.provisioning import provision_users
    provision_users(app)

    return app


app = create()
