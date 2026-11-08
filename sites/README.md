# sites/

Where site packages live. A **site** is a Python package that plugs into
`rhymes_with_soot`; it provides its own config, blueprints, models, templates,
and static assets, and builds its app with `rhymes_with_soot.create_app`.

Start from the [`site_template/`](../site_template/) copy source at the repo
root: duplicate it here, rename, and fill in.

Each site is a self-contained subdirectory here, e.g.:

```
sites/
└── mysite/
    ├── __init__.py      # calls create_app(...)
    ├── config.py        # BaseConfig subclass
    ├── routes.py        # blueprints
    ├── models.py        # domain models on rhymes_with_soot's Base
    ├── templates/       # overrides framework templates by filename
    ├── static/          # site CSS/JS/images (shadows framework by filename)
    └── users.json       # provisioning file (gitignored, never committed)
```

Brand the site per-package: override `base.html` and add the assets under the
site's own `static/`.
