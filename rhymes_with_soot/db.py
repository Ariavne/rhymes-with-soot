"""SQLite engine + scoped session. WAL enabled."""
import logging
import os

from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker, scoped_session

logger = logging.getLogger("rhymes_with_soot")

engine = None
Session = None

# Migration steps: callables taking the engine.
_migration_steps = []


def _set_sqlite_pragmas(dbapi_connection, connection_record):
    cursor = dbapi_connection.cursor()
    try:
        cursor.execute("PRAGMA journal_mode=WAL;")
        cursor.execute("PRAGMA synchronous=NORMAL;")
        cursor.execute("PRAGMA busy_timeout=30000;")
    finally:
        cursor.close()


def init_db(app):
    """Create the engine, session, and tables.
    Call after blueprints are registered so site models are on Base."""
    global engine, Session

    db_dir = os.path.dirname(app.config["DB_PATH"])
    if db_dir:
        os.makedirs(db_dir, exist_ok=True)

    engine = create_engine(
        f"sqlite:///{app.config['DB_PATH']}",
        connect_args={"check_same_thread": False, "timeout": 30},
    )
    event.listen(engine, "connect", _set_sqlite_pragmas)
    Session = scoped_session(sessionmaker(bind=engine))

    from rhymes_with_soot.models import Base
    Base.metadata.create_all(engine)
    run_migrations(engine)

    @app.teardown_appcontext
    def shutdown_session(exception=None):
        Session.remove()


def register_migration(step):
    """Register an idempotent migration step for this process.

    Steps run in registration order, after create_all, at every startup
    (init_db). They must be safe to re-run: check for the change before
    making it (has_table / inspect the columns). Register at import time —
    the site's models import is the natural place — because create_app runs
    the migrations as soon as it is called.
    """
    _migration_steps.append(step)


def run_migrations(engine):
    """Run every registered migration step against the engine.

    A step that raises is logged and skipped so one bad migration cannot
    take the site down; the rest of the steps still run.
    """
    for step in _migration_steps:
        try:
            step(engine)
        except Exception:
            logger.exception("Migration step %s failed", step.__name__)


def has_table(engine, table):
    """True when the table exists; migration steps use this to guard
    against a database where the table was never created."""
    from sqlalchemy import inspect

    return inspect(engine).has_table(table)


def _ensure_user_role_column(engine):
    """create_all never alters existing tables, so add the column once.
    Existing users default to 'user'."""
    from sqlalchemy import inspect, text

    if not has_table(engine, "users"):
        return
    cols = {c["name"] for c in inspect(engine).get_columns("users")}
    if "role" in cols:
        return
    with engine.begin() as conn:
        conn.execute(text(
            "ALTER TABLE users ADD COLUMN role VARCHAR(16) "
            "NOT NULL DEFAULT 'user'"
        ))
    logger.info("Added users.role column to existing database")


register_migration(_ensure_user_role_column)


def get_session():
    return Session()
