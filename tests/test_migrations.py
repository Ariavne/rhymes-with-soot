"""Migration registry: ordering, failure isolation, and the has_table helper."""
import pytest
from sqlalchemy import create_engine, text

from rhymes_with_soot import db as db_mod


@pytest.fixture
def steps():
    """Isolate the process-global migration list for the duration of a test."""
    saved = list(db_mod._migration_steps)
    db_mod._migration_steps.clear()
    yield db_mod._migration_steps
    db_mod._migration_steps.clear()
    db_mod._migration_steps.extend(saved)


@pytest.fixture
def engine(tmp_path):
    eng = create_engine(f"sqlite:///{tmp_path / 'mig.db'}")
    yield eng
    eng.dispose()


def test_steps_run_in_registration_order(steps, engine):
    order = []
    db_mod.register_migration(lambda e: order.append("a"))
    db_mod.register_migration(lambda e: order.append("b"))
    db_mod.register_migration(lambda e: order.append("c"))
    db_mod.run_migrations(engine)
    assert order == ["a", "b", "c"]


def test_failing_step_is_skipped_and_others_run(steps, engine):
    ran = []

    def boom(e):
        raise RuntimeError("kaboom")

    db_mod.register_migration(lambda e: ran.append("first"))
    db_mod.register_migration(boom)
    db_mod.register_migration(lambda e: ran.append("last"))

    db_mod.run_migrations(engine)
    assert ran == ["first", "last"]


def test_has_table_reflects_schema(steps, engine):
    assert db_mod.has_table(engine, "users") is False
    with engine.begin() as conn:
        conn.execute(text("CREATE TABLE users (id TEXT)"))
    assert db_mod.has_table(engine, "users") is True


def test_add_column_step_is_idempotent(steps, engine):
    with engine.begin() as conn:
        conn.execute(text("CREATE TABLE notes (id TEXT)"))

    calls = []

    def add_tag(e):
        from sqlalchemy import inspect
        if "tag" in {c["name"] for c in inspect(e).get_columns("notes")}:
            return
        calls.append(1)
        with e.begin() as conn:
            conn.execute(text("ALTER TABLE notes ADD COLUMN tag TEXT"))

    db_mod.register_migration(add_tag)
    db_mod.run_migrations(engine)
    db_mod.run_migrations(engine)
    assert calls == [1]
