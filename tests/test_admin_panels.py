"""Admin panel hook tests: a site's registered panels render as links on /admin."""
import pytest

from rhymes_with_soot.admin import list_admin_panels, register_admin_panel
from rhymes_with_soot.admin import panels as panels_mod

from tests.helpers import login, make_user

GOOD_PW = "Sup3r-Secret!pw"


@pytest.fixture
def clean_panels():
    """The panel registry is process-wide; keep tests from leaking registrations."""
    saved = list(panels_mod._PANELS)
    panels_mod._PANELS.clear()
    yield
    panels_mod._PANELS[:] = saved


def test_register_and_list(clean_panels):
    register_admin_panel("Reports", "reports.page")
    panels = list_admin_panels()
    assert [(p.label, p.endpoint) for p in panels] == [("Reports", "reports.page")]


def test_register_rejects_bad_args(clean_panels):
    with pytest.raises(ValueError):
        register_admin_panel("", "x")
    with pytest.raises(ValueError):
        register_admin_panel("Label", "")
    assert list_admin_panels() == []


def test_panel_link_renders_on_admin(app, clean_panels):
    # test.page is an existing endpoint in the test blueprint.
    register_admin_panel("Reports", "test.page")
    make_user(app, "root", GOOD_PW, role="admin")
    client = app.test_client()
    login(client, "root", GOOD_PW)
    body = client.get("/admin").get_data(as_text=True)
    assert 'class="admin-panel-link"' in body
    assert 'href="/t/page"' in body
    assert "Reports" in body


def test_admin_page_without_panels_has_no_nav(app, clean_panels):
    make_user(app, "root", GOOD_PW, role="admin")
    client = app.test_client()
    login(client, "root", GOOD_PW)
    body = client.get("/admin").get_data(as_text=True)
    assert "admin-panels" not in body
