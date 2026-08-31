import pytest

from app.db.session import init_db


@pytest.fixture(scope="session", autouse=True)
def _init_db():
    # test_retention.py writes rows directly via SessionLocal(), bypassing
    # the app lifespan (app.main.lifespan) that normally calls init_db() on
    # startup. Without this, table creation only happened incidentally when
    # test_api_smoke.py ran first and spun up a TestClient -- which doesn't
    # happen in CI, where that module self-skips for lack of a committed
    # model artifact, leaving the retention tests with no tables to write to.
    init_db()
