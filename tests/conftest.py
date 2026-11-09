from dataclasses import replace

import pytest

import mc_commands
from mc_commands import Settings

TEST_SETTINGS = Settings(
    alias="test",
    endpoint="http://localhost:9000",
    access_key="testkey",
    secret_key="testsecret",
    mc_binary="/opt/mc-test",
    mc_timeout=15.0,
)


@pytest.fixture(autouse=True)
def mc_settings():
    """Feste Konfiguration, unabhängig von .env oder der Shell-Umgebung."""
    mc_commands.configure(TEST_SETTINGS)
    yield TEST_SETTINGS
    mc_commands.configure(None)


@pytest.fixture
def use_settings():
    """Einzelne Werte überschreiben: use_settings(secret_key="...")."""
    def _use(**overrides) -> Settings:
        settings = replace(TEST_SETTINGS, **overrides)
        mc_commands.configure(settings)
        return settings
    return _use
