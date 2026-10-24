import json
from dataclasses import fields
from time import time

import pytest
import requests
import trakt.auth
import trakt.core
from requests.adapters import BaseAdapter
from trakt.api import HttpClient, TokenAuth
from trakt.config import AuthConfig
from trakt.errors import TraktInternalException

from plextraktsync.trakt.TraktApi import TraktApi


class OAuthTransport(BaseAdapter):
    def __init__(self, secret=None, fail=False):
        self.secret = secret
        self.fail = fail

    def send(self, request, **kwargs):
        body = json.loads(request.body) if request.body else {}
        response = requests.Response()
        response.status_code = 200
        response.url = request.url
        if body.get("grant_type") == "refresh_token":
            response.status_code = 400
            data = {"error": "invalid_grant", "error_description": "session not found"}
        elif request.url.endswith("/oauth/device/code"):
            assert body["client_id"] == "new-client"
            if self.fail:
                response.status_code = 500
                data = {}
            else:
                data = {
                    "device_code": "device-code",
                    "user_code": "USER-CODE",
                    "verification_url": "https://trakt.tv/activate",
                    "interval": 0,
                }
        elif request.url.endswith("/oauth/device/token"):
            assert body == {"code": "device-code", "client_id": "new-client", "client_secret": self.secret}
            data = {
                "access_token": "fresh-access",
                "refresh_token": "fresh-refresh",
                "created_at": int(time()),
                "expires_in": 7200,
            }
        else:
            assert request.headers["Authorization"] == "Bearer fresh-access"
            assert request.headers["trakt-api-key"] == "new-client"
            data = {"username": "new-user"}
        response._content = json.dumps(data).encode()
        return response

    def close(self):
        pass


@pytest.fixture
def auth_environment(tmp_path, monkeypatch):
    config_file = tmp_path / ".pytrakt.json"
    config_file.write_text(json.dumps({
        "CLIENT_ID": "old-client",
        "CLIENT_SECRET": "old-secret",
        "OAUTH_TOKEN": "expired-access",
        "OAUTH_REFRESH": "revoked-refresh",
        "OAUTH_EXPIRES_AT": 1,
    }))
    config = AuthConfig(str(config_file)).update(**{field.name: None for field in fields(AuthConfig)})
    with requests.Session() as session:
        client = HttpClient("https://api.trakt.tv/", session)
        client.auth = TokenAuth(client=client, config=config)
        monkeypatch.setattr(trakt.core, "BASE_URL", "https://api.trakt.tv/")
        monkeypatch.setattr(trakt.core, "session", session)
        monkeypatch.setattr(trakt.core, "config", lambda: config)
        monkeypatch.setattr(trakt.core, "api", lambda: client)
        monkeypatch.setattr(trakt.auth, "config_factory", lambda: config)
        monkeypatch.setattr(trakt.auth, "api", lambda: client)
        monkeypatch.setattr(trakt.core, "AUTH_METHOD", trakt.core.DEVICE_AUTH)
        yield config_file, session, client


@pytest.mark.parametrize("client_secret", [None, "provided-secret"])
def test_device_login_replaces_revoked_credentials(auth_environment, client_secret):
    config_file, session, client = auth_environment
    session.mount("https://", OAuthTransport(secret=client_secret))

    TraktApi.device_auth("new-client", client_secret)

    saved = json.loads(config_file.read_text())
    assert saved["CLIENT_ID"] == "new-client"
    assert saved["CLIENT_SECRET"] == client_secret
    assert saved["OAUTH_TOKEN"] == "fresh-access"
    assert saved["OAUTH_REFRESH"] == "fresh-refresh"
    assert client.get("users/me") == {"username": "new-user"}


def test_failed_device_login_preserves_saved_credentials(auth_environment):
    config_file, session, _ = auth_environment
    original = config_file.read_bytes()
    session.mount("https://", OAuthTransport(fail=True))

    with pytest.raises(TraktInternalException):
        TraktApi.device_auth("new-client")

    assert config_file.read_bytes() == original
