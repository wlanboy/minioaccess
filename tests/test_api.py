from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

import main

CSRF = {"X-Requested-With": "minioaccess"}


@pytest.fixture
def client():
    # Ohne Context-Manager läuft der lifespan (mc alias set) nicht.
    return TestClient(main.app)


# ---------------------------------------------------------------------------
# Statisches Frontend
# ---------------------------------------------------------------------------

def test_index_serves_static_html(client):
    res = client.get("/")
    assert res.status_code == 200
    assert "app.js" in res.text


def test_static_assets(client):
    assert client.get("/app.js").status_code == 200
    assert client.get("/style.css").status_code == 200


# ---------------------------------------------------------------------------
# CSRF
# ---------------------------------------------------------------------------

class TestCsrf:
    def test_post_without_header_rejected(self, client):
        with patch.object(main, "create_bucket") as create:
            res = client.post("/api/buckets", json={"name": "abc"})
        assert res.status_code == 403
        create.assert_not_called()

    def test_delete_without_header_rejected(self, client):
        with patch.object(main, "delete_bucket") as delete:
            res = client.delete("/api/buckets/abc")
        assert res.status_code == 403
        delete.assert_not_called()

    def test_cross_site_rejected(self, client):
        res = client.post("/api/users/bob/disable", headers={**CSRF, "Sec-Fetch-Site": "cross-site"})
        assert res.status_code == 403

    def test_foreign_origin_rejected(self, client):
        res = client.post("/api/users/bob/disable", headers={**CSRF, "Origin": "http://evil.example"})
        assert res.status_code == 403

    def test_same_origin_allowed(self, client):
        with patch.object(main, "disable_user", return_value="") as disable:
            res = client.post(
                "/api/users/bob/disable",
                headers={**CSRF, "Origin": "http://testserver", "Sec-Fetch-Site": "same-origin"},
            )
        assert res.status_code == 200
        disable.assert_called_once_with("bob")

    def test_get_needs_no_header(self, client):
        with patch.object(main, "list_users", return_value=[]):
            assert client.get("/api/users").status_code == 200


# ---------------------------------------------------------------------------
# Users
# ---------------------------------------------------------------------------

class TestUsers:
    def test_list(self, client):
        users = [{"name": "alice", "enabled": True}]
        with patch.object(main, "list_users", return_value=users):
            assert client.get("/api/users").json() == users

    def test_create(self, client):
        with patch.object(main, "create_user", return_value="") as create:
            res = client.post("/api/users", headers=CSRF,
                              json={"access_key": " alice ", "secret_key": "x" * 12})
        assert res.status_code == 200
        assert res.json()["message"] == "Benutzer 'alice' erstellt."
        create.assert_called_once_with("alice", "x" * 12)

    def test_create_short_secret(self, client):
        with patch.object(main, "create_user") as create:
            res = client.post("/api/users", headers=CSRF,
                              json={"access_key": "alice", "secret_key": "short"})
        assert res.status_code == 400
        assert "12 Zeichen" in res.json()["detail"]
        create.assert_not_called()

    def test_create_empty_name(self, client):
        res = client.post("/api/users", headers=CSRF, json={"access_key": "  ", "secret_key": "x" * 12})
        assert res.status_code == 400

    def test_mc_error_becomes_400(self, client):
        with patch.object(main, "delete_user", return_value="Error: user not found"):
            res = client.delete("/api/users/bob", headers=CSRF)
        assert res.status_code == 400
        assert res.json()["detail"] == "Error: user not found"

    def test_change_password(self, client):
        with patch.object(main, "change_password", return_value="") as change:
            res = client.put("/api/users/bob/password", headers=CSRF, json={"secret_key": "y" * 16})
        assert res.status_code == 200
        change.assert_called_once_with("bob", "y" * 16)


# ---------------------------------------------------------------------------
# Buckets & Berechtigungen
# ---------------------------------------------------------------------------

class TestBuckets:
    def test_create(self, client):
        with patch.object(main, "create_bucket", return_value="") as create:
            res = client.post("/api/buckets", headers=CSRF, json={"name": "my-bucket"})
        assert res.status_code == 200
        create.assert_called_once_with("my-bucket")

    @pytest.mark.parametrize("name", ["*", "A", "ab", "-abc", "a..b", "Upper", "a/b"])
    def test_create_invalid_name(self, client, name):
        with patch.object(main, "create_bucket") as create:
            res = client.post("/api/buckets", headers=CSRF, json={"name": name})
        assert res.status_code == 400
        create.assert_not_called()

    def test_attach_policy(self, client):
        with (
            patch.object(main, "list_buckets", return_value=["data"]),
            patch.object(main, "ensure_bucket_policy", return_value="data-readonly") as ensure,
            patch.object(main, "attach_policy", return_value="") as attach,
        ):
            res = client.post("/api/buckets/data/policies", headers=CSRF,
                              json={"user": "bob", "policy_type": "readonly"})
        assert res.status_code == 200
        ensure.assert_called_once_with("data", "readonly")
        attach.assert_called_once_with("data-readonly", "bob")

    def test_attach_unknown_type(self, client):
        with (
            patch.object(main, "list_buckets", return_value=["data"]),
            patch.object(main, "ensure_bucket_policy") as ensure,
        ):
            res = client.post("/api/buckets/data/policies", headers=CSRF,
                              json={"user": "bob", "policy_type": "data"})
        assert res.status_code == 400
        ensure.assert_not_called()

    def test_attach_wildcard_bucket_rejected(self, client):
        """Regression: Bucket '*' hätte eine Policy auf arn:aws:s3:::* erzeugt."""
        with patch.object(main, "ensure_bucket_policy") as ensure:
            res = client.post("/api/buckets/*/policies", headers=CSRF,
                              json={"user": "bob", "policy_type": "readwrite"})
        assert res.status_code == 400
        ensure.assert_not_called()

    def test_attach_unknown_bucket(self, client):
        with (
            patch.object(main, "list_buckets", return_value=["data"]),
            patch.object(main, "ensure_bucket_policy") as ensure,
        ):
            res = client.post("/api/buckets/other/policies", headers=CSRF,
                              json={"user": "bob", "policy_type": "readonly"})
        assert res.status_code == 404
        ensure.assert_not_called()

    def test_detach(self, client):
        with patch.object(main, "detach_policy", return_value="") as detach:
            res = client.delete("/api/buckets/data/policies/data-readonly/users/bob", headers=CSRF)
        assert res.status_code == 200
        detach.assert_called_once_with("data-readonly", "bob")

    def test_attach_invalid_user(self, client):
        with (
            patch.object(main, "list_buckets", return_value=["data"]),
            patch.object(main, "ensure_bucket_policy") as ensure,
        ):
            res = client.post("/api/buckets/data/policies", headers=CSRF,
                              json={"user": "--insecure", "policy_type": "readonly"})
        assert res.status_code == 400
        ensure.assert_not_called()

    def test_policies_unknown_bucket(self, client):
        with (
            patch.object(main, "list_buckets", return_value=["data"]),
            patch.object(main, "get_bucket_policies") as get,
        ):
            res = client.get("/api/buckets/other/policies")
        assert res.status_code == 404
        get.assert_not_called()

    def test_policies_invalid_bucket(self, client):
        with patch.object(main, "get_bucket_policies") as get:
            res = client.get("/api/buckets/*/policies")
        assert res.status_code == 400
        get.assert_not_called()

    def test_ip_bucket_name_rejected(self, client):
        with patch.object(main, "create_bucket") as create:
            res = client.post("/api/buckets", headers=CSRF, json={"name": "192.168.1.10"})
        assert res.status_code == 400
        create.assert_not_called()

    def test_detach_invalid_values(self, client):
        with patch.object(main, "detach_policy") as detach:
            assert client.delete("/api/buckets/data/policies/--help/users/bob", headers=CSRF).status_code == 400
            assert client.delete("/api/buckets/data/policies/data-readonly/users/-x", headers=CSRF).status_code == 400
        detach.assert_not_called()


# ---------------------------------------------------------------------------
# Argument-Injection (Werte, die mc als Flag lesen würde)
# ---------------------------------------------------------------------------

class TestArgumentInjection:
    @pytest.mark.parametrize("name", ["--insecure", "-h", "ab", "a b", "a/b", "x" * 129])
    def test_create_user_invalid_name(self, client, name):
        with patch.object(main, "create_user") as create:
            res = client.post("/api/users", headers=CSRF, json={"access_key": name, "secret_key": "x" * 12})
        assert res.status_code == 400
        create.assert_not_called()

    def test_create_user_secret_starting_with_dash(self, client):
        with patch.object(main, "create_user") as create:
            res = client.post("/api/users", headers=CSRF,
                              json={"access_key": "alice", "secret_key": "--insecure-123"})
        assert res.status_code == 400
        create.assert_not_called()

    @pytest.mark.parametrize("path", [
        "/api/users/--help/disable",
        "/api/users/--help/enable",
    ])
    def test_user_actions_reject_flags(self, client, path):
        with patch.object(main, "disable_user") as disable, patch.object(main, "enable_user") as enable:
            assert client.post(path, headers=CSRF).status_code == 400
        disable.assert_not_called()
        enable.assert_not_called()

    def test_delete_user_rejects_flag(self, client):
        with patch.object(main, "delete_user") as delete:
            assert client.delete("/api/users/--help", headers=CSRF).status_code == 400
        delete.assert_not_called()

    def test_delete_policy_rejects_flag(self, client):
        with patch.object(main, "delete_policy") as delete:
            assert client.delete("/api/policies/--help", headers=CSRF).status_code == 400
        delete.assert_not_called()

    def test_valid_user_with_special_chars(self, client):
        with patch.object(main, "create_user", return_value="") as create:
            res = client.post("/api/users", headers=CSRF,
                              json={"access_key": "svc.backup@team=a+b,c-d", "secret_key": "x" * 12})
        assert res.status_code == 200
        create.assert_called_once()


# ---------------------------------------------------------------------------
# Bucket löschen: Default ohne --force
# ---------------------------------------------------------------------------

class TestBucketDelete:
    def test_default_without_force(self, client):
        with patch.object(main, "delete_bucket", return_value="") as delete:
            res = client.delete("/api/buckets/data", headers=CSRF)
        assert res.status_code == 200
        delete.assert_called_once_with("data", False)

    def test_force(self, client):
        with patch.object(main, "delete_bucket", return_value="") as delete:
            res = client.delete("/api/buckets/data?force=true", headers=CSRF)
        assert res.status_code == 200
        assert "inklusive aller Objekte" in res.json()["message"]
        delete.assert_called_once_with("data", True)

    def test_not_empty_error_is_400(self, client):
        with patch.object(main, "delete_bucket", return_value="Error: bucket is not empty"):
            res = client.delete("/api/buckets/data", headers=CSRF)
        assert res.status_code == 400
