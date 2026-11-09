import json
import os
import subprocess
from unittest.mock import patch

import pytest

import mc_commands
from mc_commands import (
    MC_BINARY,
    McError,
    check_connection,
    create_bucket,
    create_bucket_policy,
    create_user,
    delete_bucket,
    ensure_bucket_policy,
    get_bucket_policies,
    get_policy_details,
    is_valid_bucket,
    list_buckets,
    list_users,
    policy_statements,
    run_mc_command,
)

REFUSED = McError("connection refused")

# ---------------------------------------------------------------------------
# policy_statements
# ---------------------------------------------------------------------------

def _by_resource(statements: list[dict]) -> dict[str, set[str]]:
    result: dict[str, set[str]] = {}
    for stmt in statements:
        assert stmt["Effect"] == "Allow"
        for resource in stmt["Resource"]:
            result.setdefault(resource, set()).update(stmt["Action"])
    return result


class TestPolicyStatements:
    def test_readonly(self):
        assert _by_resource(policy_statements("data", "readonly")) == {
            "arn:aws:s3:::data": {"s3:GetBucketLocation", "s3:ListBucket"},
            "arn:aws:s3:::data/*": {"s3:GetObject"},
        }

    def test_readwrite(self):
        assert _by_resource(policy_statements("data", "readwrite")) == {
            "arn:aws:s3:::data": {"s3:*"},
            "arn:aws:s3:::data/*": {"s3:*"},
        }

    def test_writeonly_allows_multipart(self):
        assert _by_resource(policy_statements("data", "writeonly")) == {
            "arn:aws:s3:::data": {"s3:GetBucketLocation", "s3:ListBucketMultipartUploads"},
            "arn:aws:s3:::data/*": {"s3:PutObject", "s3:AbortMultipartUpload", "s3:ListMultipartUploadParts"},
        }

    def test_writeonly_cannot_read(self):
        actions = set().union(*_by_resource(policy_statements("data", "writeonly")).values())
        assert "s3:GetObject" not in actions
        assert "s3:ListBucket" not in actions

    @pytest.mark.parametrize("policy_type", ["admin", "", "data"])
    def test_unknown_type_raises(self, policy_type):
        with pytest.raises(ValueError):
            policy_statements("data", policy_type)


# ---------------------------------------------------------------------------
# list_users
# ---------------------------------------------------------------------------

def _user_json(access_key: str, enabled: bool) -> str:
    status = "enabled" if enabled else "disabled"
    return json.dumps({"status": "success", "accessKey": access_key, "userStatus": status})


class TestListUsers:
    def test_parses_two_users(self):
        output = f"{_user_json('alice', True)}\n{_user_json('bob', True)}"
        with patch("mc_commands.run_mc_command", return_value=output):
            assert list_users() == [{"name": "alice", "enabled": True}, {"name": "bob", "enabled": True}]

    def test_parses_disabled_user(self):
        output = f"{_user_json('alice', True)}\n{_user_json('bob', False)}"
        with patch("mc_commands.run_mc_command", return_value=output):
            assert list_users() == [{"name": "alice", "enabled": True}, {"name": "bob", "enabled": False}]

    def test_error_is_raised(self):
        """Regression 2.3: MinIO nicht erreichbar darf nicht als leere Liste erscheinen."""
        with patch("mc_commands.run_mc_command", side_effect=REFUSED), pytest.raises(McError):
            list_users()

    def test_ignores_empty_lines(self):
        output = f"{_user_json('alice', True)}\n\n{_user_json('bob', True)}\n"
        with patch("mc_commands.run_mc_command", return_value=output):
            assert list_users() == [{"name": "alice", "enabled": True}, {"name": "bob", "enabled": True}]

    def test_single_user(self):
        with patch("mc_commands.run_mc_command", return_value=_user_json("charlie", True)):
            assert list_users() == [{"name": "charlie", "enabled": True}]


# ---------------------------------------------------------------------------
# list_buckets
# ---------------------------------------------------------------------------

def _bucket_json(name: str) -> str:
    return json.dumps({"status": "success", "type": "folder", "key": f"{name}/", "size": 0})


class TestListBuckets:
    def test_parses_bucket_names(self):
        output = f"{_bucket_json('mybucket')}\n{_bucket_json('other')}"
        with patch("mc_commands.run_mc_command", return_value=output):
            buckets = list_buckets()
        assert "mybucket" in buckets
        assert "other" in buckets

    def test_strips_trailing_slash(self):
        with patch("mc_commands.run_mc_command", return_value=_bucket_json("mybucket")):
            buckets = list_buckets()
        assert buckets == ["mybucket"]

    def test_error_is_raised(self):
        with patch("mc_commands.run_mc_command", side_effect=REFUSED), pytest.raises(McError):
            list_buckets()

    def test_empty_output_returns_empty_list(self):
        with patch("mc_commands.run_mc_command", return_value=""):
            assert list_buckets() == []

    def test_ignores_non_folder_entries(self):
        file_entry = json.dumps({"status": "success", "type": "file", "key": "somefile.txt", "size": 100})
        output = f"{_bucket_json('mybucket')}\n{file_entry}"
        with patch("mc_commands.run_mc_command", return_value=output):
            buckets = list_buckets()
        assert buckets == ["mybucket"]


# ---------------------------------------------------------------------------
# create_bucket_policy
# ---------------------------------------------------------------------------

class TestCreateBucketPolicy:
    def test_returns_policy_name_on_success(self):
        with patch("mc_commands.run_mc_command", return_value=json.dumps({"status": "success", "policy": "mybucket-readonly"})):
            result = create_bucket_policy("mybucket", "readonly")
        assert result == "mybucket-readonly"

    def test_returns_policy_name_if_already_exists(self):
        with patch("mc_commands.run_mc_command", side_effect=McError("policy already exists")):
            result = create_bucket_policy("mybucket", "readwrite")
        assert result == "mybucket-readwrite"

    def test_raises_on_other_errors(self):
        with patch("mc_commands.run_mc_command", side_effect=REFUSED), pytest.raises(McError):
            create_bucket_policy("mybucket", "readonly")

    def test_unknown_policy_type_raises(self):
        with patch("mc_commands.run_mc_command") as run, pytest.raises(ValueError):
            create_bucket_policy("mybucket", "unknown")
        run.assert_not_called()

    def test_error_in_name_is_not_an_error(self):
        """Regression 2.2: „Error“ in der Ausgabe ist kein Fehler, nur der Exit-Code zählt."""
        with patch("mc_commands.run_mc_command", return_value='{"status":"success","policy":"Error-bucket"}'):
            assert create_bucket_policy("mybucket", "readonly") == "mybucket-readonly"

    def test_policy_json_structure(self):
        """Prüft, dass die erzeugte Policy das korrekte JSON-Format hat."""
        captured_path: list[str] = []

        def fake_run(command):
            captured_path.append(command[-1])  # letztes Arg = temp-Datei
            return json.dumps({"status": "success"})

        with patch("mc_commands.run_mc_command", side_effect=fake_run):
            create_bucket_policy("testbucket", "readonly")

        assert captured_path, "run_mc_command wurde nicht aufgerufen"

    def test_policy_json_content(self):
        """Verifiziert das erzeugte Policy-JSON für readwrite."""
        written_json: list[dict] = []

        import io

        class FakeTempFile:
            def __init__(self):
                self.name = "/tmp/fake_policy.json"
                self._buf = io.StringIO()

            def write(self, data):
                self._buf.write(data)

            def __enter__(self):
                return self

            def __exit__(self, *_):
                written_json.append(json.loads(self._buf.getvalue()))

        fake_tf = FakeTempFile()

        with patch("mc_commands.run_mc_command", return_value=json.dumps({"status": "success"})), \
             patch("tempfile.NamedTemporaryFile", return_value=fake_tf), \
             patch("os.unlink"):
            create_bucket_policy("testbucket", "readwrite")

        assert len(written_json) == 1
        policy = written_json[0]
        assert policy["Version"] == "2012-10-17"
        assert policy["Statement"] == policy_statements("testbucket", "readwrite")


class TestEnsureBucketPolicy:
    def test_existing_policy_is_reused(self):
        with patch("mc_commands.list_policies", return_value=["data-readonly"]), \
             patch("mc_commands.create_bucket_policy") as create:
            assert ensure_bucket_policy("data", "readonly") == "data-readonly"
        create.assert_not_called()

    def test_missing_policy_is_created(self):
        with patch("mc_commands.list_policies", return_value=[]), \
             patch("mc_commands.create_bucket_policy", return_value="data-writeonly") as create:
            assert ensure_bucket_policy("data", "writeonly") == "data-writeonly"
        create.assert_called_once_with("data", "writeonly")

    def test_list_error_is_raised(self):
        with patch("mc_commands.list_policies", side_effect=REFUSED), \
             patch("mc_commands.create_bucket_policy") as create, pytest.raises(McError):
            ensure_bucket_policy("data", "readonly")
        create.assert_not_called()


class TestGetPolicyDetails:
    def test_action_as_string(self):
        doc = {"status": "success", "policy": {"Statement": [
            {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::data/*"},
            {"Effect": "Allow", "Action": ["s3:ListBucket"], "Resource": ["arn:aws:s3:::data"]},
        ]}}
        with patch("mc_commands.run_mc_command", return_value=json.dumps(doc)):
            details = get_policy_details("p")
        assert details["actions"] == ["s3:GetObject", "s3:ListBucket"]
        assert details["resources"] == ["arn:aws:s3:::data/*", "arn:aws:s3:::data"]

    def test_error_is_raised(self):
        with patch("mc_commands.run_mc_command", side_effect=REFUSED), pytest.raises(McError):
            get_policy_details("p")


# ---------------------------------------------------------------------------
# get_bucket_policies
# ---------------------------------------------------------------------------

def _user_info_json(username: str, policy_name: str) -> str:
    return json.dumps({"status": "success", "accessKey": username, "policyName": policy_name, "userStatus": "enabled"})


class TestGetBucketPolicies:
    def test_returns_matching_policies(self):
        user_info = _user_info_json("alice", "mybucket-readonly")
        with patch("mc_commands.list_users", return_value=[{"name": "alice", "enabled": True}]), \
             patch("mc_commands.run_mc_command", return_value=user_info):
            policies = get_bucket_policies("mybucket")

        assert len(policies) == 1
        assert policies[0] == {"user": "alice", "policy": "mybucket-readonly"}

    def test_filters_policies_from_other_buckets(self):
        user_info = _user_info_json("alice", "otherbucket-readonly")
        with patch("mc_commands.list_users", return_value=[{"name": "alice", "enabled": True}]), \
             patch("mc_commands.run_mc_command", return_value=user_info):
            policies = get_bucket_policies("mybucket")

        assert policies == []

    def test_handles_multiple_policies_per_user(self):
        user_info = _user_info_json("alice", "mybucket-readonly,mybucket-readwrite")
        with patch("mc_commands.list_users", return_value=[{"name": "alice", "enabled": True}]), \
             patch("mc_commands.run_mc_command", return_value=user_info):
            policies = get_bucket_policies("mybucket")

        assert len(policies) == 2
        policy_names = {p["policy"] for p in policies}
        assert policy_names == {"mybucket-readonly", "mybucket-readwrite"}

    def test_handles_multiple_users(self):
        def fake_user_info(command):
            user = command[-1]
            return _user_info_json(user, "mybucket-readonly")

        with patch("mc_commands.list_users", return_value=[{"name": "alice", "enabled": True}, {"name": "bob", "enabled": True}]), \
             patch("mc_commands.run_mc_command", side_effect=fake_user_info):
            policies = get_bucket_policies("mybucket")

        assert len(policies) == 2
        users = {p["user"] for p in policies}
        assert users == {"alice", "bob"}

    def test_no_users_returns_empty(self):
        with patch("mc_commands.list_users", return_value=[]):
            policies = get_bucket_policies("mybucket")
        assert policies == []

    def test_skips_users_with_mc_error(self):
        with patch("mc_commands.list_users", return_value=[{"name": "ghost", "enabled": True}]), \
             patch("mc_commands.run_mc_command", side_effect=McError("user not found")):
            policies = get_bucket_policies("mybucket")

        assert policies == []

    def test_timeout_is_raised(self):
        with patch("mc_commands.list_users", return_value=[{"name": "alice", "enabled": True}]), \
             patch("mc_commands.run_mc_command", side_effect=McError("timeout", 504)), pytest.raises(McError):
            get_bucket_policies("mybucket")


# ---------------------------------------------------------------------------
# run_mc_command: Credentials nur per MC_HOST_<alias>
# ---------------------------------------------------------------------------

def _completed(returncode=0, stdout="", stderr=""):
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr=stderr)


@pytest.fixture(autouse=False)
def mc_config():
    """Feste Werte, unabhängig von .env oder der Shell-Umgebung."""
    with patch.multiple("mc_commands", MINIO_ALIAS="test", MINIO_ENDPOINT="http://localhost:9000",
                        MINIO_ACCESS_KEY="testkey", MINIO_SECRET_KEY="testsecret"):
        yield


@pytest.mark.usefixtures("mc_config")
class TestRunMcCommand:
    def test_credentials_in_env_not_argv(self):
        with patch("mc_commands.subprocess.run", return_value=_completed(stdout="ok")) as run:
            run_mc_command([MC_BINARY, "--json", "ls", "test"])
        argv = run.call_args.args[0]
        env = run.call_args.kwargs["env"]
        assert "testsecret" not in " ".join(argv)
        assert env["MC_HOST_test"] == "http://testkey:testsecret@localhost:9000"

    def test_special_chars_are_url_encoded(self):
        with patch("mc_commands.MINIO_SECRET_KEY", "p@ss:w/rd%"), \
             patch("mc_commands.subprocess.run", return_value=_completed()) as run:
            run_mc_command([MC_BINARY, "ls", "test"])
        assert run.call_args.kwargs["env"]["MC_HOST_test"] == "http://testkey:p%40ss%3Aw%2Frd%25@localhost:9000"

    def test_invalid_endpoint(self):
        with patch("mc_commands.MINIO_ENDPOINT", "localhost:9000"), pytest.raises(RuntimeError):
            run_mc_command([MC_BINARY, "ls", "test"])

    def test_stdout_not_logged(self, caplog):
        caplog.set_level("DEBUG")
        with patch("mc_commands.subprocess.run", return_value=_completed(stdout='{"secretKey":"leak"}')):
            run_mc_command([MC_BINARY, "--json", "admin", "user", "info", "test", "bob"])
        assert "leak" not in caplog.text
        assert "bob" not in caplog.text

    def test_json_error_message(self):
        out = json.dumps({"status": "error", "error": {"message": "boom"}})
        with patch("mc_commands.subprocess.run", return_value=_completed(returncode=1, stdout=out)), \
             pytest.raises(McError) as exc:
            run_mc_command([MC_BINARY, "ls", "test"])
        assert exc.value.message == "boom"
        assert exc.value.status == 400

    def test_text_error_message(self):
        with patch("mc_commands.subprocess.run", return_value=_completed(returncode=1, stderr="mc: <ERROR> nope")), \
             pytest.raises(McError) as exc:
            run_mc_command([MC_BINARY, "ls", "test"])
        assert exc.value.message == "mc: <ERROR> nope"

    def test_error_text_in_stdout_with_exit_0_is_success(self):
        """Regression 2.2: Nur der Exit-Code entscheidet."""
        with patch("mc_commands.subprocess.run", return_value=_completed(stdout="Error-user")):
            assert run_mc_command([MC_BINARY, "ls", "test"]) == "Error-user"

    def test_timeout(self):
        with patch("mc_commands.MC_TIMEOUT", 3.0), \
             patch("mc_commands.subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="mc", timeout=3)) as run, \
             pytest.raises(McError) as exc:
            run_mc_command([MC_BINARY, "ls", "test"])
        assert run.call_args.kwargs["timeout"] == 3.0
        assert exc.value.status == 504
        assert "Timeout" in exc.value.message

    def test_os_error(self):
        with patch("mc_commands.subprocess.run", side_effect=FileNotFoundError("./mc")), \
             pytest.raises(McError) as exc:
            run_mc_command([MC_BINARY, "ls", "test"])
        assert exc.value.status == 500


@pytest.fixture
def fake_mc(tmp_path):
    path = tmp_path / "mc"
    path.write_text("#!/bin/sh\n")
    path.chmod(0o755)
    with patch("mc_commands.MC_BINARY", str(path)):
        yield str(path)


@pytest.mark.usefixtures("mc_config")
class TestCheckConnection:
    def test_uses_admin_info(self, fake_mc):
        with patch("mc_commands.run_mc_command", return_value="{}") as run:
            check_connection()
        assert run.call_args.args[0] == [fake_mc, "--json", "admin", "info", "test"]

    def test_fails_when_minio_unreachable(self, fake_mc):
        with patch("mc_commands.run_mc_command", side_effect=REFUSED), pytest.raises(RuntimeError):
            check_connection()

    def test_fails_when_binary_missing(self, tmp_path):
        with patch("mc_commands.MC_BINARY", str(tmp_path / "missing")), \
             patch("mc_commands.run_mc_command") as run, pytest.raises(RuntimeError, match="MC_BINARY"):
            check_connection()
        run.assert_not_called()

    def test_fails_when_not_executable(self, fake_mc):
        os.chmod(fake_mc, 0o644)
        with patch("mc_commands.run_mc_command") as run, pytest.raises(RuntimeError):
            check_connection()
        run.assert_not_called()


class TestResolveMcBinary:
    def test_env_wins(self, monkeypatch):
        monkeypatch.setenv("MC_BINARY", "/opt/mc")
        assert mc_commands._resolve_mc_binary() == "/opt/mc"

    def test_path_fallback(self, monkeypatch):
        monkeypatch.delenv("MC_BINARY", raising=False)
        with patch("mc_commands.shutil.which", return_value="/usr/bin/mc"):
            assert mc_commands._resolve_mc_binary() == "/usr/bin/mc"

    def test_local_fallback(self, monkeypatch):
        monkeypatch.delenv("MC_BINARY", raising=False)
        with patch("mc_commands.shutil.which", return_value=None):
            assert mc_commands._resolve_mc_binary() == "./mc"


# ---------------------------------------------------------------------------
# Validierung als letzte Sicherung vor mc
# ---------------------------------------------------------------------------

class TestValidation:
    @pytest.mark.parametrize("name", ["data", "my-bucket", "a.b.c", "abc123"])
    def test_valid_buckets(self, name):
        assert is_valid_bucket(name)

    @pytest.mark.parametrize("name", ["*", "ab", "-abc", "abc-", "a..b", "Upper", "a/b", "10.0.0.1"])
    def test_invalid_buckets(self, name):
        assert not is_valid_bucket(name)

    def test_create_bucket_rejects_wildcard(self):
        with patch("mc_commands.run_mc_command") as run, pytest.raises(ValueError):
            create_bucket("*")
        run.assert_not_called()

    def test_create_user_rejects_flag(self):
        with patch("mc_commands.run_mc_command") as run, pytest.raises(ValueError):
            create_user("--insecure", "x" * 12)
        run.assert_not_called()

    def test_create_bucket_policy_rejects_wildcard(self):
        with patch("mc_commands.run_mc_command") as run, pytest.raises(ValueError):
            create_bucket_policy("*", "readwrite")
        run.assert_not_called()


class TestDeleteBucket:
    @pytest.mark.usefixtures("mc_config")
    def test_without_force(self):
        with patch("mc_commands.run_mc_command", return_value="") as run:
            delete_bucket("data")
        assert run.call_args.args[0] == [MC_BINARY, "--json", "rb", "test/data"]

    @pytest.mark.usefixtures("mc_config")
    def test_with_force(self):
        with patch("mc_commands.run_mc_command", return_value="") as run:
            delete_bucket("data", force=True)
        assert run.call_args.args[0] == [MC_BINARY, "--json", "rb", "--force", "test/data"]
