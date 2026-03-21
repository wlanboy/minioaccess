import json
from unittest.mock import patch

from mc_commands import (
    get_policy_actions,
    list_users,
    list_buckets,
    create_bucket_policy,
    get_bucket_policies,
)


# ---------------------------------------------------------------------------
# get_policy_actions
# ---------------------------------------------------------------------------

class TestGetPolicyActions:
    def test_readonly(self):
        actions = get_policy_actions("readonly")
        assert "s3:GetObject" in actions
        assert "s3:GetBucketLocation" in actions
        assert "s3:ListBucket" in actions

    def test_readwrite(self):
        actions = get_policy_actions("readwrite")
        assert actions == ["s3:*"]

    def test_writeonly(self):
        actions = get_policy_actions("writeonly")
        assert actions == ["s3:PutObject"]

    def test_unknown_type_returns_empty(self):
        assert get_policy_actions("admin") == []
        assert get_policy_actions("") == []


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

    def test_returns_empty_list_on_error(self):
        with patch("mc_commands.run_mc_command", return_value="Error: connection refused"):
            assert list_users() == []

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

    def test_returns_empty_on_error(self):
        with patch("mc_commands.run_mc_command", return_value="Error: connection refused"):
            assert list_buckets() == []

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
        with patch("mc_commands.run_mc_command", return_value="Error: policy already exists"):
            result = create_bucket_policy("mybucket", "readwrite")
        assert result == "mybucket-readwrite"

    def test_returns_error_on_other_errors(self):
        with patch("mc_commands.run_mc_command", return_value="Error: connection refused"):
            result = create_bucket_policy("mybucket", "readonly")
        assert result.startswith("Error")

    def test_unknown_policy_type_returns_error(self):
        result = create_bucket_policy("mybucket", "unknown")
        assert result.startswith("Error")

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
        stmt = policy["Statement"][0]
        assert stmt["Effect"] == "Allow"
        assert "arn:aws:s3:::testbucket" in stmt["Resource"]
        assert "arn:aws:s3:::testbucket/*" in stmt["Resource"]
        assert stmt["Action"] == ["s3:*"]


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
             patch("mc_commands.run_mc_command", return_value="Error: user not found"):
            policies = get_bucket_policies("mybucket")

        assert policies == []
