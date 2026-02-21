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

class TestListUsers:
    def test_parses_two_users(self):
        output = "enabled  alice\nenabled  bob"
        with patch("mc_commands.run_mc_command", return_value=output):
            assert list_users() == ["alice", "bob"]

    def test_returns_empty_list_on_error(self):
        with patch("mc_commands.run_mc_command", return_value="Error: connection refused"):
            assert list_users() == []

    def test_ignores_lines_without_two_parts(self):
        output = "enabled  alice\n\nenabled  bob\n"
        with patch("mc_commands.run_mc_command", return_value=output):
            assert list_users() == ["alice", "bob"]

    def test_single_user(self):
        with patch("mc_commands.run_mc_command", return_value="enabled  charlie"):
            assert list_users() == ["charlie"]


# ---------------------------------------------------------------------------
# list_buckets
# ---------------------------------------------------------------------------

class TestListBuckets:
    def test_parses_bucket_names(self):
        output = "[2024-01-01 00:00:00 UTC]     0B mybucket/\n[2024-01-01 00:00:00 UTC]     0B other/"
        with patch("mc_commands.run_mc_command", return_value=output):
            buckets = list_buckets()
        assert "mybucket/" in buckets
        assert "other/" in buckets

    def test_filters_error_lines(self):
        output = "mc: ERROR something went wrong\n[2024-01-01] 0B good/"
        with patch("mc_commands.run_mc_command", return_value=output):
            buckets = list_buckets()
        assert all("ERROR" not in b for b in buckets)

    def test_empty_output_returns_empty_list(self):
        with patch("mc_commands.run_mc_command", return_value=""):
            assert list_buckets() == []


# ---------------------------------------------------------------------------
# create_bucket_policy
# ---------------------------------------------------------------------------

class TestCreateBucketPolicy:
    def test_returns_policy_name_on_success(self):
        with patch("mc_commands.run_mc_command", return_value="Policy created"):
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
            return "Policy created"

        with patch("mc_commands.run_mc_command", side_effect=fake_run):
            create_bucket_policy("testbucket", "readonly")

        assert captured_path, "run_mc_command wurde nicht aufgerufen"
        # Datei wird nach dem Aufruf gelöscht (finally: os.unlink) – wir
        # prüfen daher das JSON über einen zweiten Patch-Ansatz.

    def test_policy_json_content(self):
        """Verifiziert das erzeugte Policy-JSON für readwrite."""
        written_json: list[dict] = []

        original_open = open

        def capturing_open(path, mode="r", **kwargs):
            fh = original_open(path, mode, **kwargs)
            if mode == "w" and path.endswith(".json"):
                import io

                class CapturingWrapper(io.TextIOWrapper):
                    pass

                # Einfacherer Ansatz: JSON nach dem Schreiben lesen
                return fh
            return fh

        # Einfacherer, zuverlässigerer Ansatz über tempfile-Mock
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

        with patch("mc_commands.run_mc_command", return_value="Policy created"), \
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

class TestGetBucketPolicies:
    def test_returns_matching_policies(self):
        user_info = "AccessKey: alice\nPolicyName: mybucket-readonly"
        with patch("mc_commands.list_users", return_value=["alice"]), \
             patch("mc_commands.run_mc_command", return_value=user_info):
            policies = get_bucket_policies("mybucket")

        assert len(policies) == 1
        assert policies[0] == {"user": "alice", "policy": "mybucket-readonly"}

    def test_filters_policies_from_other_buckets(self):
        user_info = "AccessKey: alice\nPolicyName: otherbucket-readonly"
        with patch("mc_commands.list_users", return_value=["alice"]), \
             patch("mc_commands.run_mc_command", return_value=user_info):
            policies = get_bucket_policies("mybucket")

        assert policies == []

    def test_handles_multiple_policies_per_user(self):
        user_info = "AccessKey: alice\nPolicyName: mybucket-readonly,mybucket-readwrite"
        with patch("mc_commands.list_users", return_value=["alice"]), \
             patch("mc_commands.run_mc_command", return_value=user_info):
            policies = get_bucket_policies("mybucket")

        assert len(policies) == 2
        policy_names = {p["policy"] for p in policies}
        assert policy_names == {"mybucket-readonly", "mybucket-readwrite"}

    def test_handles_multiple_users(self):
        def fake_user_info(command):
            user = command[-1]
            return f"AccessKey: {user}\nPolicyName: mybucket-readonly"

        with patch("mc_commands.list_users", return_value=["alice", "bob"]), \
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
        def fake_user_info(command):
            return "Error: user not found"

        with patch("mc_commands.list_users", return_value=["ghost"]), \
             patch("mc_commands.run_mc_command", side_effect=fake_user_info):
            policies = get_bucket_policies("mybucket")

        assert policies == []
