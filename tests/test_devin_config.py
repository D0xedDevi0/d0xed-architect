"""Config: env-only token, fail-closed allowlists, no secret leakage."""
import os
import tempfile
import unittest

from devin.config import (BOT_ID_ENV, BOT_USERNAME_ENV, CREDENTIALS_DIR_ENV,
                          CREDENTIAL_FILENAME, GITHUB_CREDENTIAL_FILENAME,
                          GITHUB_TOKEN_ENV, GROUPS_ENV, TOKEN_ENV, USERS_ENV,
                          Config, ConfigError, load_config, resolve_github_token,
                          resolve_token)
from tests.devin_fixtures import (BOT_ID, BOT_USERNAME, FAKE_GITHUB_TOKEN,
                                  FAKE_TOKEN, GROUP_ID, USER_ID)


class TestConfig(unittest.TestCase):
    def test_missing_token_raises(self):
        with self.assertRaises(ConfigError):
            load_config({USERS_ENV: str(USER_ID)})

    def test_invalid_token_format_raises(self):
        for bad in ("notatoken", "123:", ":AAAAA", "abc:def"):
            with self.assertRaises(ConfigError):
                load_config({TOKEN_ENV: bad, USERS_ENV: str(USER_ID)})

    def test_missing_users_raises(self):
        with self.assertRaises(ConfigError):
            load_config({TOKEN_ENV: FAKE_TOKEN})

    def test_invalid_user_raises(self):
        with self.assertRaises(ConfigError):
            load_config({TOKEN_ENV: FAKE_TOKEN, USERS_ENV: "not-an-int"})

    def test_invalid_group_raises(self):
        with self.assertRaises(ConfigError):
            load_config({TOKEN_ENV: FAKE_TOKEN, USERS_ENV: str(USER_ID),
                         GROUPS_ENV: "oops"})

    def test_valid_config_loads(self):
        cfg = load_config({TOKEN_ENV: FAKE_TOKEN, USERS_ENV: str(USER_ID)})
        self.assertEqual(cfg.allowed_user_ids, (USER_ID,))
        self.assertEqual(cfg.allowed_group_ids, ())
        self.assertEqual(cfg.token, FAKE_TOKEN)
        self.assertIsNone(cfg.bot_id)
        self.assertIsNone(cfg.bot_username)

    def test_optional_group_parsed(self):
        cfg = load_config({TOKEN_ENV: FAKE_TOKEN, USERS_ENV: str(USER_ID),
                           GROUPS_ENV: str(GROUP_ID)})
        self.assertEqual(cfg.allowed_group_ids, (GROUP_ID,))

    def test_comma_separated_lists(self):
        cfg = load_config({TOKEN_ENV: FAKE_TOKEN,
                           USERS_ENV: f"{USER_ID},123",
                           GROUPS_ENV: f"{GROUP_ID},-999"})
        self.assertEqual(cfg.allowed_user_ids, (USER_ID, 123))
        self.assertEqual(cfg.allowed_group_ids, (GROUP_ID, -999))

    def test_whitespace_separated_groups(self):
        # systemd Environment= passes a QUOTED value through verbatim, so a unit
        # can list several rooms; an unquoted line is truncated by systemd to
        # its first token, which silently dropped a whole group.
        cfg = load_config({TOKEN_ENV: FAKE_TOKEN, USERS_ENV: str(USER_ID),
                           GROUPS_ENV: f"{GROUP_ID} -999;"})
        self.assertEqual(cfg.allowed_group_ids, (GROUP_ID, -999))

    def test_identity_pins_parsed(self):
        cfg = load_config({TOKEN_ENV: FAKE_TOKEN, USERS_ENV: str(USER_ID),
                           BOT_ID_ENV: str(BOT_ID),
                           BOT_USERNAME_ENV: BOT_USERNAME})
        self.assertEqual(cfg.bot_id, BOT_ID)
        self.assertEqual(cfg.bot_username, BOT_USERNAME)

    def test_invalid_bot_id_raises(self):
        with self.assertRaises(ConfigError):
            load_config({TOKEN_ENV: FAKE_TOKEN, USERS_ENV: str(USER_ID),
                         BOT_ID_ENV: "not-an-int"})

    def test_repr_omits_token(self):
        cfg = load_config({TOKEN_ENV: FAKE_TOKEN, USERS_ENV: str(USER_ID)})
        self.assertNotIn(FAKE_TOKEN, repr(cfg))


class TestCredentialDir(unittest.TestCase):
    """Production token source: systemd LoadCredentialEncrypted directory."""

    def test_reads_from_credential_dir_preferentially(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, CREDENTIAL_FILENAME), "w") as fh:
                fh.write(FAKE_TOKEN + "\n")
            env = {CREDENTIALS_DIR_ENV: d, TOKEN_ENV: "999999999:" + "B" * 35}
            self.assertEqual(resolve_token(env), FAKE_TOKEN)
            cfg = load_config({**env, USERS_ENV: str(USER_ID)})
            self.assertEqual(cfg.token, FAKE_TOKEN)

    def test_falls_back_to_env_when_credential_absent(self):
        with tempfile.TemporaryDirectory() as d:
            env = {CREDENTIALS_DIR_ENV: d, TOKEN_ENV: FAKE_TOKEN,
                   USERS_ENV: str(USER_ID)}
            self.assertEqual(resolve_token(env), FAKE_TOKEN)

    def test_missing_credential_dir_falls_back(self):
        env = {CREDENTIALS_DIR_ENV: "/nonexistent/dir", TOKEN_ENV: FAKE_TOKEN}
        self.assertEqual(resolve_token(env), FAKE_TOKEN)


class TestGithubToken(unittest.TestCase):
    """Optional GitHub token: same resolution order as the bot token, and it
    must never appear in a repr (or anywhere a log could capture)."""

    def test_absent_is_none_and_private_repos_stay_refused(self):
        cfg = load_config({TOKEN_ENV: FAKE_TOKEN, USERS_ENV: str(USER_ID)})
        self.assertIsNone(cfg.github_token)

    def test_reads_from_env(self):
        cfg = load_config({TOKEN_ENV: FAKE_TOKEN, USERS_ENV: str(USER_ID),
                           GITHUB_TOKEN_ENV: FAKE_GITHUB_TOKEN})
        self.assertEqual(cfg.github_token, FAKE_GITHUB_TOKEN)

    def test_credential_dir_preferred_over_env(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, GITHUB_CREDENTIAL_FILENAME), "w") as fh:
                fh.write(FAKE_GITHUB_TOKEN + "\n")
            env = {CREDENTIALS_DIR_ENV: d, GITHUB_TOKEN_ENV: "ghp_" + "Z" * 36}
            self.assertEqual(resolve_github_token(env), FAKE_GITHUB_TOKEN)

    def test_repr_omits_github_token(self):
        cfg = load_config({TOKEN_ENV: FAKE_TOKEN, USERS_ENV: str(USER_ID),
                           GITHUB_TOKEN_ENV: FAKE_GITHUB_TOKEN})
        self.assertNotIn(FAKE_GITHUB_TOKEN, repr(cfg))


class TestOpenDms(unittest.TestCase):
    """`*` in DEVIN_ALLOWED_USERS opens private chats to anyone.

    It is the owner's switch for a bot that serves the public from its DMs. It
    must be incapable of opening a room, and it must not be reachable by an
    empty or malformed allowlist.
    """

    def _cfg(self, users):
        return load_config({TOKEN_ENV: FAKE_TOKEN, USERS_ENV: users})

    def test_star_opens_dms_with_nobody_named(self):
        cfg = self._cfg("*")
        self.assertTrue(cfg.open_dms)
        self.assertEqual(cfg.allowed_user_ids, ())

    def test_star_alongside_the_owner_keeps_the_id(self):
        cfg = self._cfg("424242 *")
        self.assertTrue(cfg.open_dms)
        self.assertEqual(cfg.allowed_user_ids, (424242,))

    def test_without_the_star_dms_stay_closed(self):
        self.assertFalse(self._cfg("424242").open_dms)

    def test_an_empty_allowlist_still_refuses_to_start(self):
        for empty in ("", "   ", ","):
            with self.assertRaises(ConfigError):
                self._cfg(empty)

    def test_open_dms_are_reported_in_the_repr(self):
        self.assertIn("open_dms=True", repr(self._cfg("*")))


if __name__ == "__main__":
    unittest.main()
