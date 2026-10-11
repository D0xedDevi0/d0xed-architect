"""Config: env-only token, fail-closed allowlists, no secret leakage."""
import os
import tempfile
import unittest

from devin.config import (BOT_ID_ENV, BOT_USERNAME_ENV, CREDENTIALS_DIR_ENV,
                          CREDENTIAL_FILENAME, GROUPS_ENV, TOKEN_ENV, USERS_ENV,
                          Config, ConfigError, load_config, resolve_token)
from tests.devin_fixtures import (BOT_ID, BOT_USERNAME, FAKE_TOKEN, GROUP_ID,
                                  USER_ID)


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


if __name__ == "__main__":
    unittest.main()
