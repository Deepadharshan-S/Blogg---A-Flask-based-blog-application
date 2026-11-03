"""Tests for MFA/TOTP secret encryption at rest (BLOGG-SEC-015).

Verifies:
- Authenticated Fernet encryption of TOTP secrets in the database.
- Key separation: BLOGG_MFA_ENCRYPTION_KEY != SECRET_KEY.
- Transparent backward compatibility for legacy plaintext secrets.
- In-place migration CLI (flask migrate-mfa-secrets).
- Seamless MultiFernet key rotation CLI (flask rotate-mfa-keys).
- Decryption failure handling (wrong key or corrupted ciphertext).
- Information exposure prevention (no secrets in JSON/admin serialization).
"""

from unittest.mock import patch

import pyotp
from cryptography.fernet import Fernet

from app import create_app, db
from app.crypto import is_encrypted_secret
from tests.iam_base import IAMTestCase


class MFAEncryptionTestCase(IAMTestCase):
    def setUp(self):
        super().setUp()
        self.user = self.make_user()

    def test_mfa_secret_encrypted_at_rest(self):
        """Ensure mfa_secret is encrypted when stored in the database."""
        plaintext_secret = self.user.generate_mfa_secret()
        db.session.add(self.user)
        db.session.commit()

        # The underlying database column contains the Fernet ciphertext
        raw_db_value = self.user._mfa_secret
        self.assertIsNotNone(raw_db_value)
        self.assertTrue(is_encrypted_secret(raw_db_value))
        self.assertTrue(raw_db_value.startswith("gAAAAA"))
        self.assertNotEqual(raw_db_value, plaintext_secret)

        # The model property returns the decrypted plaintext Base32 secret
        self.assertEqual(self.user.mfa_secret, plaintext_secret)

        # TOTP verification and provisioning URI function seamlessly
        totp = pyotp.TOTP(plaintext_secret)
        self.assertTrue(self.user.verify_mfa_code(totp.now()))
        self.assertIn(plaintext_secret, self.user.mfa_provisioning_uri())

    def test_legacy_plaintext_secret_transparent_read(self):
        """Ensure legacy unencrypted Base32 secrets can be read without errors."""
        legacy_secret = "JBSWY3DPEHPK3PXP"
        # Directly bypass property setter to simulate legacy database row
        self.user._mfa_secret = legacy_secret
        db.session.add(self.user)
        db.session.commit()

        # Reading through property returns plaintext secret
        self.assertEqual(self.user.mfa_secret, legacy_secret)
        totp = pyotp.TOTP(legacy_secret)
        self.assertTrue(self.user.verify_mfa_code(totp.now()))

    def test_migrate_mfa_secrets_cli(self):
        """Ensure 'flask migrate-mfa-secrets' encrypts unencrypted secrets idempotently."""
        runner = self.app.test_cli_runner()

        # Seed users: one legacy plaintext, one already encrypted, one without MFA
        u1 = self.make_user(username="legacy_user", email="legacy@example.com")
        u1._mfa_secret = "JBSWY3DPEHPK3PXP"
        u2 = self.make_user(username="encrypted_user", email="enc@example.com")
        u2.generate_mfa_secret()
        u3 = self.make_user(username="nomfa_user", email="nomfa@example.com")
        db.session.add_all([u1, u2, u3])
        db.session.commit()

        u2_raw_before = u2._mfa_secret

        result = runner.invoke(args=["migrate-mfa-secrets"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("1 secret(s) encrypted", result.output)

        # u1 is now encrypted
        db.session.refresh(u1)
        self.assertTrue(is_encrypted_secret(u1._mfa_secret))
        self.assertEqual(u1.mfa_secret, "JBSWY3DPEHPK3PXP")

        # u2 is unchanged
        db.session.refresh(u2)
        self.assertEqual(u2._mfa_secret, u2_raw_before)

        # Running again is an idempotent no-op
        result2 = runner.invoke(args=["migrate-mfa-secrets"])
        self.assertEqual(result2.exit_code, 0)
        self.assertIn("0 secret(s) encrypted", result2.output)

    def test_key_rotation_cli(self):
        """Ensure 'flask rotate-mfa-keys' re-encrypts tokens with primary key."""
        old_key = Fernet.generate_key().decode()
        new_key = Fernet.generate_key().decode()

        # Set up user encrypted with old_key
        with patch.dict(self.app.config, {"BLOGG_MFA_ENCRYPTION_KEY": old_key}):
            plaintext = self.user.generate_mfa_secret()
            db.session.add(self.user)
            db.session.commit()
            old_ciphertext = self.user._mfa_secret

        # Configure MultiFernet with new_key as primary, old_key as secondary
        dual_keys = f"{new_key},{old_key}"
        with patch.dict(self.app.config, {"BLOGG_MFA_ENCRYPTION_KEY": dual_keys}):
            # User can still decrypt prior to running rotation
            self.assertEqual(self.user.mfa_secret, plaintext)

            runner = self.app.test_cli_runner()
            result = runner.invoke(args=["rotate-mfa-keys"])
            self.assertEqual(result.exit_code, 0)
            self.assertIn("1 secret(s) re-encrypted", result.output)

            db.session.refresh(self.user)
            new_ciphertext = self.user._mfa_secret
            self.assertNotEqual(old_ciphertext, new_ciphertext)

        # User can now be decrypted using ONLY new_key
        with patch.dict(self.app.config, {"BLOGG_MFA_ENCRYPTION_KEY": new_key}):
            self.assertEqual(self.user.mfa_secret, plaintext)

    def test_decryption_failure_handling(self):
        """Ensure decryption with wrong key returns None and does not crash."""
        self.user.generate_mfa_secret()
        db.session.add(self.user)
        db.session.commit()

        different_key = Fernet.generate_key().decode()
        with patch.dict(self.app.config, {"BLOGG_MFA_ENCRYPTION_KEY": different_key}):
            with patch.object(self.app.logger, "error") as mock_log:
                self.assertIsNone(self.user.mfa_secret)
                self.assertFalse(self.user.verify_mfa_code("123456"))
                mock_log.assert_called()
                self.assertIn("MFA secret decryption failed", mock_log.call_args[0][0])

    def test_key_separation_enforced(self):
        """Ensure config raises RuntimeError if BLOGG_MFA_ENCRYPTION_KEY equals SECRET_KEY."""
        shared_key = Fernet.generate_key().decode()
        with patch.dict(
            "os.environ",
            {"SECRET_KEY": shared_key, "BLOGG_MFA_ENCRYPTION_KEY": shared_key},
            clear=True,
        ):
            with self.assertRaises(RuntimeError) as ctx:
                create_app("development")
            self.assertIn("must NOT be identical to SECRET_KEY", str(ctx.exception))

    def test_mfa_secret_never_exposed_in_json(self):
        """Ensure decrypted mfa_secret is not present in public or admin JSON representations."""
        self.user.generate_mfa_secret()
        self.user.mfa_enabled = True
        db.session.add(self.user)
        db.session.commit()

        public_data = self.user.to_json()
        self.assertNotIn("mfa_secret", public_data)
        self.assertNotIn("_mfa_secret", public_data)

        admin_data = self.user.to_admin_json()
        self.assertNotIn("mfa_secret", admin_data)
        self.assertNotIn("_mfa_secret", admin_data)
        self.assertTrue(admin_data["mfa_enabled"])

    def test_persistent_mfa_key_across_application_restarts(self):
        """SEC-ASSESS-002: Ensure MFA secrets remain decryptable across app restarts when a persistent key is configured."""
        persistent_key = Fernet.generate_key().decode()

        # Step 1: User enrolls in MFA under App 1 with persistent_key
        with patch.dict(self.app.config, {"BLOGG_MFA_ENCRYPTION_KEY": persistent_key}):
            plaintext = self.user.generate_mfa_secret()
            self.user.mfa_enabled = True
            db.session.add(self.user)
            db.session.commit()
            stored_ciphertext = self.user._mfa_secret
            user_id = self.user.id

        # Step 2: Simulate complete app restart with same database and persistent_key
        # Verify that decrypting under the same persistent key succeeds across restarts
        with patch.dict(self.app.config, {"BLOGG_MFA_ENCRYPTION_KEY": persistent_key}):
            refetched_user = db.session.get(self.user.__class__, user_id)
            self.assertEqual(refetched_user._mfa_secret, stored_ciphertext)
            self.assertEqual(refetched_user.mfa_secret, plaintext)
            totp = pyotp.TOTP(plaintext)
            self.assertTrue(refetched_user.verify_mfa_code(totp.now()))

    def test_dev_mode_persists_mfa_key_to_instance_file(self):
        """SEC-ASSESS-002: In development mode, verify key is persisted to instance/.dev_mfa_key and reused."""
        import os
        import tempfile

        with tempfile.TemporaryDirectory() as tmp_dir:
            instance_path = os.path.join(tmp_dir, "instance")
            dev_key_file = os.path.join(instance_path, ".dev_mfa_key")

            # Create mock app configured in DEBUG mode
            from flask import Flask

            from config import Config

            app1 = Flask(__name__, instance_path=instance_path)
            app1.config["DEBUG"] = True
            app1.config["SECRET_KEY"] = "dev-secret-key-123"

            with patch.dict("os.environ", {}, clear=True):
                Config.init_app(app1)

            key1 = app1.config.get("BLOGG_MFA_ENCRYPTION_KEY")
            self.assertIsNotNone(key1)
            self.assertTrue(os.path.isfile(dev_key_file))

            # Simulate restart: create app2 with same instance_path
            app2 = Flask(__name__, instance_path=instance_path)
            app2.config["DEBUG"] = True
            app2.config["SECRET_KEY"] = "dev-secret-key-123"

            with patch.dict("os.environ", {}, clear=True):
                Config.init_app(app2)

            key2 = app2.config.get("BLOGG_MFA_ENCRYPTION_KEY")
            # Must reuse the same key, NOT generate a fresh ephemeral one
            self.assertEqual(key1, key2)
