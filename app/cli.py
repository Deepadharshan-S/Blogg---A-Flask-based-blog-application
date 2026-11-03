"""App-factory CLI commands.

Commands registered here belong to the application itself rather than the
``blogg.py`` entry point, so every app instance (development, production and
the test runner) exposes them.
"""

import click


def register_cli_commands(app):
    @app.cli.command("prune-logs")
    def prune_logs_command():
        """Delete audit and access records older than their retention windows.

        Retention is set with BLOGG_AUDIT_RETENTION_DAYS and
        BLOGG_ACCESS_LOG_RETENTION_DAYS (0 keeps everything, the default).
        The pruning itself is written to the audit trail.
        """
        from .security import prune_expired_logs

        counts = prune_expired_logs()
        click.echo(
            f"Pruned {counts['audit_events']} audit event(s) and "
            f"{counts['access_logs']} access record(s)."
        )
        click.echo(
            f"Retention: audit={app.config['BLOGG_AUDIT_RETENTION_DAYS']}d, "
            f"access={app.config['BLOGG_ACCESS_LOG_RETENTION_DAYS']}d (0 = keep forever)"
        )

    @app.cli.command("migrate-mfa-secrets")
    def migrate_mfa_secrets_command():
        """Encrypt existing unencrypted TOTP/MFA secrets at rest.

        Scans users with plaintext secrets and encrypts them using the configured
        BLOGG_MFA_ENCRYPTION_KEY. Safe to run multiple times (idempotent).
        """
        from . import db
        from .crypto import encrypt_mfa_secret, is_encrypted_secret
        from .models import User

        users = User.query.filter(User._mfa_secret.isnot(None)).all()
        migrated = 0
        skipped = 0

        for user in users:
            raw_secret = user._mfa_secret
            if raw_secret and not is_encrypted_secret(raw_secret):
                user._mfa_secret = encrypt_mfa_secret(raw_secret)
                db.session.add(user)
                migrated += 1
            else:
                skipped += 1

        db.session.commit()
        click.echo(
            f"MFA secret migration complete: {migrated} secret(s) encrypted, "
            f"{skipped} already encrypted/empty."
        )

    @app.cli.command("rotate-mfa-keys")
    def rotate_mfa_keys_command():
        """Re-encrypt all MFA secrets with the primary key.

        When rotating keys, configure BLOGG_MFA_ENCRYPTION_KEY="<new_primary_key>,<old_key>"
        and run this command to re-encrypt all stored secrets with the new primary key.
        """
        from . import db
        from .crypto import is_encrypted_secret, rotate_mfa_secret
        from .models import User

        users = User.query.filter(User._mfa_secret.isnot(None)).all()
        rotated = 0
        skipped = 0

        for user in users:
            raw_secret = user._mfa_secret
            if raw_secret and is_encrypted_secret(raw_secret):
                new_ciphertext = rotate_mfa_secret(raw_secret)
                if new_ciphertext != raw_secret:
                    user._mfa_secret = new_ciphertext
                    db.session.add(user)
                    rotated += 1
                else:
                    skipped += 1
            else:
                skipped += 1

        db.session.commit()
        click.echo(
            f"MFA secret rotation complete: {rotated} secret(s) re-encrypted, {skipped} skipped."
        )
