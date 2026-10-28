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
