import os

import click
from flask_migrate import Migrate, upgrade

from app import create_app, db
from app.models import (
    ApiToken,
    AuditEvent,
    Comment,
    PasswordHistory,
    Permission,
    Post,
    Role,
    User,
    UserSession,
)

app = create_app(os.getenv("FLASK_CONFIG") or "development")
migrate = Migrate(app, db)


@app.shell_context_processor
def make_shell_context():
    return dict(
        db=db,
        User=User,
        Role=Role,
        Post=Post,
        Comment=Comment,
        Permission=Permission,
        AuditEvent=AuditEvent,
        PasswordHistory=PasswordHistory,
        UserSession=UserSession,
        ApiToken=ApiToken,
    )


@app.cli.command("init-db")
def init_db_command():
    """Initialize database tables and default roles."""
    click.echo("Running database migrations...")
    upgrade()
    click.echo("Inserting default roles...")
    Role.insert_roles()
    click.echo("Database initialization complete.")


@app.cli.command("seed-admin")
@click.option(
    "--email", prompt=True, default=lambda: app.config["BLOGG_ADMIN"], help="Admin email address."
)
@click.option("--username", prompt=True, default="admin", help="Admin username.")
@click.option(
    "--password", prompt=True, hide_input=True, confirmation_prompt=True, help="Admin password."
)
def seed_admin_command(email, username, password):
    """Create or update an active Administrator account."""
    Role.insert_roles()
    admin_role = Role.query.filter_by(name="Administrator").first()
    user = User.query.filter((User.email == email) | (User.username == username)).first()
    if user is None:
        user = User(
            email=email,
            username=username,
            password=password,
            confirmed=True,
            role=admin_role,
            name=username.capitalize(),
        )
        db.session.add(user)
        action = "Created"
    else:
        user.email = email
        user.username = username
        user.password = password
        user.confirmed = True
        user.role = admin_role
        action = "Updated"
    db.session.commit()
    click.echo(f"Successfully {action.lower()} administrator: {username} ({email})")


@app.cli.command("seed-data")
@click.option("--users", default=10, help="Number of fake users to generate.")
@click.option("--posts", default=20, help="Number of fake posts to generate.")
def seed_data_command(users, posts):
    """Generate fake users and posts for testing."""
    from app import fake

    Role.insert_roles()
    click.echo(f"Generating {users} fake users...")
    fake.users(users)
    click.echo(f"Generating {posts} fake posts...")
    fake.posts(posts)
    click.echo("Data seeding complete.")


@app.cli.command("test")
@click.argument("test_args", nargs=-1)
def test_command(test_args):
    """Run unit tests using pytest."""
    import pytest

    args = list(test_args) if test_args else ["tests"]
    raise SystemExit(pytest.main(args))


@app.cli.command("test-cov")
@click.argument("test_args", nargs=-1)
def test_cov_command(test_args):
    """Run unit tests with code coverage."""
    import pytest

    args = ["--cov=app", "--cov-report=term-missing"] + list(test_args)
    raise SystemExit(pytest.main(args))


@app.cli.command("lint")
def lint_command():
    """Run ruff linter and formatting checks."""
    import subprocess

    click.echo("Running ruff check...")
    check = subprocess.run(["ruff", "check", "app", "tests", "blogg.py", "config.py"])
    click.echo("Running ruff format check...")
    fmt = subprocess.run(["ruff", "format", "--check", "app", "tests", "blogg.py", "config.py"])
    if check.returncode != 0 or fmt.returncode != 0:
        raise SystemExit(1)
    click.echo("Linting checks passed!")


@app.cli.command("lint-fix")
def lint_fix_command():
    """Run ruff auto-fix and formatting."""
    import subprocess

    click.echo("Fixing lint issues...")
    subprocess.run(["ruff", "check", "--fix", "app", "tests", "blogg.py", "config.py"])
    click.echo("Formatting code...")
    subprocess.run(["ruff", "format", "app", "tests", "blogg.py", "config.py"])
    click.echo("Ruff auto-fix and formatting complete.")


if __name__ == "__main__":
    app.run()
