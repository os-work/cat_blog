import os
import sys
import logging
import logging.config
import yaml

from flask import Flask, send_from_directory
from flask_debugtoolbar import DebugToolbarExtension
from dynaconf import FlaskDynaconf

from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_bcrypt import Bcrypt
from pathlib import Path


login_manager = LoginManager()
login_manager.login_view = "auth_bp.login"
Flask_bcrypt = Bcrypt()
db = SQLAlchemy()

def create_app():
    app = Flask(__name__)

    @app.route("/favicon.ico")
    def favicon():
        return send_from_directory(
            os.path.join(app.root_path, "static"),
            "favicon.ico",
            mimetype="image/vnd.microsoft.icon",
        )

    with app.app_context():
        os.environ["ROOT_PATH_FOR_DYNACONF"] = app.root_path

        # Initialize Dynaconf explicitly
        dynaconf = FlaskDynaconf(app, settings_files=["secrets.toml"])

        # Ensure SECRET_KEY is loaded properly
        if "SECRET_KEY" not in app.config or not app.config["SECRET_KEY"]:
            raise ValueError("SECRET_KEY is missing! Ensure it's set in secrets.toml")

        # Adjust logging
        _configure_logging(app, dynaconf)

        # Initialize login manager
        login_manager.init_app(app)
        # Initialize Flask-Bcrypt
        Flask_bcrypt.init_app(app)
        # Initialize SQLAlchemy
        db.init_app(app)

        # Initialize DebugToolbarExtension
        toolbar = DebugToolbarExtension(app)

        # Register Flask blueprints
        from . import intro
        from . import auth
        app.register_blueprint(intro.intro_bp)
        app.register_blueprint(auth.auth_bp)

        # Create the database tables if they don't exist
        db.create_all()

        return app

# Configure logging for the application
def _configure_logging(app, dynaconf):
    # Get the path to the logging configuration file
    logging_config_path = Path(app.root_path).parent / "logging_config.yaml"

    if not logging_config_path.exists():
        raise FileNotFoundError(f"Logging config file not found: {logging_config_path}")

    # Load the logging configuration from the YAML file
    with open(logging_config_path, "r") as fh:
        try:
            logging_config = yaml.safe_load(fh)
        except yaml.YAMLError as e:
            raise ValueError(f"Error parsing logging config: {e}")

    # Retrieve logging level from Dynaconf settings
    env_logging_level = dynaconf.settings.get("LOGGING_LEVEL", "INFO").upper()
    logging_level = logging.DEBUG if env_logging_level == "DEBUG" else logging.INFO

    # Update logging config dynamically
    logging_config["handlers"]["console"]["level"] = logging_level
    logging_config["loggers"][""]["level"] = logging_level

    # Apply the logging configuration
    logging.config.dictConfig(logging_config)

    # Log the current logging level
    logging.getLogger(__name__).info(f"Logging configured. Level: {env_logging_level}")
