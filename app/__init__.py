import os
import sys
import logging
import logging.config
import yaml

from flask import Flask
from flask_debugtoolbar import DebugToolbarExtension
from dynaconf import FlaskDynaconf

from pathlib import Path


def create_app():
    app = Flask(__name__)

    with app.app_context():
        os.environ["ROOT_PATH_FOR_DYNACONF"] = app.root_path

        # Initialize Dynaconf explicitly
        dynaconf = FlaskDynaconf(app, settings_files=["secrets.toml"])

        # Ensure SECRET_KEY is loaded properly
        if "SECRET_KEY" not in app.config or not app.config["SECRET_KEY"]:
            raise ValueError("SECRET_KEY is missing! Ensure it's set in secrets.toml")

        _configure_logging(app, dynaconf)

        toolbar = DebugToolbarExtension(app)

        from . import intro

        app.register_blueprint(intro.intro_bp)

        return app


def _configure_logging(app, dynaconf):
    logging_config_path = Path(app.root_path).parent / "logging_config.yaml"

    if not logging_config_path.exists():
        raise FileNotFoundError(f"Logging config file not found: {logging_config_path}")

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

    logging.getLogger(__name__).info(f"Logging configured. Level: {env_logging_level}")
