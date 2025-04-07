from logging import getLogger
from flask import render_template
from datetime import datetime
from random import sample

from . import intro_bp


class PageVisit:
    COUNT = 0

    def counts(self):
        PageVisit.COUNT += 1
        return PageVisit.COUNT


class BannerColors:
    COLORS = [
        "lightcoral",
        "salmon",
        "red",
        "firebrick",
        "pink",
        "gold",
        "yellow",
        "khaki",
        "darkkhaki",
        "violet",
        "blue",
        "purple",
        "indigo",
        "greenyellow",
        "lime",
        "green",
        "olive",
        "darkcyan",
        "aqua",
        "skyblue",
        "tan",
        "sienna",
        "gray",
        "silver",
    ]

    def get_colors(self):
        return sample(BannerColors.COLORS, 5)


logger = getLogger(__name__)


### ENDPOINTS
@intro_bp.route("/")
def home():
    logger.debug("rendering home page")
    return render_template(
        "index.html",
        now=datetime.now(),
        page_visit=PageVisit(),
        banner_colors=BannerColors().get_colors(),
    )


@intro_bp.route("/about")
def about():
    logger.debug("rendering about page")
    return render_template("about.html")