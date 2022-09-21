# Configuration file for the Sphinx documentation builder.
#
# For the full list of built-in configuration values, see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

import datetime
import pathlib
import sys

docdir = pathlib.Path(__file__).resolve().parent
repodir = docdir.parent
sys.path.insert(0, str(repodir))

import secrets_env


# -- Project information -----------------------------------------------------

this_year = datetime.date.today().year

project = "secrets.env"
copyright = f"{this_year}, tzing"
author = "tzing"
version = secrets_env.__version__


# -- General configuration ---------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#general-configuration

extensions = []

templates_path = ["_templates"]
exclude_patterns = []


# -- Options for HTML output -------------------------------------------------

html_theme = "pydata_sphinx_theme"
html_static_path = ["_static"]

html_theme_options = {
    "icon_links": [
        {
            "name": "GitHub",
            "url": "https://github.com/tzing/secrets.env",
            "icon": "fab fa-github-square",
        }
    ],
    "show_toc_level": 1,
}
