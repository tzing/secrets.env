# Configuration file for the Sphinx documentation builder.
#
# For the full list of built-in configuration values, see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

import datetime
import importlib.metadata

# -- Project information -----------------------------------------------------

this_year = datetime.date.today().year

project = "secrets.env"
copyright = f"{this_year}, tzing"
author = "tzing"
release = importlib.metadata.version(project)


# -- General configuration ---------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#general-configuration

extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.intersphinx",
    "sphinx.ext.napoleon",
    "sphinx_design",
]

intersphinx_mapping = {
    "python": ("https://docs.python.org/3", None),
    "click": ("https://click.palletsprojects.com/", None),
}

templates_path = ["_templates"]
exclude_patterns = []

add_module_names = False

# -- Options for HTML output -------------------------------------------------

html_theme = "furo"

html_static_path = ["_static"]
html_css_files = [
    "css/tab.css",
]
