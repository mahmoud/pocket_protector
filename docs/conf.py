# Configuration file for the Sphinx documentation builder.

import os
import sys

# Make pocket_protector importable for autodoc
sys.path.insert(0, os.path.abspath('..'))

from pocket_protector import __version__

# -- Project information -----------------------------------------------------

project = 'PocketProtector'
copyright = '2018-2026, Kurt Rose and Mahmoud Hashemi'
author = 'Kurt Rose, Mahmoud Hashemi'
version = __version__
release = __version__

# -- General configuration ---------------------------------------------------

extensions = [
    'sphinx.ext.autodoc',
    'sphinx.ext.intersphinx',
    'sphinx.ext.ifconfig',
    'sphinx.ext.viewcode',
    'sphinx.ext.napoleon',
    'sphinx.ext.autodoc.typehints',
]

templates_path = ['_templates']
exclude_patterns = ['_build', 'Thumbs.db', '.DS_Store']
source_suffix = '.rst'
master_doc = 'index'

# -- Options for HTML output -------------------------------------------------

html_theme = 'sphinx_rtd_theme'
html_static_path = []

# -- Extension configuration -------------------------------------------------

# Autodoc
autodoc_member_order = 'bysource'
autodoc_default_options = {
    'undoc-members': False,
}

# Intersphinx
intersphinx_mapping = {
    'python': ('https://docs.python.org/3', None),
}

# Napoleon (Google/NumPy style docstrings)
napoleon_google_docstring = True
napoleon_numpy_docstring = False
