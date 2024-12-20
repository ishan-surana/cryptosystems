import sys
from pathlib import Path
sys.path.insert(0, str(Path('..').resolve()))

# Configuration file for the Sphinx documentation builder.
#
# For the full list of built-in configuration values, see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Project information -----------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#project-information

project = 'cryptosystems'
version = '1.0.0'
release = '1.0.0'
copyright = '2024, Ishan Surana'
author = 'Ishan Surana'
repo_url = 'https://github.com/ishan-surana/cryptosystems/'

# -- General configuration ---------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#general-configuration

extensions = [
    'sphinx.ext.duration',
    'sphinx.ext.doctest',
    'sphinx.ext.autodoc',
    'sphinx.ext.autosummary',
    'sphinx.ext.intersphinx',
    'sphinx_design',
    'sphinx_copybutton',
    'm2r2',
    # 'myst_parser',
]
myst_enable_extensions = ["colon_fence"]

source_suffix = {
    '.rst': 'restructuredtext',
    '.txt': 'markdown',
    '.md': 'markdown',
}

intersphinx_mapping = {
    'python': ('https://docs.python.org/3/', None),
    'sphinx': ('https://www.sphinx-doc.org/en/master/', None),
}
intersphinx_disabled_domains = ['std']

templates_path = ['_templates']

exclude_patterns = []



# -- Options for HTML output -------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#options-for-html-output

# html_theme = 'pydata_sphinx_theme'
# html_static_path = ['_static']
html_theme = 'sphinx_book_theme'

# html_sidebars = {
#     "introduction": []
# }

# html_theme_options = {
#     "header_links_before_dropdown": 6,
#     "navbar_align": "content",
#     # "logo": {
#     #     'image_light': 'logo.png',
#     #     'image_dark': 'logo.png',
#     # }
# }

html_theme_options = {
    "repository_url": "https://github.com/ishan-surana/cryptosystems",
    "use_repository_button": True,
    "use_source_button": True,
    "path_to_docs": "docs",
    "icon_links": [
        {
            "name": "GitHub",
            "url": "https://github.com/ishan-surana/cryptosystems",
            "icon": "fa-brands fa-github",
        },
        {
            "name": "PyPI",
            "url": "https://pypi.org/project/cryptosystems/",
            "icon": "https://img.shields.io/pypi/v/cryptosystems?label=latest+release&color=blue",
            "type": "url",
        },
    ],
}

html_logo = 'https://ishan-surana.github.io/images/cryptosystems.png'

# -- Options for EPUB output
epub_show_urls = 'footnote'