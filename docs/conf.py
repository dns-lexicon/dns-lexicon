from os.path import abspath, dirname, join

import tomllib

import sys
from pathlib import Path

sys.path.insert(0, str(Path('..', 'src').resolve()))

with open(join(dirname(dirname(abspath(__file__))), "pyproject.toml"), "rb") as file_h:
    metadata = tomllib.load(file_h)["project"]

master_doc = 'index'
project = "DNS-Lexicon"
version = release = metadata["version"]

extensions = [
    "myst_parser",
]

# myst_enable_extensions = [
#     "deflist",      # definition lists
#     "colon_fence",  # nicer ::: blocks
#     "substitution", # |var| equivalents
#     "linkify",      # auto-link URLs
# ]

html_theme = "piccolo_theme"
html_theme_options = {
    "source_url": 'https://github.com/dns-lexicon/dns-lexicon/'
}

html_static_path = [
    "_static",
]
html_css_files = [
    "custom.css",
]
