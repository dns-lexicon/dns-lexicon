import sys
import tomllib
from os.path import abspath, dirname, join
from pathlib import Path

sys.path.insert(0, str(Path("..", "src").resolve()))

with open(join(dirname(dirname(abspath(__file__))), "pyproject.toml"), "rb") as file_h:
    metadata = tomllib.load(file_h)["project"]

master_doc = "index"
project = "DNS-Lexicon"
version = release = metadata["version"]

extensions = [
    "sphinx_mdinclude",
    "sphinx.ext.autodoc",
]

html_theme = "piccolo_theme"
html_theme_options = {"source_url": "https://github.com/dns-lexicon/dns-lexicon/"}

html_static_path = [
    "_static",
]
html_css_files = [
    "custom.css",
]
