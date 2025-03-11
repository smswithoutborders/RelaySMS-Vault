"""
This program is free software: you can redistribute it under the terms
of the GNU General Public License, v. 3.0. If a copy of the GNU General
Public License was not distributed with this file, see <https://www.gnu.org/licenses/>.
"""

from flask import Flask
from src.api_v3 import v3_blueprint

app = Flask(__name__)

app.register_blueprint(v3_blueprint)
