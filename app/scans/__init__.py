from flask import Blueprint

bp = Blueprint('scans', __name__)

from app.scans import routes