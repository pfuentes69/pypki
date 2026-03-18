import os
from flask import Flask, redirect
from flask_cors import CORS

from pypki import logger

# Path to the web/html directory (one level up from api/, then into web/html/)
_WEB_ROOT = os.path.join(os.path.dirname(__file__), '..', 'web', 'html')


def create_app():
    logger.info("Flask App creation")

    app = Flask(__name__, static_folder=_WEB_ROOT, static_url_path='')
    CORS(app)

    @app.route('/')
    def index():
        return redirect('/index.html')

    # Register Blueprints
    from .routes.main_routes import bp as main_bp
    from .routes.auth_routes import bp as auth_bp
    from .routes.est_routes import bp as est_bp
    from .routes.ocsp_routes import bp as ocsp_bp

    app.register_blueprint(ocsp_bp, url_prefix='/ocsp')
    app.register_blueprint(auth_bp, url_prefix='/api/auth')
    app.register_blueprint(main_bp, url_prefix='/api')
    app.register_blueprint(est_bp, url_prefix='/.well-known')

    return app