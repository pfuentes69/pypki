from flask import Flask

from pypki import logger


def create_app():
    logger.info("Flask App creation")

    app = Flask(__name__)

    # Register Blueprints
    from .routes.main_routes import bp as main_bp
    from .routes.est_routes import bp as est_bp
    from .routes.ocsp_routes import bp as ocsp_bp

    app.register_blueprint(ocsp_bp, url_prefix='/ocsp')
    app.register_blueprint(main_bp, url_prefix='/api')
    app.register_blueprint(est_bp, url_prefix='/.well-known')

    return app