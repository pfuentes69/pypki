from flask import Flask

def create_app():
    app = Flask(__name__)

    # Register Blueprints
    from .routes.main_routes import bp as main_bp
    from .routes.est_routes import bp as est_bp

    app.register_blueprint(main_bp, url_prefix='/')
    app.register_blueprint(est_bp, url_prefix='/.well-known')

    return app