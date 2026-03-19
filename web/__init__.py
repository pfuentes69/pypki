import os
from flask import Flask, redirect, render_template
from flask_cors import CORS

from pypki import logger

_PAGES = {
    'index.html':               ('dashboard',           'PyPKI – Dashboard'),
    'certificate_list.html':    ('certificate_list',    'Certificate List'),
    'certificate_details.html': ('certificate_list',    'Certificate Details'),
    'certificate_request.html': ('certificate_request', 'Request Certificate'),
    'cas_and_crls.html':        ('cas_and_crls',        'CAs & CRL'),
    'ca_details.html':          ('cas_and_crls',        'CA Details'),
    'ca_add.html':              ('cas_and_crls',        'Add New CA'),
    'ca_editor.html':           ('cas_and_crls',        'Edit CA'),
    'template_list.html':       ('template_list',       'Certificate Templates'),
    'template_editor.html':     ('template_list',       'Template Editor'),
    'est_list.html':            ('est_list',            'EST Config'),
    'est_editor.html':          ('est_list',            'EST Endpoint Editor'),
    'est_test.html':            ('est_test',            'EST Test'),
    'csr_tool.html':            ('csr_tool',            'CSR Tool'),
    'kms_keygen.html':          ('kms_keygen',          'KMS Key Generation'),
    'users_list.html':          ('users_list',          'Users'),
    'user_editor.html':         ('users_list',          'User Editor'),
    'ocsp_list.html':           ('ocsp_list',            'OCSP Responders'),
    'ocsp_add.html':            ('ocsp_list',            'Add OCSP Responder'),
    'ocsp_details.html':        ('ocsp_list',            'OCSP Responder Details'),
    'ocsp_editor.html':         ('ocsp_list',            'OCSP Responder Editor'),
    'audit_logs.html':          ('audit_logs',          'Audit Logs'),
    'app_logs.html':            ('app_logs',            'App Logs'),
    'tools.html':               ('tools',               'Tools'),
    'login.html':               (None,                  'PyPKI – Sign In'),
}


def create_app():
    logger.info("Flask App creation")

    # Flask discovers web/static/ and web/templates/ automatically (same package dir)
    app = Flask(__name__)
    CORS(app)

    @app.route('/')
    def root():
        return redirect('/index.html')

    @app.route('/<page>.html')
    def serve_page(page):
        filename = page + '.html'
        if filename not in _PAGES:
            return 'Not Found', 404
        active_nav, title = _PAGES[filename]
        return render_template(filename,
                               active_nav=active_nav,
                               api_base='/api',
                               est_base='/.well-known/est',
                               title=title)

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
