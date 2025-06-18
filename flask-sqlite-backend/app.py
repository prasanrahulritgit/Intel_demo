
from flask import Flask
from flask_login import LoginManager
from flask_migrate import Migrate
from models import db, User
from datetime import datetime
from werkzeug.security import generate_password_hash
from apscheduler.schedulers.background import BackgroundScheduler

from scheduler import init_scheduler

def create_app():
    app = Flask(__name__)
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///device_list.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.secret_key = 'your-secret-key-here'

    # Initialize extensions
    db.init_app(app)
    login_manager = LoginManager(app)
    login_manager.login_view = 'auth.login'
    migrate = Migrate(app, db)
    

    login_manager.init_app(app)
    init_scheduler(app)

    # Register blueprints
    from routes.auth_routes import auth_bp
    from routes.device_routes import device_bp
    from routes.user_routes import user_bp
    from routes.reservation_routes import reservation_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(device_bp)
    app.register_blueprint(user_bp)
    app.register_blueprint(reservation_bp)

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    # Create tables and admin user
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(user_name='admin').first():
            admin = User(
                user_name='admin',
                user_ip='127.0.0.1',
                password_hash=generate_password_hash('admin123'),
                role='admin',
                created_at=datetime.utcnow()
            )
            db.session.add(admin)
            db.session.commit()

    return app

if __name__ == '__main__':
    app = create_app()
    app.run(host='0.0.0.0', port=5000, debug=True)