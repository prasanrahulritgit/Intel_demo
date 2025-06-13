from flask_sqlalchemy import SQLAlchemy
import re
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
db = SQLAlchemy()

from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import re
from datetime import datetime

db = SQLAlchemy()

def validate_ip(ip):
    """Improved IPv4 validation"""
    if not ip:  # Allow empty values
        return True
    pattern = r'^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    return re.match(pattern, ip) is not None

class Device(db.Model):
    __tablename__ = 'devices'
    
    device_id = db.Column(db.String(50), primary_key=True)
    rutomatrix_ip = db.Column(db.String(15))
    ctp1_ip = db.Column(db.String(15))
    ctp2_ip = db.Column(db.String(15))
    ctp3_ip = db.Column(db.String(15))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __init__(self, **kwargs):
        super(Device, self).__init__(**kwargs)
        self.validate_ips()
    
    def validate_ips(self):
        for field in ['rutomatrix_ip', 'ctp1_ip', 'ctp2_ip', 'ctp3_ip']:
            ip = getattr(self, field)
            if ip and not validate_ip(ip):
                raise ValueError(f"Invalid IP format in {field}")
    
    def to_dict(self):
        return {
            'device_id': self.device_id,
            'rutomatrix_ip': self.rutomatrix_ip,
            'ctp1_ip': self.ctp1_ip,
            'ctp2_ip': self.ctp2_ip,
            'ctp3_ip': self.ctp3_ip,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }
    
    def __repr__(self):
        return f"<Device {self.device_id}>"
    


class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    user_name = db.Column(db.String(80), unique=True, nullable=False)
    user_ip = db.Column(db.String(15))
    password_hash = db.Column(db.String(128), nullable=False)  # NOT 'password'
    role = db.Column(db.String(20), default='user')
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    
    # Password hashing methods
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    # For Flask-Login integration
    @property
    def is_authenticated(self):
        return True
    
    @property
    def is_anonymous(self):
        return False
    
    def get_id(self):
        return str(self.id)
    
    def to_dict(self):
        return {
            'id': self.id,
            'user_name': self.user_name,
            'user_ip': self.user_ip,
            'role': self.role,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }
    
    def __repr__(self):
        return f'<User {self.user_name}>'

class Reservation(db.Model):
    __tablename__ = 'reservations'
    
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.String(50), db.ForeignKey('devices.device_id'))
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    ip_type = db.Column(db.String(20))  # 'rutomatrix', 'ctp1', 'ctp2', 'ctp3'
    start_time = db.Column(db.DateTime, nullable=False)
    end_time = db.Column(db.DateTime, nullable=False)
    
    device = db.relationship('Device', backref='reservations')
    user = db.relationship('User', backref='reservations')
    
    def __repr__(self):
        return f'<Reservation {self.id} for device {self.device_id}>'