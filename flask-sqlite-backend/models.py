from flask import app, current_app
from flask_sqlalchemy import SQLAlchemy
import re
from datetime import datetime, timezone
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import TypeDecorator
import pytz


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
    PC_IP = db.Column(db.String(15))
    Rutomatrix_ip = db.Column(db.String(15))
    Pulse1_Ip = db.Column(db.String(15))
    CT1_ip = db.Column(db.String(15))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __init__(self, **kwargs):
        super(Device, self).__init__(**kwargs)
        self.validate_ips()
    
    def validate_ips(self):
        ip_fields = [
            'PC_IP', 'Rutomatrix_ip', 'Pulse1_Ip',
            'CT1_ip' 
        ]
        for field in ip_fields:
            ip = getattr(self, field)
            if ip and not self.validate_ip(ip):
                raise ValueError(f"Invalid IP format in {field}: {ip}")
    
    @staticmethod
    def validate_ip(ip):
        """Validate IPv4 address format using regex for stricter validation"""
        pattern = r'^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        return re.match(pattern, ip) is not None
        
    def to_dict(self):
        """Convert the model instance to a dictionary, including all fields."""
        return {
            'device_id': self.device_id,
            'PC_IP': self.PC_IP,
            'Rutomatrix_ip': self.Rutomatrix_ip,
            'Pulse1_Ip': self.Pulse1_Ip,
            'CT1_ip': self.CT1_ip,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }
    
    def __repr__(self):
        return f"<Device {self.device_id}>"
    


class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    user_name = db.Column(db.String(80), unique=True, nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
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
    
class ISTDateTime(TypeDecorator):
    """Handles datetime conversion for Indian Standard Time (IST)"""
    impl = db.DateTime
    cache_ok = True

    def process_bind_param(self, value, dialect):
        """Convert to naive datetime for storage (assumes input is IST)"""
        if value is None:
            return None
        if isinstance(value, datetime):
            if value.tzinfo is not None:
                # Convert to IST and make naive
                ist = pytz.timezone('Asia/Kolkata')
                return value.astimezone(ist).replace(tzinfo=None)
            return value  # Assume naive datetime is already IST
        raise ValueError("Expected datetime object")

    def process_result_value(self, value, dialect):
        """Attach IST timezone when loading from DB"""
        if value is not None:
            return pytz.timezone('Asia/Kolkata').localize(value)
        return value

class Reservation(db.Model):
    __tablename__ = 'reservations'
    
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.String(50), db.ForeignKey('devices.device_id'))
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    start_time = db.Column(ISTDateTime(), nullable=False)
    end_time = db.Column(ISTDateTime(), nullable=False)
    purpose = db.Column(db.String(200))
    status = db.Column(db.String(20), default='upcoming')  # upcoming, active, expired
    
    device = db.relationship('Device', backref='reservations')
    user = db.relationship('User', backref='reservations')

    def __init__(self, **kwargs):
        """Ensure all datetimes are in IST"""
        ist = pytz.timezone('Asia/Kolkata')
        
        for time_field in ['start_time', 'end_time']:
            if time_field in kwargs:
                if isinstance(kwargs[time_field], str):
                    # Parse string as IST
                    naive_dt = datetime.strptime(kwargs[time_field], '%Y-%m-%dT%H:%M')
                    kwargs[time_field] = ist.localize(naive_dt)
                elif kwargs[time_field].tzinfo is None:
                    # Assume naive is IST
                    kwargs[time_field] = ist.localize(kwargs[time_field])
                else:
                    # Convert to IST
                    kwargs[time_field] = kwargs[time_field].astimezone(ist)
        
        super().__init__(**kwargs)

    @classmethod
    def delete_expired(cls):
        """Delete all expired reservations immediately"""
        try:
            ist = pytz.timezone('Asia/Kolkata')
            current_time = datetime.now(ist)
            
            # Update status first
            expired = cls.query.filter(cls.end_time < current_time).all()
            for res in expired:
                res.status = 'expired'
            
            db.session.commit()
            return len(expired)
        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Failed to update expired: {str(e)}")
            return 0

    def update_status(self):
        """Update status based on current time"""
        ist = pytz.timezone('Asia/Kolkata')
        now = datetime.now(ist)
        
        if self.end_time < now:
            self.status = 'expired'
        elif self.start_time <= now <= self.end_time:
            self.status = 'active'
        else:
            self.status = 'upcoming'

    def can_cancel(self, user):
        """Check if user can cancel this reservation"""
        return (self.user_id == user.id or user.role == 'admin') and self.status == 'upcoming'

    def to_dict(self):
        """Convert reservation to dictionary for API responses"""
        return {
            'id': self.id,
            'device_id': self.device_id,
            'user_id': self.user_id,
            'start_time': self.start_time.isoformat(),
            'end_time': self.end_time.isoformat(),
            'purpose': self.purpose,
            'status': self.status,
            'device': {
                'device_id': self.device.device_id,
                'PC_IP': self.device.PC_IP,
                'Rutomatrix_ip': self.device.Rutomatrix_ip,
                'Pulse1_Ip': self.device.Pulse1_Ip,
                'CT1_ip': self.device.CT1_ip
            },
            'user': {
                'id': self.user.id,
            }
        }

    def __repr__(self):
        return f'<Reservation {self.id} for device {self.device_id}>'
    
    
    
class DeviceUsage(db.Model):
    __tablename__ = 'device_usage_history'
    
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.String(50), db.ForeignKey('devices.device_id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    reservation_id = db.Column(db.Integer, db.ForeignKey('reservations.id'), nullable=True)
    
    # Actual usage times
    actual_start_time = db.Column(ISTDateTime(), nullable=True)  # Changed to nullable=True for upcoming reservations
    actual_end_time = db.Column(ISTDateTime(), nullable=True)
    
    # Additional usage details
    ip_address = db.Column(db.String(45))
    ip_type = db.Column(db.String(20))  
    status = db.Column(db.String(20), default='upcoming')  # Added default status
    termination_reason = db.Column(db.String(100), nullable=True)
    
    # Relationships
    user = db.relationship('User', backref='device_usage', lazy='joined')
    device = db.relationship('Device', backref='usage_history', lazy='joined')
    reservation = db.relationship('Reservation', backref='usage_records', lazy='joined')

    def __init__(self, **kwargs):
        """Initialize with proper status handling"""
        ist = pytz.timezone('Asia/Kolkata')
        
        # Handle time fields
        for time_field in ['actual_start_time', 'actual_end_time']:
            if time_field in kwargs and kwargs[time_field] is not None:
                if isinstance(kwargs[time_field], str):
                    naive_dt = datetime.strptime(kwargs[time_field], '%Y-%m-%dT%H:%M')
                    kwargs[time_field] = ist.localize(naive_dt)
                elif kwargs[time_field].tzinfo is None:
                    kwargs[time_field] = ist.localize(kwargs[time_field])
                else:
                    kwargs[time_field] = kwargs[time_field].astimezone(ist)
        
        super().__init__(**kwargs)
        
        # Set initial status based on times
        self.update_status()

    @property
    def duration(self):
        """Calculate duration in seconds"""
        if self.actual_start_time and self.actual_end_time:
            return (self.actual_end_time - self.actual_start_time).total_seconds()
        return None

    @classmethod
    def get_active_sessions(cls, device_id=None, user_id=None):
        """Get all currently active sessions"""
        query = cls.query.filter(
            cls.actual_start_time.isnot(None),
            cls.actual_end_time.is_(None)
        )
        
        if device_id:
            query = query.filter(cls.device_id == device_id)
        if user_id:
            query = query.filter(cls.user_id == user_id)
        
        return query.all()

    @classmethod
    def terminate_active_sessions(cls, device_id=None, user_id=None, reason=None):
        """Terminate all active sessions with optional filters"""
        try:
            ist = pytz.timezone('Asia/Kolkata')
            current_time = datetime.now(ist)
        
            query = db.update(cls)\
                .where(
                    cls.actual_start_time.isnot(None),
                    cls.actual_end_time.is_(None)
                )\
                .values(
                    actual_end_time=current_time,
                    status='terminated',
                    termination_reason=reason or 'System terminated'
                )
        
            if device_id:
                query = query.where(cls.device_id == device_id)
            if user_id:
                query = query.where(cls.user_id == user_id)
            
            result = db.session.execute(query)
            db.session.commit()
            return result.rowcount
        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Failed to terminate active sessions: {str(e)}")
            return 0

    def update_status(self):
        """Update the status based on current timestamps and reservation"""
        ist = pytz.timezone('Asia/Kolkata')
        now = datetime.now(ist)
        
        # If there's a reservation and it's in the future
        if self.reservation and self.reservation.start_time > now:
            self.status = 'upcoming'
        # If no start time recorded yet
        elif not self.actual_start_time:
            self.status = 'pending'
        # If started but not ended
        elif self.actual_start_time and not self.actual_end_time:
            self.status = 'active'
        # If ended
        elif self.actual_end_time:
            if self.termination_reason:
                self.status = 'terminated'
            else:
                self.status = 'completed'

    def end_usage(self, terminated=False, reason=None):
        """Properly end a usage session"""
        ist = pytz.timezone('Asia/Kolkata')
        self.actual_end_time = datetime.now(ist)
        
        if terminated:
            self.status = 'terminated'
            self.termination_reason = reason or 'Manually terminated'
        else:
            self.status = 'completed'
        
        db.session.commit()

    def __repr__(self):
        return f'<DeviceUsage {self.id} - Device {self.device_id} by User {self.user_id} ({self.status})>'