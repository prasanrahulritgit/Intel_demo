from flask import current_app
from .base import db, ISTDateTime
from datetime import datetime
import pytz

class Reservation(db.Model):
    __tablename__ = 'reservations'
    
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.String(50), db.ForeignKey('devices.device_id'))
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    start_time = db.Column(ISTDateTime(), nullable=False)
    end_time = db.Column(ISTDateTime(), nullable=False)
    purpose = db.Column(db.String(200))
    status = db.Column(db.String(20), default='upcoming')
    
    device = db.relationship('Device', backref='reservations')
    user = db.relationship('User', backref='reservations')

    def __init__(self, **kwargs):
        ist = pytz.timezone('Asia/Kolkata')
        
        for time_field in ['start_time', 'end_time']:
            if time_field in kwargs:
                if isinstance(kwargs[time_field], str):
                    naive_dt = datetime.strptime(kwargs[time_field], '%Y-%m-%dT%H:%M')
                    kwargs[time_field] = ist.localize(naive_dt)
                elif kwargs[time_field].tzinfo is None:
                    kwargs[time_field] = ist.localize(kwargs[time_field])
                else:
                    kwargs[time_field] = kwargs[time_field].astimezone(ist)
        
        super().__init__(**kwargs)

    @classmethod
    def delete_expired(cls):
        try:
            ist = pytz.timezone('Asia/Kolkata')
            current_time = datetime.now(ist)
            
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
        ist = pytz.timezone('Asia/Kolkata')
        now = datetime.now(ist)
        
        if self.end_time < now:
            self.status = 'expired'
        elif self.start_time <= now <= self.end_time:
            self.status = 'active'
        else:
            self.status = 'upcoming'

    def can_cancel(self, user):
        return (self.user_id == user.id or user.role == 'admin') and self.status == 'upcoming'

    def to_dict(self):
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