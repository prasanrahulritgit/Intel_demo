from .base import db, ISTDateTime
from datetime import datetime
import re

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