

from flask import Blueprint, current_app, render_template, redirect, url_for, flash, request, jsonify
from flask_login import login_required, current_user
import pytz
from models.device import Device
from models.reservation import Reservation
from models.base import db
from datetime import datetime, timedelta

device_bp = Blueprint('device', __name__)

@device_bp.route('/')
@login_required
def index():
    if current_user.role != 'admin':
        return redirect(url_for('reservation.dashboard'))
    devices = Device.query.all()
    return render_template('devices.html', devices=devices)


@device_bp.route('/api/devices/<device_id>/drivers', methods=['GET'])
@login_required
def get_device_drivers(device_id):
    try:
        device = db.session.query(Device).filter_by(device_id=device_id).first()
        
        if not device:
            return jsonify({
                'status': 'error',
                'message': 'Device not found'
            }), 404
            
        response_data = {
            'status': 'success',
            'device_id': device.device_id,
            'drivers': [],
            'system_info': [],
            'other_fields': []
        }
        
        # IP-based drivers
        ip_drivers = [
            {'name': 'PC', 'ip_field': 'PC_IP', 'type': 'pc'},
            {'name': 'Rutomatrix', 'ip_field': 'Rutomatrix_ip', 'type': 'rutomatrix'},
            {'name': 'Pulse1', 'ip_field': 'Pulse1_Ip', 'type': 'pulse'},
            {'name': 'CT1', 'ip_field': 'CT1_ip', 'type': 'ct'},
        ]
        
        for driver in ip_drivers:
            ip_address = getattr(device, driver['ip_field'], None)
            if ip_address:
                response_data['drivers'].append({
                    'name': driver['name'],
                    'ip': ip_address,
                    'type': driver['type'],
                    'field': driver['ip_field']
                })
            
        return jsonify(response_data)
        
    except Exception as e:
        current_app.logger.error(f"Error fetching device drivers: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Internal server error'
        }), 500



@device_bp.route('/api/devices/status', methods=['GET'])
@login_required
def get_devices_with_status():
    try:
        # Get time range from query parameters
        start_time = request.args.get('start_time')
        end_time = request.args.get('end_time')
        
        # Parse dates if provided
        ist = pytz.timezone('Asia/Kolkata')
        now = datetime.now(ist)
        
        if start_time:
            start_time = datetime.fromisoformat(start_time.replace('Z', '+00:00')).astimezone(ist)
        if end_time:
            end_time = datetime.fromisoformat(end_time.replace('Z', '+00:00')).astimezone(ist)
        else:
            end_time = now + timedelta(hours=1)  # Default 1 hour window

        devices = Device.query.all()
        devices_list = []
        
        for device in devices:
            is_booked = False
            booking_info = {}
            
            # Check for overlapping reservations
            overlapping = Reservation.query.filter(
                Reservation.device_id == device.device_id,
                Reservation.end_time >= now.replace(tzinfo=None),
                Reservation.start_time < end_time.replace(tzinfo=None),
                Reservation.end_time > start_time.replace(tzinfo=None)
            ).first()
            
            if overlapping:
                is_booked = True
                booking_info = {
                    'reservation_start': overlapping.start_time.isoformat(),
                    'reservation_end': overlapping.end_time.isoformat()
                }
            
            device_data = {
                'device_id': device.device_id,
                'status': 'booked' if is_booked else 'available',
                **booking_info
            }
            
            devices_list.append(device_data)
        
        return jsonify({
            'status': 'success',
            'devices': devices_list,
        })
    
    except Exception as e:
        current_app.logger.error(f"Error in get_devices_with_status: {str(e)}", exc_info=True)
        return jsonify({
            'status': 'error',
            'message': str(e),
            'error_type': type(e).__name__
        }), 500
    
    

@device_bp.route('/api/devices', methods=['GET'])
@login_required
def get_devices():
    """Get all devices with their availability status"""
    try:
        # Get current time in IST
        ist = pytz.timezone('Asia/Kolkata')
        current_time = datetime.now(ist)
        
        # Get all devices
        devices = Device.query.all()
        
        # Get all active reservations
        reservations = Reservation.query.filter(
            Reservation.end_time >= current_time.replace(tzinfo=None)
        ).all()
        
        # Prepare response
        device_list = []
        for device in devices:
            # Check if device is currently booked
            is_booked = any(
                reservation.device_id == device.device_id and
                reservation.start_time <= current_time.replace(tzinfo=None) <= reservation.end_time
                for reservation in reservations
            )
            
            device_list.append({
                'device_id': device.device_id,
                'name': device.device_id,  
                'status': 'booked' if is_booked else 'available',
                'pc_ip': device.PC_IP,
                'rutomatrix_ip': device.Rutomatrix_ip,
                'pulse1_ip': device.Pulse1_Ip,
                'ct1_ip': device.CT1_ip
            })
        
        return jsonify({
            'success': True,
            'devices': device_list
        })
        
    except Exception as e:
        current_app.logger.error(f"Error getting devices: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'Failed to get devices'
        }), 500


@device_bp.route('/api/devices/<device_id>', methods=['GET'])
@login_required
def get_device(device_id):  
    device = Device.query.get_or_404(device_id)
    return jsonify({
        'device_id': device.device_id,
        'PC_IP': device.PC_IP,
        'Rutomatrix_ip': device.Rutomatrix_ip,
        'Pulse1_Ip': device.Pulse1_Ip,
        'CT1_ip': device.CT1_ip,
    })

@device_bp.route('/add', methods=['POST'])
@login_required
def add():
    if current_user.role != 'admin':
        flash('You do not have permission to perform this action', 'danger')
        return redirect(url_for('device.index'))
    
    try:
        # Validate required fields
        if not request.form.get('device_id'):
            return jsonify({
                'status': 'error',
                'message': 'Device ID is required'
            }), 400

        new_device = Device(
            device_id=request.form['device_id'],
            PC_IP=request.form.get('PC_IP'),
            Rutomatrix_ip=request.form.get('Rutomatrix_ip'),
            Pulse1_Ip=request.form.get('Pulse1_Ip'),
            CT1_ip=request.form.get('CT1_ip'),
        )

        # Validate IP addresses if provided
        ip_fields = [
            'PC_IP', 'Rutomatrix_ip', 'Pulse1_Ip',
            'CT1_ip'
        ]
        
        for field in ip_fields:
            ip_value = getattr(new_device, field)
            if ip_value and not Device.validate_ip(ip_value):
                return jsonify({
                    'status': 'error',
                    'message': f'Invalid IP format for {field}'
                }), 400

        db.session.add(new_device)
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'message': 'Device added successfully!',
            'device_id': new_device.device_id
        })
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error adding device: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': f'Error adding device: {str(e)}'
        }), 500

@device_bp.route('/edit/<device_id>', methods=['GET', 'POST'])
@login_required
def edit(device_id):
    if current_user.role != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    
    device = Device.query.get_or_404(device_id)
    
    if request.method == 'GET':
        return jsonify({
            'device_id': device.device_id,
            'PC_IP': device.PC_IP,
            'Rutomatrix_ip': device.Rutomatrix_ip,
            'Pulse1_Ip': device.Pulse1_Ip,
            'CT1_ip': device.CT1_ip
        })
    
    # Handle POST request for updates
    try:
        device.PC_IP = request.form.get('PC_IP', device.PC_IP)
        device.Rutomatrix_ip = request.form.get('Rutomatrix_ip', device.Rutomatrix_ip)
        device.Pulse1_Ip = request.form.get('Pulse1_Ip', device.Pulse1_Ip)
        device.CT1_ip = request.form.get('CT1_ip', device.CT1_ip)
        
        db.session.commit()
        return jsonify({
            'status': 'success',
            'message': 'Device updated successfully!'
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'status': 'error',
            'message': f'Error updating device: {str(e)}'
        }), 400

@device_bp.route('/delete/<device_id>', methods=['POST'])
@login_required
def delete(device_id):
    if current_user.role != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    
    device = Device.query.get_or_404(device_id)
    try:
        db.session.delete(device)
        db.session.commit()
        return jsonify({
            'status': 'success',
            'message': 'Device deleted successfully!'
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'status': 'error',
            'message': f'Error deleting device: {str(e)}'
        }), 400

@device_bp.route('/view_ips/<device_id>', methods=['GET'])
@login_required
def view_ips(device_id):
    if current_user.role != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    
    device = Device.query.get_or_404(device_id)
    return jsonify({
        'device_id': device.device_id,
        'PC_IP': device.PC_IP,
        'Rutomatrix_ip': device.Rutomatrix_ip,
        'Pulse1_Ip': device.Pulse1_Ip,
        'CT1_ip': device.CT1_ip,
    })

@device_bp.route('/api/devices/<string:device_id>/<string:ip_type>', methods=['GET'])
@login_required
def get_single_device_ip(device_id, ip_type):
    """Get specific IP address for a device by device ID and IP type
    
    Example: /api/devices/001/Pulse3_ip
    """
    if current_user.role != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    
    # Map URL-friendly IP types to database column names
    ip_type_mapping = {
        'PC_IP': 'PC_IP',
        'Rutomatrix_ip': 'Rutomatrix_ip',
        'Pulse1_Ip': 'Pulse1_Ip',
        'CT1_ip': 'CT1_ip',
    }
    
    # Validate IP type
    if ip_type not in ip_type_mapping:
        valid_types = ", ".join(ip_type_mapping.keys())
        return jsonify({'error': f'Invalid IP type. Valid types are: {valid_types}'}), 400
    
    # Get device from database
    device = Device.query.filter_by(device_id=device_id).first()
    if not device:
        return jsonify({'error': f'Device {device_id} not found'}), 404
    
    # Get the specific IP address
    ip_value = getattr(device, ip_type_mapping[ip_type])
    if not ip_value:
        return jsonify({'error': f'{ip_type} not set for device {device_id}'}), 404
    
    # Return the IP address in plain text by default
    if request.accept_mimetypes.accept_json:
        return jsonify({
            'device_id': device_id,
            'ip_type': ip_type,
            'ip_address': ip_value
        })
    else:
        return ip_value  # Returns just the IP as plain text
    
