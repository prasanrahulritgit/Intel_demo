from flask import Blueprint, render_template, redirect, url_for, flash, request, jsonify
from flask_login import login_required, current_user
from models import Device, db
from datetime import datetime

device_bp = Blueprint('device', __name__)

@device_bp.route('/')
@login_required
def index():
    if current_user.role != 'admin':
        return redirect(url_for('reservation.dashboard'))
    devices = Device.query.all()
    return render_template('devices.html', devices=devices)

@device_bp.route('/api/devices', methods=['GET'])
@login_required
def get_all():
    if current_user.role != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    
    devices = Device.query.all()
    devices_list = [{
        'device_id': device.device_id,
        'PC_IP': device.PC_IP,
        'Rutomatrix_ip': device.Rutomatrix_ip,
        'Pulse1_Ip': device.Pulse1_Ip,
        'Pulse2_ip': device.Pulse2_ip,
        'Pulse3_ip': device.Pulse3_ip,
        'CT1_ip': device.CT1_ip,
        'CT2_ip': device.CT2_ip,
        'CT3_ip': device.CT3_ip
    } for device in devices]
    return jsonify({'devices': devices_list})

@device_bp.route('/api/devices/<device_id>', methods=['GET'])
@login_required
def get_device(device_id):
    if current_user.role != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    
    device = Device.query.get_or_404(device_id)
    return jsonify({
        'device_id': device.device_id,
        'PC_IP': device.PC_IP,
        'Rutomatrix_ip': device.Rutomatrix_ip,
        'Pulse1_Ip': device.Pulse1_Ip,
        'Pulse2_ip': device.Pulse2_ip,
        'Pulse3_ip': device.Pulse3_ip,
        'CT1_ip': device.CT1_ip,
        'CT2_ip': device.CT2_ip,
        'CT3_ip': device.CT3_ip
    })

@device_bp.route('/add', methods=['POST'])
@login_required
def add():
    if current_user.role != 'admin':
        flash('You do not have permission to perform this action', 'danger')
        return redirect(url_for('device.index'))
    
    try:
        new_device = Device(
            device_id=request.form['device_id'],
            PC_IP=request.form.get('PC_IP'),
            Rutomatrix_ip=request.form.get('Rutomatrix_ip'),
            Pulse1_Ip=request.form.get('Pulse1_Ip'),
            Pulse2_ip=request.form.get('Pulse2_ip'),
            Pulse3_ip=request.form.get('Pulse3_ip'),
            CT1_ip=request.form.get('CT1_ip'),
            CT2_ip=request.form.get('CT2_ip'),
            CT3_ip=request.form.get('CT3_ip')
        )
        db.session.add(new_device)
        db.session.commit()
        return jsonify({
            'status': 'success',
            'message': 'Device added successfully!'
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'status': 'error',
            'message': f'Error adding device: {str(e)}'
        }), 400

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
            'Pulse2_ip': device.Pulse2_ip,
            'Pulse3_ip': device.Pulse3_ip,
            'CT1_ip': device.CT1_ip,
            'CT2_ip': device.CT2_ip,
            'CT3_ip': device.CT3_ip
        })
    
    # Handle POST request for updates
    try:
        device.PC_IP = request.form.get('PC_IP', device.PC_IP)
        device.Rutomatrix_ip = request.form.get('Rutomatrix_ip', device.Rutomatrix_ip)
        device.Pulse1_Ip = request.form.get('Pulse1_Ip', device.Pulse1_Ip)
        device.Pulse2_ip = request.form.get('Pulse2_ip', device.Pulse2_ip)
        device.Pulse3_ip = request.form.get('Pulse3_ip', device.Pulse3_ip)
        device.CT1_ip = request.form.get('CT1_ip', device.CT1_ip)
        device.CT2_ip = request.form.get('CT2_ip', device.CT2_ip)
        device.CT3_ip = request.form.get('CT3_ip', device.CT3_ip)
        
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
        'Pulse2_ip': device.Pulse2_ip,
        'Pulse3_ip': device.Pulse3_ip,
        'CT1_ip': device.CT1_ip,
        'CT2_ip': device.CT2_ip,
        'CT3_ip': device.CT3_ip
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
        'Pulse2_ip': 'Pulse2_ip',
        'Pulse3_ip': 'Pulse3_ip',
        'CT1_ip': 'CT1_ip',
        'CT2_ip': 'CT2_ip',
        'CT3_ip': 'CT3_ip'
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
    
