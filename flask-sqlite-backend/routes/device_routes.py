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

@device_bp.route('/add', methods=['POST'])
@login_required
def add():
    if current_user.role != 'admin':
        flash('You do not have permission to perform this action', 'danger')
        return redirect(url_for('reservation.dashboard'))
    
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
        flash('Device added successfully!', 'success')
    except ValueError as e:
        flash(str(e), 'error')
    except Exception as e:
        flash('Error adding device. Device ID may already exist.', 'error')
        db.session.rollback()
    return redirect(url_for('device.index'))

@device_bp.route('/edit/<device_id>/<field>')
@login_required
def edit_field(device_id, field):
    if current_user.role != 'admin':
        flash('You do not have permission to perform this action', 'danger')
        return redirect(url_for('reservation.dashboard'))
    
    device = Device.query.get_or_404(device_id)
    valid_fields = ['PC_IP', 'Rutomatrix_ip', 'Pulse1_Ip', 'Pulse2_ip', 
                   'Pulse3_ip', 'CT1_ip', 'CT2_ip', 'CT3_ip']
    if field not in valid_fields:
        flash('Invalid field specified!', 'error')
        return redirect(url_for('device.index'))
    
    return render_template('edit_device.html', 
                         device=device, 
                         field=field,
                         field_name=field.replace('_', ' ').title())

@device_bp.route('/update/<device_id>/<field>', methods=['POST'])
@login_required
def update_field(device_id, field):
    if current_user.role != 'admin':
        flash('You do not have permission to perform this action', 'danger')
        return redirect(url_for('reservation.dashboard'))
    
    device = Device.query.get_or_404(device_id)
    valid_fields = ['PC_IP', 'Rutomatrix_ip', 'Pulse1_Ip', 'Pulse2_ip', 
                   'Pulse3_ip', 'CT1_ip', 'CT2_ip', 'CT3_ip']
    
    if field not in valid_fields:
        flash('Invalid field specified!', 'error')
        return redirect(url_for('device.index'))
    
    try:
        setattr(device, field, request.form['new_value'] or None)
        db.session.commit()
        flash(f'{field.replace("_", " ").title()} updated successfully!', 'success')
    except Exception as e:
        flash(f'Error updating {field.replace("_", " ")}: {str(e)}', 'error')
        db.session.rollback()
    
    return redirect(url_for('device.index'))

@device_bp.route('/delete/<device_id>')
@login_required
def delete(device_id):
    if current_user.role != 'admin':
        flash('You do not have permission to perform this action', 'danger')
        return redirect(url_for('reservation.dashboard'))
    
    device = Device.query.get_or_404(device_id)
    try:
        db.session.delete(device)
        db.session.commit()
        flash('Device deleted successfully!', 'success')
    except Exception as e:
        flash(f'Error deleting device: {str(e)}', 'error')
        db.session.rollback()
    return redirect(url_for('device.index'))

# IP Address getters
@device_bp.route('/api/devices/<device_id>/<ip_type>', methods=['GET'])
@login_required
def get_ip_address(device_id, ip_type):
    device = Device.query.get_or_404(device_id)
    valid_fields = ['PC_IP', 'Rutomatrix_ip', 'Pulse1_Ip', 'Pulse2_ip', 
                   'Pulse3_ip', 'CT1_ip', 'CT2_ip', 'CT3_ip']
    
    if ip_type not in valid_fields:
        return jsonify({'error': 'Invalid IP type'}), 400
    
    return jsonify({
        'device_id': device.device_id,
        ip_type: getattr(device, ip_type)
    })

