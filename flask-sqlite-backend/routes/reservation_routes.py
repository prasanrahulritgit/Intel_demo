from collections import OrderedDict
from flask import Blueprint, Response, abort, current_app, json, jsonify, render_template, redirect, url_for, flash, request
from flask_login import current_user, login_required
from openai import api_type
import pytz
from sqlalchemy import delete, exists
from models import DeviceUsage, Reservation, Device, User, db
from datetime import datetime, timezone

reservation_bp = Blueprint('reservation', __name__)



def run_cleanup():
    current_time = datetime.utcnow()  # Use UTC for consistency
    expired_reservations = Reservation.query.filter(Reservation.end_time < current_time).all()
    
    for reservation in expired_reservations:
        db.session.delete(reservation)
    
    db.session.commit()
    
    return f"Cleaned up {len(expired_reservations)} expired reservations"


def make_naive(utc_dt):
    """Convert timezone-aware datetime to naive (for SQLite storage)"""
    return utc_dt.replace(tzinfo=None) if utc_dt.tzinfo else utc_dt


@reservation_bp.route('/api/devices/availability', methods=['GET'])
@login_required
def get_devices_with_availability():
    """Get all devices with availability status for a given time range"""
    try:
        start_time_str = request.args.get('start_time')
        end_time_str = request.args.get('end_time')
        
        if not start_time_str or not end_time_str:
            return jsonify({
                'success': False,
                'message': 'Both start_time and end_time are required'
            }), 400
            
        ist = pytz.timezone('Asia/Kolkata')
        start_time = datetime.fromisoformat(start_time_str).astimezone(ist)
        end_time = datetime.fromisoformat(end_time_str).astimezone(ist)
        
        # Get all devices
        devices = Device.query.all()
        
        # Get conflicting reservations
        conflicting_reservations = Reservation.query.filter(
            Reservation.start_time < end_time.replace(tzinfo=None),
            Reservation.end_time > start_time.replace(tzinfo=None)
        ).all()
        
        # Create a set of booked device IDs
        booked_device_ids = {res.device_id for res in conflicting_reservations}
        
        # Prepare response
        device_list = []
        for device in devices:
            device_list.append({
                'device_id': device.device_id,
                'name': device.device_id,
                'status': 'booked' if device.device_id in booked_device_ids else 'available',
                'pc_ip': device.PC_IP,
                'rutomatrix_ip': device.Rutomatrix_ip,
                'pulse1_ip': device.Pulse1_Ip,
                'ct1_ip': device.CT1_ip
            })
        
        return jsonify({
            'success': True,
            'devices': device_list,
            'meta': {
                'start_time': start_time.isoformat(),
                'end_time': end_time.isoformat()
            }
        })
        
    except Exception as e:
        current_app.logger.error(f"Error checking device availability: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'Failed to check device availability'
        }), 500




@reservation_bp.route('/dashboard')
@login_required
def dashboard():
    # Delete ALL expired reservations (not just current user's)
    expired_count = Reservation.delete_expired()
    if expired_count > 0:
        current_app.logger.info(f"Deleted {expired_count} total expired reservations")

    # Get current time in IST for display purposes
    ist = pytz.timezone('Asia/Kolkata')
    now_ist = datetime.now(ist)
    
    # Get all devices and reservations
    devices = Device.query.all()
    
    # Get non-expired reservations only
    all_reservations = Reservation.query.filter(
        Reservation.end_time >= now_ist.replace(tzinfo=None)  # Compare with naive datetime
    ).order_by(Reservation.start_time).all()
    
    # Separate reservations
    user_reservations = [
        r for r in all_reservations 
        if r.user_id == current_user.id
    ]
    other_reservations = [
        r for r in all_reservations 
        if r.user_id != current_user.id
    ]
    
    # Determine which template to use
    template_name = 'devices.html' if current_user.role == 'admin' else 'reservation.html'
    
    return render_template(
        template_name,
        devices=devices,
        user_reservations=user_reservations,
        other_reservations=other_reservations,
        now=now_ist,  # Pass IST time to template
        current_user=current_user
    )

@reservation_bp.route('/reservations')
@login_required
def view_reservations():
    """Endpoint specifically for viewing reservations (for both admins and regular users)"""
    # Delete expired reservations
    expired_count = Reservation.delete_expired()
    if expired_count > 0:
        current_app.logger.info(f"Deleted {expired_count} expired reservations")

    # Get current time in IST
    ist = pytz.timezone('Asia/Kolkata')
    now_ist = datetime.now(ist)
    
    # Get all devices and reservations
    devices = Device.query.all()
    
    # Get non-expired reservations
    all_reservations = Reservation.query.filter(
        Reservation.end_time >= now_ist.replace(tzinfo=None)
    ).order_by(Reservation.start_time).all()
    
    # Separate reservations
    user_reservations = [
        r for r in all_reservations 
        if r.user_id == current_user.id
    ]
    other_reservations = [
        r for r in all_reservations 
        if r.user_id != current_user.id
    ]
    
    if(current_user.role == 'admin') :
        return render_template(
        'admin_reservation.html',
        devices=devices,
        user_reservations=user_reservations,
        other_reservations=other_reservations,
        now=now_ist,
        current_user=current_user,
        is_admin=(current_user.role == 'admin')
    ) 
    else :
        return render_template(
        'reservation.html',
        devices=devices,
        user_reservations=user_reservations,
        other_reservations=other_reservations,
        now=now_ist,
        current_user=current_user,
        is_admin=(current_user.role == 'admin')
    )

@reservation_bp.route('/api/devices', methods=['GET'])
@login_required
def get_devices():
    try:
        devices = Device.query.all()
        return jsonify({
            'success': True,
            'devices': [device.to_dict() for device in devices]
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500


@reservation_bp.route('/api/booked-devices', methods=['GET'])
def get_booked_devices():
    """Get all currently booked devices with their reservation details"""
    try:
        ist = pytz.timezone('Asia/Kolkata')
        current_time_ist = datetime.now(ist)
        
        # Get query parameters for filtering
        device_id = request.args.get('device_id')
        user_id = request.args.get('user_id')
        show_expired = request.args.get('show_expired', 'false').lower() == 'true'
        show_upcoming = request.args.get('show_upcoming', 'true').lower() == 'true'
        show_active = request.args.get('show_active', 'true').lower() == 'true'
        
        # Base query with device and user details
        query = db.session.query(
            Reservation,
            Device,
            User
        ).join(
            Device, Reservation.device_id == Device.device_id
        ).join(
            User, Reservation.user_id == User.id
        ).order_by(
            Reservation.start_time.asc()
        )

        status_filters = []
        if show_active:
            status_filters.append(
                (Reservation.start_time <= current_time_ist) &
                (Reservation.end_time >= current_time_ist)
            )
        if show_upcoming:
            status_filters.append(Reservation.start_time > current_time_ist)
        if show_expired:
            status_filters.append(Reservation.end_time < current_time_ist)
        
        if status_filters:
            query = query.filter(db.or_(*status_filters))
        
        results = query.all()
        
        # Format the response
        booked_devices = []
        for reservation, device, user in results:
            # Determine which IP to show based on device type
            ip_type = 'pc'  # default
            if 'rutomatrix' in device.device_id.lower():
                ip_type = 'rutomatrix'
            elif 'pulse' in device.device_id.lower():
                ip_type = 'pulse'
            elif 'ct' in device.device_id.lower():
                ip_type = 'ct'
            
            ip_address = {
                'pc': device.PC_IP,
                'rutomatrix': device.Rutomatrix_ip,
                'pulse': device.Pulse1_Ip,
                'ct': device.CT1_ip
            }.get(ip_type, None)
            
            # Convert times to IST
            start_ist = reservation.start_time.astimezone(ist)
            end_ist = reservation.end_time.astimezone(ist)
            
            booked_devices.append({
                'id': reservation.id,
                'device': {
                    'id': device.device_id,
                    'pc_ip': device.PC_IP,
                    'rutomatrix_ip': device.Rutomatrix_ip,
                    'pulse1_ip': device.Pulse1_Ip,
                    'ct1_ip': device.CT1_ip,
                },
                'user': {
                    'id': user.id,
                },
                'time': {
                    'start': start_ist.isoformat(),
                    'end': end_ist.isoformat(),
                    'duration_minutes': int((end_ist - start_ist).total_seconds() / 60),
                    'timezone': 'Asia/Kolkata'
                },
                'status': reservation.status,
                'purpose': reservation.purpose or ''
            })
        
        return jsonify({
            'success': True,
            'data': {
                'booked_devices': booked_devices,
                'meta': {
                    'count': len(booked_devices),
                    'current_time': current_time_ist.isoformat(),
                    'filters': {
                        'device_id': device_id,
                        'user_id': user_id,
                        'show_expired': show_expired,
                        'show_upcoming': show_upcoming,
                        'show_active': show_active
                    }
                }
            }
        })
        
    except Exception as e:
        current_app.logger.error(f"Failed to fetch booked devices: {str(e)}", exc_info=True)
        return jsonify({
            'success': False,
            'message': 'Failed to fetch booked devices',
            'error': str(e)
        }), 500
    


@reservation_bp.route('/api/reservations', methods=['GET'])
@login_required
def get_reservations():
    """Get all reservations with filtering options"""
    try:
        # Get query parameters
        device_id = request.args.get('device_id', type=int)
        user_id = request.args.get('user_id', type=int)
        show_expired = request.args.get('show_expired', 'false').lower() == 'true'
        show_upcoming = request.args.get('show_upcoming', 'true').lower() == 'true'
        show_active = request.args.get('show_active', 'true').lower() == 'true'

        # Base query
        query = Reservation.query.join(Device).join(User)

        # Apply filters
        if device_id:
            query = query.filter(Reservation.device_id == device_id)
        if user_id:
            query = query.filter(Reservation.user_id == user_id)

        # Get current time in IST
        ist = pytz.timezone('Asia/Kolkata')
        current_time_ist = datetime.now(ist)

        # Time-based filtering
        conditions = []
        if show_expired:
            conditions.append(Reservation.end_time < current_time_ist)
        if show_upcoming:
            conditions.append(Reservation.start_time > current_time_ist)
        if show_active:
            conditions.append((Reservation.start_time <= current_time_ist) & 
                            (Reservation.end_time >= current_time_ist))
        
        if conditions:
            query = query.filter(db.or_(*conditions))

        # Execute query and prepare response
        reservations = query.all()
        booked_devices = []

        for reservation in reservations:
            device = reservation.device
            user = reservation.user

            # Convert times to IST
            start_ist = reservation.start_time.astimezone(ist)
            end_ist = reservation.end_time.astimezone(ist)

            device_info = OrderedDict()
            device_info['id'] = device.device_id
            device_info['ct1_ip'] = device.CT1_ip
            device_info['pulse1_ip'] = device.Pulse1_Ip
            device_info['pc_ip'] = device.PC_IP
            device_info['rutomatrix_ip'] = device.Rutomatrix_ip

            booked_devices.append({
                'id': reservation.id,
                'device': device_info,
                'user': {
                    'id': user.id,
                },
                'time': {
                    'start': start_ist.isoformat(),
                    'end': end_ist.isoformat(),
                    'duration_minutes': int((end_ist - start_ist).total_seconds() / 60),
                    'timezone': 'Asia/Kolkata'
                },
                'status': reservation.status,
                'purpose': reservation.purpose or ''
            })

        response = {
            'success': True,
            'data': {
                'booked_devices': booked_devices,
                'meta': {
                    'count': len(booked_devices),
                    'current_time': current_time_ist.isoformat(),
                    'filters': {
                        'device_id': device_id,
                        'user_id': user_id,
                        'show_expired': show_expired,
                        'show_upcoming': show_upcoming,
                        'show_active': show_active
                    }
                }
            }
        }

        return Response(
            json.dumps(response, ensure_ascii=False, sort_keys=False),
            mimetype='application/json'
        )

    except Exception as e:
        current_app.logger.error(f"Error fetching reservations: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'Failed to fetch reservations'
        }), 500
    

'''@reservation_bp.route('/api/reservations', methods=['POST'])
@login_required
def create_reservation():
    """Create a new reservation"""
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['device_id', 'start_time', 'end_time']
        if not all(field in data for field in required_fields):
            return jsonify({
                'success': False,
                'message': 'Missing required fields'
            }), 400
            
        # Check device exists
        device = Device.query.get(data['device_id'])
        if not device:
            return jsonify({
                'success': False,
                'message': 'Device not found'
            }), 404
            
        # Parse times
        ist = pytz.timezone('Asia/Kolkata')
        try:
            start_time = datetime.fromisoformat(data['start_time'])
            end_time = datetime.fromisoformat(data['end_time'])
            
            # Localize to IST
            if start_time.tzinfo is None:
                start_time = ist.localize(start_time)
            else:
                start_time = start_time.astimezone(ist)
                
            if end_time.tzinfo is None:
                end_time = ist.localize(end_time)
            else:
                end_time = end_time.astimezone(ist)
                
        except ValueError:
            return jsonify({
                'success': False,
                'message': 'Invalid datetime format'
            }), 400
            
        # Validate times
        now = datetime.now(ist)
        if start_time < now:
            return jsonify({
                'success': False,
                'message': 'Start time cannot be in the past'
            }), 400
            
        if end_time <= start_time:
            return jsonify({
                'success': False,
                'message': 'End time must be after start time'
            }), 400
            

        conflict = Reservation.query.filter(
            Reservation.device_id == data['device_id'],
            Reservation.start_time < end_time.replace(tzinfo=None),
            Reservation.end_time > start_time.replace(tzinfo=None)
        ).first()
        
        if conflict:
            return jsonify({
                'success': False,
                'message': 'Device already reserved for this time period'
            }), 409
            
        # Create reservation
        reservation = Reservation(
            device_id=data['device_id'],
            user_id=current_user.id,
            start_time=start_time,
            end_time=end_time,
            purpose=data.get('purpose', ''),
            status='upcoming'  # <-- Reservation status
        )
        db.session.add(reservation)
        db.session.flush()

        usage_record = DeviceUsage(
            device_id=data['device_id'],
            user_id=current_user.id,
            reservation_id=reservation.id,  # <-- Must match
            actual_start_time=start_time.replace(tzinfo=None),
            actual_end_time=end_time.replace(tzinfo=None),
            status='upcoming',  # <-- Critical change
            ip_address=request.remote_addr
        )
        db.session.add(usage_record)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Reservation created',
            'reservation': reservation.to_dict()
        })
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error creating reservation: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'Failed to create reservation'
        }), 500
'''
    
@reservation_bp.route('/api/reservations', methods=['POST'])
@login_required
def create_reservation():
    """Create a new reservation"""
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['device_id', 'start_time', 'end_time']
        if not all(field in data for field in required_fields):
            return jsonify({
                'success': False,
                'message': 'Missing required fields'
            }), 400
            
        # Check device exists
        device = Device.query.get(data['device_id'])
        if not device:
            return jsonify({
                'success': False,
                'message': 'Device not found'
            }), 404
            
        # Parse times with IST timezone
        ist = pytz.timezone('Asia/Kolkata')
        try:
            start_time = datetime.fromisoformat(data['start_time'])
            end_time = datetime.fromisoformat(data['end_time'])
            
            # Localize to IST
            if start_time.tzinfo is None:
                start_time = ist.localize(start_time)
            else:
                start_time = start_time.astimezone(ist)
                
            if end_time.tzinfo is None:
                end_time = ist.localize(end_time)
            else:
                end_time = end_time.astimezone(ist)
                
        except ValueError:
            return jsonify({
                'success': False,
                'message': 'Invalid datetime format'
            }), 400
            
        # Validate times
        now = datetime.now(ist)
        if start_time < now:
            return jsonify({
                'success': False,
                'message': 'Start time cannot be in the past'
            }), 400
            
        if end_time <= start_time:
            return jsonify({
                'success': False,
                'message': 'End time must be after start time'
            }), 400
            
        # Check for conflicts
        conflict = Reservation.query.filter(
            Reservation.device_id == data['device_id'],
            Reservation.start_time < end_time.replace(tzinfo=None),
            Reservation.end_time > start_time.replace(tzinfo=None)
        ).first()
        
        if conflict:
            return jsonify({
                'success': False,
                'message': 'Device already reserved for this time period'
            }), 409
            
        # Create reservation
        reservation = Reservation(
            device_id=data['device_id'],
            user_id=current_user.id,
            start_time=start_time,
            end_time=end_time,
            purpose=data.get('purpose', ''),
            status='upcoming'
        )
        db.session.add(reservation)
        db.session.flush()

        usage_record = DeviceUsage(
            device_id=data['device_id'],
            user_id=current_user.id,
            reservation_id=reservation.id,
            actual_start_time=start_time.replace(tzinfo=None),
            actual_end_time=end_time.replace(tzinfo=None),
            status='upcoming',
            ip_address=request.remote_addr
        )
        db.session.add(usage_record)
        db.session.commit()
        
        # Prepare response with IST times and device info
        start_ist = reservation.start_time.astimezone(ist)
        end_ist = reservation.end_time.astimezone(ist)
        
        device_info = OrderedDict()
        device_info['id'] = device.device_id
        device_info['ct1_ip'] = device.CT1_ip
        device_info['pulse1_ip'] = device.Pulse1_Ip
        device_info['pc_ip'] = device.PC_IP
        device_info['rutomatrix_ip'] = device.Rutomatrix_ip
        
        response = {
            'success': True,
            'message': 'Reservation created',
            'data': {
                'id': reservation.id,
                'device': device_info,
                'user': {
                    'id': current_user.id,
                },
                'time': {
                    'start': start_ist.isoformat(),
                    'end': end_ist.isoformat(),
                    'duration_minutes': int((end_ist - start_ist).total_seconds() / 60),
                    'timezone': 'Asia/Kolkata'
                },
                'status': reservation.status
            }
        }
        
        return Response(
            json.dumps(response, ensure_ascii=False, sort_keys=False),
            mimetype='application/json'
        )
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error creating reservation: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'Failed to create reservation'
        }), 500

@reservation_bp.route('/reservation/cancel/<int:reservation_id>', methods=['POST'])
@login_required
def cancel_reservation(reservation_id):
    reservation = Reservation.query.get_or_404(reservation_id)
    
    if reservation.user_id != current_user.id and not current_user.is_admin:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403

    try:
        # Find the existing DeviceUsage record
        usage_record = DeviceUsage.query.filter_by(reservation_id=reservation.id).first()
        
        if not usage_record:
            # Log error (for debugging)
            current_app.logger.error(f"No DeviceUsage found for reservation_id={reservation.id}")
            return jsonify({
                'success': False,
                'message': 'Device usage record not found',
                'reservation_id': reservation.id
            }), 404

        # Update the record
        usage_record.actual_end_time = datetime.now()
        usage_record.status = 'Terminated'  # <-- Update status
        db.session.add(usage_record)
        
        # Delete the reservation
        db.session.delete(reservation)
        db.session.commit()

        return jsonify({
            'success': True,
            'message': 'Reservation cancelled',
            'reservation_id': reservation_id
        })
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Cancellation failed: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'Failed to cancel reservation',
            'error': str(e)
        }), 500


@reservation_bp.route('/api/user-reservations', methods=['GET'])
@login_required
def get_user_reservations():
    """Get all reservations with user details and IP information"""
    try:
        # Get query parameters
        show_expired = request.args.get('show_expired', 'false').lower() == 'true'
        device_id = request.args.get('device_id', None)
        user_id = request.args.get('user_id', None)
        
        # Get current time in IST
        ist = pytz.timezone('Asia/Kolkata')
        current_time = datetime.now(ist)
        
        # Base query with joins
        query = db.session.query(
            Reservation,
            User,
            Device
        ).join(
            User, Reservation.user_id == User.id
        ).join(
            Device, Reservation.device_id == Device.device_id
        ).order_by(
            Reservation.start_time.asc()
        )
        
        # Apply filters
        if not show_expired:
            query = query.filter(Reservation.end_time >= current_time)
            
        if device_id:
            query = query.filter(Reservation.device_id == device_id)
            
        if user_id:
            query = query.filter(Reservation.user_id == user_id)
        
        # Execute query
        results = query.all()
        
        # Format response
        reservations = []
        for reservation, user, device in results:
            # Get device IP based on reservation type
            ip_mapping = {
                'pc': device.PC_IP,
                'rutomatrix': device.Rutomatrix_ip,
                'pulse1': device.Pulse1_Ip,
                'ct1': device.CT1_ip,
            }
            
            # Determine which IP to use based on reservation type
            ip_type = reservation.ip_type.lower()
            device_ip = None
            
            if 'pc' in ip_type:
                device_ip = ip_mapping['pc']
            elif 'rutomatrix' in ip_type:
                device_ip = ip_mapping['rutomatrix']
            elif 'pulse1' in ip_type:
                device_ip = ip_mapping['pulse1']
            elif 'ct1' in ip_type:
                device_ip = ip_mapping['ct1']
            
            reservations.append({
                'reservation_id': reservation.id,
                'device_id': reservation.device_id,
                'device_name': device.device_id,  # Assuming device_id is the name
                'user_id': user.id,
                'user_ip': user.user_ip,
                'device_ip': device_ip,
                'ip_type': reservation.ip_type,
                'start_time': reservation.start_time.astimezone(ist).isoformat(),
                'end_time': reservation.end_time.astimezone(ist).isoformat(),
                'status': reservation.status,
                'is_active': reservation.status == 'active',
                'can_manage': current_user.role == 'admin' or user.id == current_user.id
            })
        
        return jsonify({
            'success': True,
            'count': len(reservations),
            'reservations': reservations,
            'current_time': current_time.isoformat(),
            'filters': {
                'show_expired': show_expired,
                'device_id': device_id,
                'user_id': user_id
            }
        })
        
    except Exception as e:
        current_app.logger.error(f"Failed to fetch user reservations: {str(e)}", exc_info=True)
        return jsonify({
            'success': False,
            'message': 'Failed to fetch reservations',
            'error': str(e)
        }), 500
    

@reservation_bp.route('/api/user-reservations/<int:user_id>', methods=['GET'])
@login_required
def get_user_reservation_details(user_id):
    """Get all reservation details for a specific user"""
    try:
        # Verify the requesting user has permission
        

        # Get the user
        user = User.query.get_or_404(user_id)

        # Get current time in IST
        ist = pytz.timezone('Asia/Kolkata')
        current_time = datetime.now(ist)

        # Get all reservations for this user with device details
        reservations = db.session.query(
            Reservation,
            Device
        ).join(
            Device, Reservation.device_id == Device.device_id
        ).filter(
            Reservation.user_id == user_id
        ).order_by(
            Reservation.start_time.desc()
        ).all()

        # Format the response
        result = {
            'user_id': user.id,
            'user_ip': user.user_ip,
            'role': user.role,
            'reservations': []
        }

        for reservation, device in reservations:
            # Determine which device IP to include based on reservation type
            ip_type = reservation.ip_type.lower()
            device_ip = None

            if 'pc' in ip_type:
                device_ip = device.PC_IP
            elif 'rutomatrix' in ip_type:
                device_ip = device.Rutomatrix_ip
            elif 'pulse1' in ip_type:
                device_ip = device.Pulse1_Ip
            elif 'ct1' in ip_type:
                device_ip = device.CT1_ip

            result['reservations'].append({
                'reservation_id': reservation.id,
                'device_id': device.device_id,
                'device_name': device.device_id,  # Assuming device_id is the name
                'ip_type': reservation.ip_type,
                'device_ip': device_ip,
                'start_time': reservation.start_time.astimezone(ist).isoformat(),
                'end_time': reservation.end_time.astimezone(ist).isoformat(),
                'status': reservation.status,
                'is_active': reservation.status == 'active',
                'duration_minutes': int((reservation.end_time - reservation.start_time).total_seconds() / 60)
            })

        return jsonify({
            'success': True,
            'data': result,
            'current_time': current_time.isoformat()
        })

    except Exception as e:
        current_app.logger.error(f"Failed to fetch user reservations: {str(e)}", exc_info=True)
        return jsonify({
            'success': False,
            'message': 'Failed to fetch user reservations',
            'error': str(e)
        }), 500

    
@reservation_bp.route('/api/user-reservations/<int:user_id>/time-filter', methods=['GET'])
@login_required
def get_user_reservations_with_time(user_id):
    """Get reservation details for a specific user with time filtering"""
    try:
        # Verify permissions
        if current_user.role != 'admin' and current_user.id != user_id:
            return jsonify({
                'success': False,
                'message': 'Unauthorized: You can only view your own reservations'
            }), 403

        # Get query parameters for time filtering
        start_time_str = request.args.get('start_time')
        end_time_str = request.args.get('end_time')
        timezone = request.args.get('timezone', 'Asia/Kolkata')
        
        # Get timezone object
        try:
            tz = pytz.timezone(timezone)
        except pytz.exceptions.UnknownTimeZoneError:
            return jsonify({
                'success': False,
                'message': f'Invalid timezone: {timezone}'
            }), 400

        # Parse time parameters
        current_time = datetime.now(tz)
        
        try:
            start_time = datetime.strptime(start_time_str, '%Y-%m-%dT%H:%M').replace(tzinfo=tz) if start_time_str else None
            end_time = datetime.strptime(end_time_str, '%Y-%m-%dT%H:%M').replace(tzinfo=tz) if end_time_str else None
        except ValueError:
            return jsonify({
                'success': False,
                'message': 'Invalid time format. Use YYYY-MM-DDTHH:MM'
            }), 400

        # Get user details
        user = User.query.get_or_404(user_id)

        # Base query
        query = db.session.query(Reservation, Device)\
            .join(Device, Reservation.device_id == Device.device_id)\
            .filter(Reservation.user_id == user_id)

        # Apply time filters
        if start_time:
            query = query.filter(Reservation.end_time >= start_time.astimezone(pytz.UTC).replace(tzinfo=None))
        if end_time:
            query = query.filter(Reservation.start_time <= end_time.astimezone(pytz.UTC).replace(tzinfo=None))

        # Execute query
        reservations = query.order_by(Reservation.start_time.desc()).all()

        # Format response
        result = {
            'user_id': user.id,
            'user_ip': user.user_ip,
            'timezone': timezone,
            'current_time': current_time.isoformat(),
            'filters': {
                'start_time': start_time.isoformat() if start_time else None,
                'end_time': end_time.isoformat() if end_time else None
            },
            'reservations': []
        }

        for reservation, device in reservations:
            # Get device IP based on reservation type
            ip_mapping = {
                'pc': device.PC_IP,
                'rutomatrix': device.Rutomatrix_ip,
                'pulse1': device.Pulse1_Ip,
                'ct1': device.CT1_ip,
            }
            
            ip_type = reservation.ip_type.lower()
            device_ip = next(
                (ip_mapping[key] for key in ip_mapping if key in ip_type),
                None
            )

            # Convert times to requested timezone
            start_local = reservation.start_time.replace(tzinfo=pytz.UTC).astimezone(tz)
            end_local = reservation.end_time.replace(tzinfo=pytz.UTC).astimezone(tz)

            result['reservations'].append({
                'reservation_id': reservation.id,
                'device_id': device.device_id,
                'device_name': device.device_id,
                'ip_type': reservation.ip_type,
                'device_ip': device_ip,
                'start_time': start_local.isoformat(),
                'end_time': end_local.isoformat(),
                'duration_minutes': int((end_local - start_local).total_seconds() / 60),
                'status': reservation.status,
                'is_active': (
                    start_local <= current_time <= end_local
                    if (start_time is None and end_time is None)
                    else None
                )
            })

        return jsonify({
            'success': True,
            'data': result
        })

    except Exception as e:
        current_app.logger.error(f"Error fetching reservations: {str(e)}", exc_info=True)
        return jsonify({
            'success': False,
            'message': 'Failed to fetch reservations',
            'error': str(e)
        }), 500
