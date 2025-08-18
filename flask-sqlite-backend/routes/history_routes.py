from flask import Blueprint, current_app, render_template, request, jsonify
from sqlalchemy import delete
from werkzeug.exceptions import BadRequest,Forbidden
from datetime import datetime, timedelta
from models.device import Device
from models.device_usage import DeviceUsage
from models.reservation import Reservation
from models.user import User
from models.base import db
from flask_login import current_user, login_required
import pytz

history_bp = Blueprint('history', __name__, url_prefix='/history')

# Timezone setup
IST = pytz.timezone('Asia/Kolkata')

# Helper function to format duration
def format_duration(seconds):
    if not seconds:
        return None
    hours = seconds // 3600
    minutes = (seconds % 3600) // 60
    return f"{hours}h {minutes}m"

@history_bp.route('/')
@login_required
def index():
    """Main history view"""
    history_records = DeviceUsage.query.order_by(DeviceUsage.actual_start_time.desc()).all()
    devices = Device.query.all()
    users = User.query.all()
    
    return render_template(
        'history.html',
        history_records=history_records,
        devices=devices,
        users=users,
        current_user=current_user
    )

@history_bp.route('/update-usage-status/<int:record_id>', methods=['PATCH'])
@login_required
def update_usage_status(record_id):
    """Update the status of a usage record"""
    try:
        record = DeviceUsage.query.get_or_404(record_id)
        
        if current_user.id != record.user_id and current_user.role != 'admin':
            return jsonify({'error': 'Unauthorized access'}), 403

        data = request.get_json()
        new_status = data.get('status')
        
        if new_status not in ['active', 'completed', 'terminated']:
            return jsonify({'error': 'Invalid status'}), 400

        ist = pytz.timezone('Asia/Kolkata')
        
        if new_status == 'active':
            record.actual_start_time = datetime.now(ist)
        elif new_status in ['completed', 'terminated']:
            record.actual_end_time = datetime.now(ist)
            if new_status == 'terminated':
                record.termination_reason = data.get('reason', 'Terminated by user')

        record.status = new_status
        db.session.commit()
        
        return jsonify({'message': 'Status updated successfully'}), 200
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error updating record {record_id}: {str(e)}", exc_info=True)
        return jsonify({'error': 'Failed to update status'}), 500
    

@history_bp.route('/list-usage-records', methods=['GET'])
@login_required
def list_usage_records():
    """Get a list of all usage records (admin only)"""
    try:
        if current_user.role != 'admin':
            return jsonify({'error': 'Admin privileges required'}), 403

        records = DeviceUsage.query.order_by(DeviceUsage.actual_start_time.desc()).all()
        
        result = []
        for record in records:
            result.append({
                'id': record.id,
                'device_id': record.device_id,
                'user_id': record.user_id,
                'start_time': record.actual_start_time.isoformat() if record.actual_start_time else None,
                'status': record.status
            })
            
        return jsonify({'records': result, 'count': len(result)})
        
    except Exception as e:
        current_app.logger.error(f"Error listing records: {str(e)}", exc_info=True)
        return jsonify({'error': 'Failed to fetch records'}), 500
    

@history_bp.route('/delete-usage-record/<int:record_id>', methods=['DELETE'])
@login_required
def delete_usage_record(record_id):
    """Delete a specific usage record (admin only)"""
    try:
        record = DeviceUsage.query.get_or_404(record_id)
        
        if current_user.role != 'admin':
            return jsonify({'error': 'Admin privileges required'}), 403

        db.session.delete(record)
        db.session.commit()
        
        return jsonify({'message': 'Record deleted successfully'}), 200
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error deleting record {record_id}: {str(e)}", exc_info=True)
        return jsonify({'error': 'Failed to delete record'}), 500
    


@history_bp.route('/get-usage-record/<int:record_id>', methods=['GET'])
@login_required
def get_usage_record_details(record_id):
    try:
        # Eager load all relationships
        record = DeviceUsage.query.options(
            db.joinedload(DeviceUsage.device),
            db.joinedload(DeviceUsage.user),
            db.joinedload(DeviceUsage.reservation)
        ).get(record_id)
        
        if not record:
            return jsonify({'error': 'Record not found'}), 404
            
        if current_user.role != 'admin' and current_user.id != record.user_id:
            return jsonify({'error': 'Unauthorized access'}), 403

        # Format the response data
        response_data = {
            'id': record.id,
            'device_id': record.device_id,
            'user_info': {
                'user_id': record.user.id,
                'user_name': record.user.user_name,
                'user_ip': record.user.user_ip
            },
            'timing': {
                'start_time': record.actual_start_time.isoformat() if record.actual_start_time else None,
                'end_time': record.actual_end_time.isoformat() if record.actual_end_time else None,
                'duration': record.duration
            },
            'network_info': {
                'ip_address': record.ip_address,
                'ip_type': record.ip_type
            },
            'status_info': {
                'status': record.status,
                'termination_reason': record.termination_reason
            },
            'reservation_info': {
                'reservation_id': record.reservation_id,
                'ip_type': record.reservation.ip_type if record.reservation else None
            }
        }
        
        return jsonify(response_data)
        
    except Exception as e:
        current_app.logger.error(f"Error fetching record {record_id}: {str(e)}", exc_info=True)
        return jsonify({'error': 'Failed to fetch record details'}), 500
    

@history_bp.route('/<int:record_id>', methods=['GET', 'DELETE'])
@login_required
def usage_record(record_id):
    """Handle both GET and DELETE requests for usage records"""
    try:
        record = DeviceUsage.query.get_or_404(record_id)
        
        if request.method == 'DELETE':
            # Check if user is admin or owns the record
            if current_user.role != 'admin' and current_user.id != record.user_id:
                return jsonify({'message': 'Permission denied'}), 403
            
            try:
                # If the usage is still active, set end time first
                if record.status == 'active' and not record.actual_end_time:
                    ist = pytz.timezone('Asia/Kolkata')
                    record.actual_end_time = datetime.now(ist)
                    record.status = 'completed'
                    record.termination_reason = 'Deleted by user'
                    db.session.commit()
                
                # Now delete the record
                db.session.delete(record)
                db.session.commit()
                return jsonify({'message': 'Record deleted successfully'}), 200
            except Exception as e:
                db.session.rollback()
                current_app.logger.error(f"Error deleting record: {str(e)}")
                return jsonify({'message': 'Failed to delete record'}), 500
        
        # Handle GET request
        return jsonify({
            'record': {
                'id': record.id,
                'device_id': record.device_id,
                'device_name': record.device.device_name if record.device else None,
                'user_id': record.user_id,
                'user_name': record.user.name if record.user else None,
                'reservation_id': record.reservation_id,
                'start_time': record.actual_start_time.isoformat() if record.actual_start_time else None,
                'end_time': record.actual_end_time.isoformat() if record.actual_end_time else None,
                'status': record.status,
                'ip_address': record.ip_address,
                'ip_type': record.ip_type,
                'duration': record.duration,
                'duration_formatted': format_duration(record.duration),
                'termination_reason': record.termination_reason
            }
        })
        
    except Exception as e:
        current_app.logger.error(f"Error in usage_record endpoint: {str(e)}")
        return jsonify({'message': 'Server error processing request'}), 500

'''@history_bp.route('/<int:record_id>', methods=['GET', 'DELETE'])
@login_required
def usage_record(record_id):
    """Handle both GET and DELETE requests for usage records"""
    record = DeviceUsage.query.get_or_404(record_id)
    
    if request.method == 'DELETE':
        # Check if user is admin or owns the record
        if current_user.role != 'admin' and current_user.id != record.user_id:
            return jsonify({'message': 'Permission denied'}), 403
        
        try:
            # If the usage is still active, set end time first
            if record.status == 'active' and not record.actual_end_time:
                ist = pytz.timezone('Asia/Kolkata')
                record.actual_end_time = datetime.now(ist)
                record.status = 'completed'
                record.termination_reason = 'Deleted by user'
                db.session.commit()
            
            # Now delete the record
            db.session.delete(record)
            db.session.commit()
            return jsonify({'message': 'Record deleted successfully'}), 200
        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Error deleting record: {str(e)}")
            return jsonify({'message': 'Failed to delete record'}), 500
    
    # Handle GET request (your existing code)
    return jsonify({
        'record': {
            'id': record.id,
            'device_id': record.device_id,
            'device_name': record.device.device_name if record.device else None,
            'user_id': record.user_id,
            'user_name': record.user.name if record.user else None,
            'reservation_id': record.reservation_id,
            'start_time': record.actual_start_time.isoformat() if record.actual_start_time else None,
            'end_time': record.actual_end_time.isoformat() if record.actual_end_time else None,
            'status': record.status,
            'ip_address': record.ip_address,
            'ip_type': record.ip_type,
            'duration': record.duration,
            'duration_formatted': format_duration(record.duration),
            'termination_reason': record.termination_reason
        }
    })'''


@history_bp.route('/clear-old', methods=['POST'])
@login_required
def clear_old_records():
    """Delete records older than 6 months (admin only)"""
    if not current_user.is_admin:
        raise Forbidden("Only administrators can clear old records")
    
    try:
        six_months_ago = datetime.now(IST) - timedelta(days=180)
        deleted_count = db.session.query(DeviceUsage)\
            .filter(DeviceUsage.actual_start_time < six_months_ago)\
            .delete()
        db.session.commit()
        
        return jsonify({
            'message': f'Deleted {deleted_count} old records',
            'deleted_count': deleted_count
        })
    except Exception as e:
        db.session.rollback()
        raise BadRequest(f"Failed to clear old records: {str(e)}")

@history_bp.route('/active', methods=['GET'])
@login_required
def get_active_sessions():
    """Get all currently active sessions"""
    active_sessions = DeviceUsage.query.filter_by(
        actual_end_time=None
    ).order_by(
        DeviceUsage.actual_start_time.asc()
    ).all()
    
    return jsonify({
        'count': len(active_sessions),
        'sessions': [{
            'id': s.id,
            'device_id': s.device_id,
            'device_name': s.device.device_name if s.device else None,
            'user_id': s.user_id,
            'user_name': s.user.name if s.user else None,
            'start_time': s.actual_start_time.isoformat() if s.actual_start_time else None,
            'duration': (datetime.now(IST) - s.actual_start_time).total_seconds() if s.actual_start_time else None,
            'duration_formatted': format_duration((datetime.now(IST) - s.actual_start_time).total_seconds()) if s.actual_start_time else None
        } for s in active_sessions]
    })

@history_bp.route('/start-usage/<int:reservation_id>', methods=['POST'])
@login_required
def start_usage(reservation_id):
    """Mark a reservation as actually being used"""
    try:
       
        reservation = Reservation.query.filter_by(
            id=reservation_id,
            user_id=current_user.id
        ).first_or_404()
        
       
        usage_record = DeviceUsage.query.filter_by(
            reservation_id=reservation_id
        ).first()
        
        if usage_record and usage_record.actual_start_time:
            return jsonify({
                'message': 'Usage already started',
                'actual_start_time': usage_record.actual_start_time.isoformat()
            }), 400
            
        if not usage_record:
            # Create new usage record
            usage_record = DeviceUsage(
                device_id=reservation.device_id,
                user_id=current_user.id,
                reservation_id=reservation_id,
                ip_type=reservation.ip_type,
                status='active'
            )
        
        # Update usage record
        usage_record.actual_start_time = datetime.now(IST)
        usage_record.status = 'active'
        usage_record.ip_address = request.remote_addr
        
        db.session.add(usage_record)
        db.session.commit()
        
        return jsonify({
            'message': 'Usage started successfully',
            'actual_start_time': usage_record.actual_start_time.isoformat(),
            'reservation_id': reservation_id
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@history_bp.route('/end-usage/<int:reservation_id>', methods=['POST'])
@login_required
def end_usage(reservation_id):
    """Mark a reservation usage as completed"""
    try:
        # Find the usage record
        usage_record = DeviceUsage.query.filter_by(
            reservation_id=reservation_id,
            user_id=current_user.id
        ).first_or_404()
        
        if usage_record.actual_end_time:
            return jsonify({
                'message': 'Usage already ended',
                'actual_end_time': usage_record.actual_end_time.isoformat()
            }), 400
            
        # Update usage record
        end_time = datetime.now(IST)
        usage_record.actual_end_time = end_time
        usage_record.status = 'completed'
        
        if usage_record.actual_start_time:
            usage_record.duration = (end_time - usage_record.actual_start_time).total_seconds()
        
        db.session.commit()
        
        return jsonify({
            'message': 'Usage ended successfully',
            'actual_end_time': usage_record.actual_end_time.isoformat(),
            'duration': usage_record.duration,
            'duration_formatted': format_duration(usage_record.duration),
            'reservation_id': reservation_id
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500