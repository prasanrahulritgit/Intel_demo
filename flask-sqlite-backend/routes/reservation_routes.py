from flask import Blueprint, current_app, render_template, redirect, url_for, flash, request
from flask_login import current_user, login_required
import pytz
from sqlalchemy import delete, exists
from models import DeviceUsage, Reservation, Device, db
from datetime import datetime

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
    
    return render_template(
        'admin_reservation.html',
        devices=devices,
        user_reservations=user_reservations,
        other_reservations=other_reservations,
        now=now_ist,
        current_user=current_user,
        is_admin=(current_user.role == 'admin')
    )



'''@reservation_bp.route('/reserve', methods=['POST', 'GET'])
@login_required
def make_reservation():
    try:
        # 1. Force delete expired FIRST
        expired_count = Reservation.delete_expired()
        if expired_count > 0:
            current_app.logger.info(f"Deleted {expired_count} expired reservations")

        # 2. Process new reservation
        ist = pytz.timezone('Asia/Kolkata')
        current_time = datetime.now(ist)
        
        device_id = request.form['device_id']
        ip_type = request.form['ip_type'].lower()  # Normalize case
        
        # Convert to IST
        start_time = ist.localize(datetime.strptime(
            request.form['start_time'], '%Y-%m-%dT%H:%M'
        ))
        end_time = ist.localize(datetime.strptime(
            request.form['end_time'], '%Y-%m-%dT%H:%M'
        ))

        # Validation
        if end_time <= start_time:
            flash('End time must be after start time', 'danger')
        elif start_time < current_time:
            flash('Start time cannot be in the past', 'danger')
        else:
            # Set limits PER DEVICE
            limits = {
                'pc': 1,
                'rutomatrix': 1,
                'pulseview': 1,
                'ct': 1
            }
            
            # Determine which limit applies
            max_users = 1  # Default
            if 'pulse' in ip_type.lower():
                max_users = limits['pulseview']
            elif 'ct' in ip_type.lower():
                max_users = limits['ct']
            elif 'pc' in ip_type.lower():
                max_users = limits['pc']
            elif 'rutomatrix' in ip_type.lower():
                max_users = limits['rutomatrix']

            # Check conflicts for THIS DEVICE and IP TYPE
            conflicts = Reservation.query.filter(
                Reservation.device_id == device_id,
                Reservation.ip_type.ilike(f'%{ip_type}%'),  # Case-insensitive partial match
                Reservation.end_time >= current_time,  
                Reservation.start_time < end_time,
                Reservation.end_time > start_time
            ).count()

            if conflicts >= max_users:
                flash(f'Maximum {max_users} user(s) allowed for {ip_type} on device {device_id}', 'danger')
            else:
                # Create reservation
                reservation = Reservation(
                    device_id=device_id,
                    user_id=current_user.id,
                    ip_type=ip_type,
                    start_time=start_time,
                    end_time=end_time
                )
                db.session.add(reservation)
                db.session.commit()
                flash('Reservation successful!', 'success')

    except Exception as e:
        db.session.rollback()
        flash('Reservation failed', 'danger')
        current_app.logger.error(f"Error: {str(e)}", exc_info=True)
    
    return redirect(url_for('reservation.dashboard'))'''


@reservation_bp.route('/reserve', methods=['POST'])
@login_required
def make_reservation():
    try:
        # 1. Clean up expired reservations
        expired_count = Reservation.delete_expired()
        if expired_count > 0:
            current_app.logger.info(f"Deleted {expired_count} expired reservations")

        # 2. Process new reservation
        ist = pytz.timezone('Asia/Kolkata')
        current_time = datetime.now(ist)
        
        device_id = request.form['device_id']
        ip_type = request.form['ip_type'].lower()
        
        # Parse times
        start_time = ist.localize(datetime.strptime(
            request.form['start_time'], '%Y-%m-%dT%H:%M'
        ))
        end_time = ist.localize(datetime.strptime(
            request.form['end_time'], '%Y-%m-%dT%H:%M'
        ))

        # Validation
        if end_time <= start_time:
            flash('End time must be after start time', 'danger')
            return redirect(url_for('reservation.dashboard'))
            
        if start_time < current_time:
            flash('Start time cannot be in the past', 'danger')
            return redirect(url_for('reservation.dashboard'))

        # Check availability
        max_users = {
            'pc': 1,
            'rutomatrix': 1,
            'pulseview': 1,
            'ct': 1
        }.get(ip_type.split('-')[0].lower(), 1)

        conflicts = Reservation.query.filter(
            Reservation.device_id == device_id,
            Reservation.ip_type.ilike(f'%{ip_type}%'),
            Reservation.end_time >= current_time,
            Reservation.start_time < end_time,
            Reservation.end_time > start_time
        ).count()

        if conflicts >= max_users:
            flash(f'Maximum {max_users} user(s) allowed for {ip_type}', 'danger')
            return redirect(url_for('reservation.dashboard'))

        # Create records
        reservation = Reservation(
            device_id=device_id,
            user_id=current_user.id,
            ip_type=ip_type,
            start_time=start_time,
            end_time=end_time
        )
        
        # Automatically create DeviceUsage record
        usage_record = DeviceUsage(
            device_id=device_id,
            user_id=current_user.id,
            reservation_id=reservation.id,
            ip_type=ip_type,
            actual_start_time=start_time,  # Same as reservation time
            actual_end_time=end_time,      # Same as reservation time
            status='completed',            # Mark as completed immediately
            ip_address=request.remote_addr # Capture IP at booking time
        )

        db.session.add(reservation)
        db.session.add(usage_record)
        db.session.commit()

        flash('Booking successful!', 'success')
        return redirect(url_for('reservation.dashboard'))

    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Booking error: {str(e)}", exc_info=True)
        flash('Booking failed', 'danger')
        return redirect(url_for('reservation.dashboard'))


'''@reservation_bp.route('/cancel/<int:reservation_id>', methods=['POST'])
@login_required
def cancel_reservation(reservation_id):
    reservation = Reservation.query.get_or_404(reservation_id)
    ist = pytz.timezone('Asia/Kolkata')
    now = datetime.now(ist)
    
    # Allow cancellation if: user owns it AND (active or upcoming)
    if not (reservation.user_id == current_user.id and 
            reservation.start_time <= now <= reservation.end_time):
        flash('You can only cancel your own active or upcoming reservations', 'danger')
        return redirect(url_for('reservation.dashboard'))
    
    try:
        db.session.delete(reservation)
        db.session.commit()
        flash('Reservation cancelled successfully', 'success')
        current_app.logger.info(
            f"User {current_user.id} canceled reservation {reservation_id} "
            f"(Device: {reservation.device_id})"
        )
    except Exception as e:
        db.session.rollback()
        flash('Failed to cancel reservation', 'danger')
        current_app.logger.error(f"Cancellation error: {str(e)}")
    
    return redirect(url_for('reservation.dashboard'))'''

@reservation_bp.route('/cancel/<int:reservation_id>', methods=['POST'])
@login_required
def cancel_reservation(reservation_id):
    reservation = Reservation.query.get_or_404(reservation_id)
    ist = pytz.timezone('Asia/Kolkata')
    now = datetime.now(ist)
    
    # Allow cancellation if: user owns it AND reservation is upcoming or active
    if not (reservation.user_id == current_user.id and 
            now <= reservation.end_time):  # Changed condition to check if current time is before end time
        flash('You can only cancel your own upcoming or active reservations', 'danger')
        return redirect(url_for('reservation.dashboard'))
    
    try:
        db.session.delete(reservation)
        db.session.commit()
        flash('Reservation cancelled successfully', 'success')
        current_app.logger.info(
            f"User {current_user.id} canceled reservation {reservation_id} "
            f"(Device: {reservation.device_id})"
        )
    except Exception as e:
        db.session.rollback()
        flash('Failed to cancel reservation', 'danger')
        current_app.logger.error(f"Cancellation error: {str(e)}")
    
    return redirect(url_for('reservation.dashboard'))


@reservation_bp.route('/admin/cancel/<int:reservation_id>', methods=['POST'])
@login_required
def admin_cancel_reservation(reservation_id):
    if current_user.role != 'admin':  # You can keep this or use current_user.is_admin() after adding the method
        flash('Admin privileges required', 'danger')
        return redirect(url_for('reservation.dashboard'))
    
    reservation = Reservation.query.get_or_404(reservation_id)
    device_id = reservation.device_id
    user_id = reservation.user_id
    
    try:
        db.session.delete(reservation)
        db.session.commit()
        
        flash(f'Admin: Successfully canceled reservation #{reservation_id}', 'success')
        current_app.logger.info(
            f"Admin {current_user.id} canceled reservation {reservation_id} "
            f"(User: {user_id}, Device: {device_id})"
        )
        
    except Exception as e:
        db.session.rollback()
        flash(f'Failed to cancel reservation: {str(e)}', 'danger')
        current_app.logger.error(f"Admin cancellation error: {str(e)}")
    
    return redirect(url_for('reservation.dashboard'))

