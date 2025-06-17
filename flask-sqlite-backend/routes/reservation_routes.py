from flask import Blueprint, current_app, render_template, redirect, url_for, flash, request
from flask_login import current_user, login_required
from models import Reservation, Device, db
from datetime import datetime, timedelta, timezone

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
    # Get current time in UTC and convert to naive for SQLite if needed
    now_utc = datetime.now(timezone.utc)
    now_naive = now_utc.replace(tzinfo=None)  # For SQLite comparison
    
    # Delete expired reservations
    expired_count = db.session.execute(
        db.delete(Reservation)
        .where(Reservation.user_id == current_user.id)
        .where(Reservation.end_time < now_naive)
    ).rowcount
    
    if expired_count > 0:
        db.session.commit()
        current_app.logger.info(f"Cleaned up {expired_count} expired reservations for user {current_user.id}")

    # Get all devices and reservations
    devices = Device.query.all()
    all_reservations = Reservation.query.order_by(Reservation.start_time).all()
    
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
        now=now_utc,  # Pass timezone-aware datetime to template
        current_user=current_user
    )

@reservation_bp.route('/reserve', methods=['POST'])
@login_required
def make_reservation():
    try:
        # Get form data
        device_id = request.form['device_id']
        ip_type = request.form['ip_type']
        
        # Convert to timezone-aware UTC datetimes
        start_time = datetime.strptime(
            request.form['start_time'], 
            '%Y-%m-%dT%H:%M'
        ).replace(tzinfo=timezone.utc)
        
        end_time = datetime.strptime(
            request.form['end_time'], 
            '%Y-%m-%dT%H:%M'
        ).replace(tzinfo=timezone.utc)
        
        now = datetime.now(timezone.utc)

        # Validation (all comparisons between timezone-aware datetimes)
        if end_time <= start_time:
            flash('End time must be after start time', 'danger')
        elif start_time < now:
            flash('Start time cannot be in the past', 'danger')
        else:
            buffer = timedelta(minutes=15)
            max_users = 1 if ip_type == 'rutomatrix' else 3
            
            # All comparisons use timezone-aware datetimes
            conflicts = Reservation.query.filter(
                Reservation.device_id == device_id,
                Reservation.ip_type == ip_type,
                Reservation.start_time < (end_time + buffer),
                Reservation.end_time > (start_time - buffer)
            ).count()
            
            if conflicts >= max_users:
                flash('Time slot unavailable - maximum users reached', 'danger')
            else:
                reservation = Reservation(
                    device_id=device_id,
                    user_id=current_user.id,
                    ip_type=ip_type,
                    start_time=start_time,
                    end_time=end_time
                )
                db.session.add(reservation)
                db.session.commit()
                flash('Reservation created successfully!', 'success')
                
    except ValueError:
        flash('Invalid date/time format', 'danger')
    except Exception as e:
        db.session.rollback()
        flash('Failed to create reservation', 'danger')
        current_app.logger.error(f"Reservation error: {str(e)}", exc_info=True)
    
    return redirect(url_for('reservation.dashboard'))



@reservation_bp.route('/cancel/<int:reservation_id>', methods=['POST'])
@login_required
def cancel_reservation(reservation_id):
    reservation = Reservation.query.get_or_404(reservation_id)
    
    if not reservation.can_cancel(current_user):
        flash('You can only cancel your own upcoming reservations', 'danger')
        return redirect(url_for('reservation.dashboard'))
    
    try:
        db.session.delete(reservation)
        db.session.commit()
        flash('Reservation cancelled successfully', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Failed to cancel reservation', 'danger')
        current_app.logger.error(f"Cancellation error: {str(e)}")
    
    return redirect(url_for('reservation.dashboard'))