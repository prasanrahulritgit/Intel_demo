from flask import Flask, jsonify, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from models import Reservation, db, Device, User
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from apscheduler.schedulers.background import BackgroundScheduler
from datetime import datetime, timedelta, timezone



app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///device_list.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = 'your-secret-key-here'  # Change this to a strong random key in production

migrate = Migrate(app, db)

# Initialize extensions
db.init_app(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'


def cleanup_expired_reservations():
    """Background task to clean up expired reservations"""
    with app.app_context():
        try:
            now = datetime.now()
            expired_count = db.session.execute(
                db.delete(Reservation)
                .where(Reservation.end_time < now)
            ).rowcount
            db.session.commit()
            app.logger.info(f"Cleaned up {expired_count} expired reservations")
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Cleanup error: {str(e)}")

# Initialize scheduler when app starts
scheduler = BackgroundScheduler(daemon=True)
scheduler.add_job(
    func=cleanup_expired_reservations,
    trigger='interval',
    minutes=1  # Run every 1 minutes
)
scheduler.start()


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Create tables and admin user
with app.app_context():
    db.create_all()
    if not User.query.filter_by(user_name='admin').first():
        admin = User(
            user_name='admin',
            user_ip='127.0.0.1',
            password_hash=generate_password_hash('admin123'),  # Change password in production!
            role='admin',
            created_at=datetime.utcnow()
        )
        db.session.add(admin)
        db.session.commit()

# ========================
# AUTHENTICATION ROUTES
# ========================

@app.route('/login', methods=['GET', 'POST'])
def login():
    from forms import LoginForm  
    form = LoginForm()  
    
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        
        user = User.query.filter_by(user_name=username).first()
        
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            flash('Logged in successfully!', 'success')
            next_page = request.args.get('next')
            return redirect(next_page or url_for('dashboard'))
        flash('Invalid username or password', 'danger')
    
    return render_template('login.html', form=form)  # Pass form to template

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        ip_address = request.form.get('ip_address')
        
        if User.query.filter_by(user_name=username).first():
            flash('Username already exists', 'danger')
            return redirect(url_for('register'))
        
        new_user = User(
            user_name=username,
            user_ip=ip_address,
            password_hash=generate_password_hash(password),
            role='user',
            created_at=datetime.utcnow()
        )
        
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

'''@app.route('/dashboard')
@login_required
def dashboard():
    # First clean up expired reservations for current user
    now = make_naive(datetime.now(timezone.utc))
    
    # Delete expired reservations
    expired_count = db.session.execute(
        db.delete(Reservation)
        .where(Reservation.user_id == current_user.id)
        .where(Reservation.end_time < now)
    ).rowcount
    
    if expired_count > 0:
        db.session.commit()
        app.logger.info(f"Cleaned up {expired_count} expired reservations for user {current_user.id}")

    # Get remaining reservations
    devices = Device.query.all()
    reservations = Reservation.query.filter(
        Reservation.user_id == current_user.id
    ).order_by(Reservation.start_time).all()
    
    return render_template(
        'devices.html' if current_user.role == 'admin' else 'reservation.html',
        devices=devices,
        reservations=reservations,
        now=now
    )'''

@app.route('/dashboard')
@login_required
def dashboard():
    # First clean up expired reservations for current user
    now = make_naive(datetime.now(timezone.utc))
    
    # Delete expired reservations
    expired_count = db.session.execute(
        db.delete(Reservation)
        .where(Reservation.user_id == current_user.id)
        .where(Reservation.end_time < now)
    ).rowcount
    
    if expired_count > 0:
        db.session.commit()
        app.logger.info(f"Cleaned up {expired_count} expired reservations for user {current_user.id}")

    # Get all devices and all reservations (both current user's and others')
    devices = Device.query.all()
    all_reservations = Reservation.query.order_by(Reservation.start_time).all()
    
    # Separate current user's reservations from others'
    user_reservations = [r for r in all_reservations if r.user_id == current_user.id]
    other_reservations = [r for r in all_reservations if r.user_id != current_user.id]
    
    return render_template(
        'devices.html' if current_user.role == 'admin' else 'reservation.html',
        devices=devices,
        user_reservations=user_reservations,  # Current user's reservations
        other_reservations=other_reservations,  # Other users' reservations
        now=now,
        current_user=current_user  # Pass current user to template
    )

# ========================
# DEVICE MANAGEMENT ROUTES (ADMIN ONLY)
# ========================

@app.route('/')
@login_required
def index():
    if current_user.role != 'admin':
        return redirect(url_for('dashboard'))
    devices = Device.query.all()
    return render_template('devices.html', devices=devices)

@app.route('/api/devices', methods=['GET'])
def get_all_devices():
    if current_user.role != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    
    devices = Device.query.all()
    devices_list = [device.to_dict() for device in devices]
    return jsonify({'devices': devices_list})

@app.route('/api/devices/<device_id>/rutomatrix_ip', methods=['GET'])
@login_required
def get_rutomatrix_ip(device_id):
    device = Device.query.get_or_404(device_id)
    return jsonify({
        'device_id': device.device_id,
        'rutomatrix_ip': device.rutomatrix_ip
    })


@app.route('/api/devices/<device_id>/ctp1_ip', methods=['GET'])
@login_required
def get_ctp1_ip(device_id):
    device = Device.query.get_or_404(device_id)
    return jsonify({
        'device_id': device.device_id,
        'ctp1_ip': device.ctp1_ip
    })

@app.route('/api/devices/<device_id>/ctp2_ip', methods=['GET'])
@login_required
def get_ctp2_ip(device_id):
    device = Device.query.get_or_404(device_id)
    return jsonify({
        'device_id': device.device_id,
        'ctp2_ip': device.ctp2_ip
    })

@app.route('/api/devices/<device_id>/ctp3_ip', methods=['GET'])
@login_required
def get_ctp3_ip(device_id):
    device = Device.query.get_or_404(device_id)
    return jsonify({
        'device_id': device.device_id,
        'ctp3_ip': device.ctp3_ip
    })


@app.route('/add', methods=['POST'])
@login_required
def add_device():
    if current_user.role != 'admin':
        flash('You do not have permission to perform this action', 'danger')
        return redirect(url_for('dashboard'))
    
    try:
        new_device = Device(
            device_id=request.form['device_id'],
            rutomatrix_ip=request.form['rutomatrix_ip'],
            ctp1_ip=request.form['ctp1_ip'],
            ctp2_ip=request.form['ctp2_ip'],
            ctp3_ip=request.form['ctp3_ip']
        )
        db.session.add(new_device)
        db.session.commit()
        flash('Device added successfully!', 'success')
    except ValueError as e:
        flash(str(e), 'error')
    except Exception as e:
        flash('Error adding device. Device ID may already exist.', 'error')
    return redirect(url_for('index'))

@app.route('/edit/<device_id>/<field>')
@login_required
def edit_device_field(device_id, field):
    if current_user.role != 'admin':
        flash('You do not have permission to perform this action', 'danger')
        return redirect(url_for('dashboard'))
    
    device = Device.query.get_or_404(device_id)
    valid_fields = ['rutomatrix_ip', 'ctp1_ip', 'ctp2_ip', 'ctp3_ip']
    if field not in valid_fields:
        flash('Invalid field specified!', 'error')
        return redirect(url_for('index'))
    
    return render_template('edit_device.html', 
                         device=device, 
                         field=field,
                         field_name=field.replace('_', ' ').upper())

@app.route('/update/<device_id>/<field>', methods=['POST'])
@login_required
def update_device_field(device_id, field):
    if current_user.role != 'admin':
        flash('You do not have permission to perform this action', 'danger')
        return redirect(url_for('dashboard'))
    
    device = Device.query.get_or_404(device_id)
    valid_fields = ['rutomatrix_ip', 'ctp1_ip', 'ctp2_ip', 'ctp3_ip']
    
    if field not in valid_fields:
        flash('Invalid field specified!', 'error')
        return redirect(url_for('index'))
    
    try:
        setattr(device, field, request.form['new_value'])
        device.validate_ips()
        db.session.commit()
        flash(f'{field.replace("_", " ").title()} updated successfully!', 'success')
    except ValueError as e:
        flash(str(e), 'error')
    except Exception as e:
        flash('Error updating device.', 'error')
    
    return redirect(url_for('index'))

@app.route('/delete/<device_id>')
@login_required
def delete_device(device_id):
    if current_user.role != 'admin':
        flash('You do not have permission to perform this action', 'danger')
        return redirect(url_for('dashboard'))
    
    device = Device.query.get_or_404(device_id)
    db.session.delete(device)
    db.session.commit()
    flash('Device deleted successfully!', 'success')
    return redirect(url_for('index'))

# ========================
# USER MANAGEMENT ROUTES (ADMIN ONLY)
# ========================

@app.route('/users')
@login_required
def user_index():
    if current_user.role != 'admin':
        flash('You do not have permission to view this page', 'danger')
        return redirect(url_for('dashboard'))
    
    users = User.query.all()
    return render_template('users.html', users=users)

@app.route('/users/add', methods=['POST'])
@login_required
def add_user():
    if current_user.role != 'admin':
        flash('You do not have permission to perform this action', 'danger')
        return redirect(url_for('dashboard'))
    
    try:
        new_user = User(
            user_name=request.form['user_name'],
            user_ip=request.form['user_ip'],
            password_hash=generate_password_hash(request.form['password']),
            role=request.form.get('role', 'user'),
            created_at=datetime.utcnow()
        )
        db.session.add(new_user)
        db.session.commit()
        flash('User added successfully!', 'success')
    except Exception as e:
        flash(f'Error adding user: {str(e)}', 'error')
    return redirect(url_for('user_index'))

@app.route('/users/edit/<int:user_id>')
@login_required
def edit_user(user_id):
    user = User.query.get_or_404(user_id)
    return render_template('edit_user.html', user=user)

@app.route('/users/update/<int:user_id>', methods=['POST'])
@login_required
def update_user(user_id):
    user = User.query.get_or_404(user_id)
    try:
        user.user_name = request.form['user_name']
        user.user_ip = request.form['user_ip']
        if request.form['password']:  # Only update password if provided
            user.password = request.form['password']
        db.session.commit()
        flash('User updated successfully!', 'success')
    except Exception as e:
        flash(f'Error updating user: {str(e)}', 'error')
    return redirect(url_for('user_index'))


@app.route('/users/delete/<int:user_id>')
@login_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    flash('User deleted successfully!', 'success')
    return redirect(url_for('user_index'))



# ========================
# RESERVATION ROUTES (FOR REGULAR USERS)
# ========================



def make_naive(utc_dt):
    """Convert timezone-aware datetime to naive (for SQLite storage)"""
    return utc_dt.replace(tzinfo=None) if utc_dt.tzinfo else utc_dt

def make_aware(naive_dt):
    """Convert naive datetime to timezone-aware (UTC) for comparison"""
    if naive_dt is None:
        return None
    if hasattr(naive_dt, 'tzinfo'):  # Already a datetime object
        return naive_dt.replace(tzinfo=timezone.utc) if not naive_dt.tzinfo else naive_dt
    return naive_dt  # Return as-is if not a datetime object


@app.route('/reserve', methods=['POST', 'GET'])
@login_required
def make_reservation():
    try:
        # Get form data
        device_id = request.form['device_id']
        ip_type = request.form['ip_type']
        start_time = datetime.strptime(request.form['start_time'], '%Y-%m-%dT%H:%M')
        end_time = datetime.strptime(request.form['end_time'], '%Y-%m-%dT%H:%M')
        now = datetime.now()

        # Validate times
        if end_time <= start_time:
            flash('End time must be after start time', 'danger')
        elif start_time < now:
            flash('Start time cannot be in the past', 'danger')
        else:
            # Check for conflicts
            buffer = timedelta(minutes=15)
            max_users = 1 if ip_type == 'rutomatrix' else 3
            
            conflicts = Reservation.query.filter(
                Reservation.device_id == device_id,
                Reservation.ip_type == ip_type,
                Reservation.start_time < end_time + buffer,
                Reservation.end_time > start_time - buffer
            ).count()
            
            if conflicts >= max_users:
                flash('Time slot unavailable - maximum users reached', 'danger')
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
                flash('Reservation created successfully!', 'success')
                
    except ValueError:
        flash('Invalid date/time format', 'danger')
    except Exception as e:
        db.session.rollback()
        flash('Failed to create reservation', 'danger')
        app.logger.error(f"Reservation error: {str(e)}")
    
    return redirect(url_for('dashboard'))




@app.route('/cancel/<int:reservation_id>', methods=['POST'])
@login_required
def cancel_reservation(reservation_id):
    reservation = Reservation.query.get_or_404(reservation_id)
    
    if not reservation.can_cancel(current_user):
        flash('You can only cancel your own upcoming reservations', 'danger')
        return redirect(url_for('dashboard'))
    
    try:
        db.session.delete(reservation)
        db.session.commit()
        flash('Reservation cancelled successfully', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Failed to cancel reservation', 'danger')
        app.logger.error(f"Cancellation error: {str(e)}")
    
    return redirect(url_for('dashboard'))




if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)