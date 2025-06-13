from flask import Flask, jsonify, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from models import Reservation, db, Device, User
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from apscheduler.schedulers.background import BackgroundScheduler
from atexit import register


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///device_list.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = 'your-secret-key-here'  # Change this to a strong random key in production

migrate = Migrate(app, db)

# Initialize extensions
db.init_app(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

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
    from forms import LoginForm  # Import your form class
    form = LoginForm()  # Create form instance
    
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

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role == 'admin':
        devices = Device.query.all()
        return render_template('devices.html', devices=devices)
    else:
        devices = Device.query.all()
        return render_template('reservation.html', devices=devices)
    


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

'''@app.route('/reserve', methods=['POST'])
@login_required
def make_reservation():
    if request.method == 'POST':
        device_id = request.form['device_id']
        ip_type = request.form['ip_type']
        
        try:
            start_time = datetime.strptime(request.form['start_time'], '%Y-%m-%dT%H:%M')
            end_time = datetime.strptime(request.form['end_time'], '%Y-%m-%dT%H:%M')
        except ValueError:
            flash('Invalid date/time format', 'danger')
            return redirect(url_for('dashboard'))
        
        # Check time validity
        if end_time <= start_time:
            flash('End time must be after start time', 'danger')
            return redirect(url_for('dashboard'))
        
        if start_time < datetime.now():
            flash('Start time cannot be in the past', 'danger')
            return redirect(url_for('dashboard'))
        
        # Check maximum concurrent users
        max_users = 1 if ip_type == 'rutomatrix' else 3
        current_reservations = Reservation.query.filter(
            Reservation.device_id == device_id,
            Reservation.ip_type == ip_type,
            Reservation.start_time <= end_time,
            Reservation.end_time >= start_time
        ).count()
        
        if current_reservations >= max_users:
            flash(f'Cannot reserve - {ip_type} already has maximum users ({max_users})', 'danger')
            return redirect(url_for('dashboard'))
        
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
    
    return redirect(url_for('dashboard'))'''

@app.route('/reserve', methods=['POST', 'GET'])
@login_required
def make_reservation():
    if request.method == 'POST':
        # First, clean up any of the CURRENT USER'S expired reservations
        now = datetime.now()
        expired_reservations = Reservation.query.filter(
            Reservation.end_time < now,
            Reservation.user_id == current_user.id  # Only delete current user's reservations
        ).all()
        
        for reservation in expired_reservations:
            db.session.delete(reservation)
        db.session.commit()

        # Process new reservation
        device_id = request.form['device_id']
        ip_type = request.form['ip_type']
        
        try:
            start_time = datetime.strptime(request.form['start_time'], '%Y-%m-%dT%H:%M')
            end_time = datetime.strptime(request.form['end_time'], '%Y-%m-%dT%H:%M')
        except ValueError:
            flash('Invalid date/time format', 'danger')
            return redirect(url_for('dashboard'))
        
        # Enhanced time validation
        if end_time <= start_time:
            flash('End time must be after start time', 'danger')
            return redirect(url_for('dashboard'))
        
        if start_time < datetime.now():
            flash('Start time cannot be in the past', 'danger')
            return redirect(url_for('dashboard'))
        
        # Check reservation overlap (including buffer time if needed)
        buffer_minutes = 15  # Optional buffer between reservations
        max_users = 1 if ip_type == 'rutomatrix' else 3
        
        overlapping_reservations = Reservation.query.filter(
            Reservation.device_id == device_id,
            Reservation.ip_type == ip_type,
            Reservation.start_time <= (end_time + timedelta(minutes=buffer_minutes)),
            Reservation.end_time >= (start_time - timedelta(minutes=buffer_minutes))
        ).count()
        
        if overlapping_reservations >= max_users:
            flash(f'Time slot unavailable - {ip_type} already has maximum users ({max_users})', 'danger')
            return redirect(url_for('dashboard'))
        
        # Create new reservation
        try:
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
        except Exception as e:
            db.session.rollback()
            flash('Failed to create reservation. Please try again.', 'danger')
            app.logger.error(f"Reservation failed: {str(e)}")
    
    return redirect(url_for('dashboard'))

@app.route('/cancel_reservation/<int:reservation_id>', methods=['POST'])
@login_required
def cancel_reservation(reservation_id):
    reservation = Reservation.query.get_or_404(reservation_id)
    
    # Only allow cancellation by owner or admin
    if reservation.user_id != current_user.id and current_user.role != 'admin':
        flash('You can only cancel your own reservations', 'danger')
        return redirect(url_for('dashboard'))
    
    db.session.delete(reservation)
    db.session.commit()
    flash('Reservation cancelled successfully', 'success')
    return redirect(url_for('dashboard'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)