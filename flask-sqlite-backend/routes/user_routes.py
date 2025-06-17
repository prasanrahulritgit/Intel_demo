from flask import Blueprint, render_template, redirect, url_for, flash, request, jsonify
from flask_login import login_required, current_user
from models import User, db
from werkzeug.security import generate_password_hash
from datetime import datetime

user_bp = Blueprint('user', __name__)

@user_bp.route('/users')
@login_required
def index():
    if current_user.role != 'admin':
        flash('You do not have permission to view this page', 'danger')
        return redirect(url_for('reservation.dashboard'))
    
    users = User.query.all()
    return render_template('users.html', users=users)

@user_bp.route('/users/add', methods=['POST'])
@login_required
def add():
    if current_user.role != 'admin':
        flash('You do not have permission to perform this action', 'danger')
        return redirect(url_for('reservation.dashboard'))
    
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
    return redirect(url_for('user.index'))

@user_bp.route('/users/edit/<int:user_id>')
@login_required
def edit(user_id):
    if current_user.role != 'admin':
        flash('You do not have permission to perform this action', 'danger')
        return redirect(url_for('reservation.dashboard'))
    
    user = User.query.get_or_404(user_id)
    return render_template('edit_user.html', user=user)

@user_bp.route('/users/update/<int:user_id>', methods=['POST'])
@login_required
def update(user_id):
    if current_user.role != 'admin':
        flash('You do not have permission to perform this action', 'danger')
        return redirect(url_for('reservation.dashboard'))
    
    user = User.query.get_or_404(user_id)
    try:
        user.user_name = request.form['user_name']
        user.user_ip = request.form['user_ip']
        if request.form['password']:  # Only update password if provided
            user.password_hash = generate_password_hash(request.form['password'])
        db.session.commit()
        flash('User updated successfully!', 'success')
    except Exception as e:
        flash(f'Error updating user: {str(e)}', 'error')
    return redirect(url_for('user.index'))

@user_bp.route('/users/delete/<int:user_id>')
@login_required
def delete(user_id):
    if current_user.role != 'admin':
        flash('You do not have permission to perform this action', 'danger')
        return redirect(url_for('reservation.dashboard'))
    
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    flash('User deleted successfully!', 'success')
    return redirect(url_for('user.index'))