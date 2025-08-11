from apscheduler.schedulers.background import BackgroundScheduler
from datetime import datetime
from models import DeviceUsage, db, Reservation
from flask import app, current_app
import pytz

scheduler = BackgroundScheduler()

def delete_expired_reservations():
    try:
        with current_app.app_context():
            ist = pytz.timezone('Asia/Kolkata')
            current_time = datetime.now(ist)
            
            result = db.session.execute(
                db.delete(Reservation)
                .where(Reservation.end_time < current_time)
            )
            db.session.commit()
            
            count = result.rowcount
            if count > 0:
                current_app.logger.info(f"Auto-deleted {count} expired reservations")
            return count
            
    except Exception as e:
        current_app.logger.error(f"Cleanup failed: {str(e)}")
        db.session.rollback()
        return 0

def init_scheduler(app):
    """Initialize the scheduler with the Flask app"""
    with app.app_context():
        scheduler.add_job(
            func=delete_expired_reservations,
            trigger='interval',
            minutes=1,  # Run every minute
            id='reservation_cleanup_job',
            replace_existing=True
        )
        
        if not scheduler.running:
            scheduler.start()
        
        @app.teardown_appcontext
        def shutdown_scheduler(exception=None):
            if scheduler.running:
                scheduler.shutdown()

def delete_expired_job():
    with app.app_context():
        count = Reservation.delete_expired()
        app.logger.info(f"Scheduler deleted {count} expired reservations")

# Add this when initializing scheduler
scheduler.add_job(
    delete_expired_job,
    'interval',
    minutes=1,
    id='expired_cleanup'
)

def update_statuses():
    with app.app_context():
        try:
            # Update reservation statuses
            reservations = Reservation.query.all()
            for res in reservations:
                res.update_status()
                db.session.add(res)
            
            # Update usage statuses
            usages = DeviceUsage.query.all()
            for usage in usages:
                usage.update_status()
                db.session.add(usage)
                
            db.session.commit()
        except Exception as e:
            current_app.logger.error(f"Error updating statuses: {str(e)}")
            db.session.rollback()