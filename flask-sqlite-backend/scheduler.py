from apscheduler.schedulers.background import BackgroundScheduler
from datetime import datetime
from models import db, Reservation
from flask import current_app

scheduler = BackgroundScheduler()

def delete_expired_reservations():
    with current_app.app_context():
        try:
            current_time = datetime.utcnow()
            expired_reservations = Reservation.query.filter(
                Reservation.end_time < current_time
            ).all()
            
            count = 0
            for reservation in expired_reservations:
                db.session.delete(reservation)
                count += 1
            
            db.session.commit()
            current_app.logger.info(f"Deleted {count} expired reservations")
            return count
        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Error deleting expired reservations: {str(e)}")
            return 0

def init_scheduler(app):
    scheduler.add_job(
        func=delete_expired_reservations,
        trigger='interval',
        minutes=1,
        id='reservation_cleanup_job',
        replace_existing=True
    )
    
    if not scheduler.running:
        scheduler.start()
    
    # Proper shutdown when app exits
    @app.teardown_appcontext
    def shutdown_scheduler(exception=None):
        if scheduler.running:
            scheduler.shutdown()