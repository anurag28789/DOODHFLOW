from app import app, db
from models import User

with app.app_context():
    admin_username = "admin"
    admin_password = "123456"

    existing_admin = User.query.filter_by(username=admin_username).first()
    if existing_admin:
        print("Admin user already exists.")
    else:
        admin_user = User(
            username=admin_username,
            role="admin",
            is_active_flag=True,      # set the column, not the property
            is_active_admin=True
        )
        admin_user.set_password(admin_password)
        db.session.add(admin_user)
        db.session.commit()
        print(f"Admin user '{admin_username}' created successfully.")
