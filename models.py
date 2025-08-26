from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timezone, date
from db import db  # Assuming you have a db instance in db.py

# ---------------------- USER ----------------------
class User(db.Model, UserMixin):
    __tablename__ = 'user'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False) # 'admin', 'milkman', 'customer'

    is_active_flag = db.Column('is_active', db.Boolean, default=True)
    is_active_admin = db.Column(db.Boolean, default=True)
    deactivation_reason = db.Column(db.Text, nullable=True)

    name = db.Column(db.String(150))
    phone = db.Column(db.String(20), nullable=True)
    email = db.Column(db.String(150), nullable=True)

    customer = db.relationship('Customer', uselist=False, foreign_keys='Customer.user_id')

    @property
    def is_active(self):
        """
        Property for Flask-Login. An admin/milkman is only active if both their
        main account and their admin privileges are active.
        """
        if self.role in ['admin', 'milkman']:
            return self.is_active_flag and self.is_active_admin
        return self.is_active_flag

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def get_id(self):
        return str(self.id)

    def __repr__(self):
        return f"<User {self.username} ({self.role})>"

# ---------------------- CUSTOMER ----------------------
class Customer(db.Model):
    __tablename__ = 'customer'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    milkman_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    name = db.Column(db.String(150), nullable=False)
    phone = db.Column(db.String(30), nullable=False)
    address = db.Column(db.String(250), nullable=False)

    cow_rate = db.Column(db.Float, nullable=False, default=0.0)
    buffalo_rate = db.Column(db.Float, nullable=False, default=0.0)
    active = db.Column(db.Boolean, default=True)

    requirements = db.relationship('Requirement', back_populates='customer', cascade="all, delete-orphan")
    user = db.relationship('User', foreign_keys=[user_id], back_populates='customer')
    milkman = db.relationship('User', foreign_keys=[milkman_id])
    payments = db.relationship('Payment', back_populates='customer', cascade="all, delete-orphan")

# ---------------------- FARMER ----------------------
class Farmer(db.Model, UserMixin):
    __tablename__ = 'farmer'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    # UPDATED: Added role column for consistency with the User model
    role = db.Column(db.String(20), nullable=False, default='farmer')

    name = db.Column(db.String(100))
    phone = db.Column(db.String(20))
    address = db.Column(db.String(100))
    cow_rate = db.Column(db.Float, default=0.0)
    buffalo_rate = db.Column(db.Float, default=0.0)
    active = db.Column(db.Boolean, default=True)

    milkman_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    milkman = db.relationship('User', backref='farmers', foreign_keys=[milkman_id])

    # REMOVED: The user_id and user relationship are no longer needed,
    # as Farmer is now its own user entity.

    @property
    def is_active(self):
        """Property for Flask-Login, checks the farmer's own active status."""
        return self.active

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def get_id(self):
        return str(self.id)

    def __repr__(self):
        return f"<Farmer {self.username}>"

# ---------------------- REQUIREMENT ----------------------
from datetime import datetime
from db import db

class Requirement(db.Model):
    """
    Represents a single milk requirement (order) for a customer on a specific date and session.
    """
    __tablename__ = 'requirement'

    id = db.Column(db.Integer, primary_key=True)
    customer_id = db.Column(db.Integer, db.ForeignKey('customer.id'), nullable=False)

    date_requested = db.Column(db.Date, nullable=False, default=datetime.utcnow)
    session = db.Column(db.String(10), nullable=False)  # 'morning' or 'evening'

    cow_qty = db.Column(db.Float, default=0.0)
    buffalo_qty = db.Column(db.Float, default=0.0)

    # Stores the milk rate at the time of the order to prevent changes from affecting past records
    cow_rate_at_order = db.Column(db.Float, nullable=False)
    buffalo_rate_at_order = db.Column(db.Float, nullable=False)

    status = db.Column(db.String(20), default='pending') # e.g., 'pending', 'paid', 'unpaid', 'cancelled'
    status_update_time = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    customer = db.relationship('Customer', back_populates='requirements')
    payments = db.relationship('Payment', back_populates='requirement', cascade="all, delete-orphan")

    # Ensures a customer can only have one requirement entry per session on any given day
    __table_args__ = (
        db.UniqueConstraint('customer_id', 'date_requested', 'session', name='_cust_date_session_uc'),
    )

    def __repr__(self):
        return f"<Requirement ID: {self.id} for Customer {self.customer_id} on {self.date_requested}>"



# ---------------------- MILK RATE ----------------------
class MilkRate(db.Model):
    __tablename__ = 'milkrate'
    id = db.Column(db.Integer, primary_key=True)
    milkman_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    for_group = db.Column(db.String(20), nullable=False)  # 'customer' or 'farmer'
    customer_id = db.Column(db.Integer, db.ForeignKey('customer.id'), nullable=True)
    farmer_id = db.Column(db.Integer, db.ForeignKey('farmer.id'), nullable=True)
    cow_rate = db.Column(db.Float, nullable=False)
    buffalo_rate = db.Column(db.Float, nullable=False)
    date_effective = db.Column(db.Date, default=date.today)

    customer = db.relationship('Customer', backref='milk_rates', foreign_keys=[customer_id])
    farmer = db.relationship('Farmer', backref='milk_rates', foreign_keys=[farmer_id])


# ---------------------- COLLECTION ----------------------
class Collection(db.Model):
    __tablename__ = 'collection'

    id = db.Column(db.Integer, primary_key=True)
    farmer_id = db.Column(db.Integer, db.ForeignKey('farmer.id'), nullable=False)
    date = db.Column(db.Date, nullable=False)
    session = db.Column(db.String(20), nullable=False)
    cow_qty = db.Column(db.Float, nullable=False, default=0)
    buffalo_qty = db.Column(db.Float, nullable=False, default=0)
    status = db.Column(db.String(16), nullable=False, default='unpaid')
    cow_amount = db.Column(db.Float, nullable=False, default=0)
    buffalo_amount = db.Column(db.Float, nullable=False, default=0)
    total_amount = db.Column(db.Float, nullable=False, default=0)
    remarks = db.Column(db.String(128))

    # UPDATED: Use a timezone-aware default for the new timestamp column
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        db.UniqueConstraint('farmer_id', 'date', 'session'),
    )


# ---------------------- PAYMENT ----------------------
class Payment(db.Model):
    __tablename__ = 'payment'

    id = db.Column(db.Integer, primary_key=True)
    customer_id = db.Column(db.Integer, db.ForeignKey('customer.id'), nullable=False)
    requirement_id = db.Column(db.Integer, db.ForeignKey('requirement.id'), nullable=True)
    amount = db.Column(db.Float, nullable=False)
    bill_date = db.Column(db.DateTime, default=datetime.utcnow)
    total_amount = db.Column(db.Float, nullable=False)
    payment_mode = db.Column(db.String(20), default='cash')
    collected_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    remarks = db.Column(db.String(255))

    customer = db.relationship('Customer', back_populates='payments')
    requirement = db.relationship('Requirement', back_populates='payments')
    collected_by = db.relationship('User', foreign_keys=[collected_by_id])

class Expense(db.Model):
    __tablename__ = 'expense'
    id = db.Column(db.Integer, primary_key=True)
    milkman_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    date = db.Column(db.Date, nullable=False, default=date.today)
    expense_type = db.Column(db.String(50), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    remarks = db.Column(db.String(255), nullable=True)

    milkman = db.relationship('User', backref='expenses')

class CasualSale(db.Model):
    __tablename__ = 'casual_sale'
    id = db.Column(db.Integer, primary_key=True)
    milkman_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    date = db.Column(db.Date, nullable=False, default=date.today)
    session = db.Column(db.String(10), nullable=False)
    cow_qty = db.Column(db.Float, default=0.0)
    buffalo_qty = db.Column(db.Float, default=0.0)
    amount_collected = db.Column(db.Float, nullable=False)

    milkman = db.relationship('User', backref='casual_sales')