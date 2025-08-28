from flask import (
    Flask, render_template, redirect, url_for, flash,
    request, abort, session, Response
)
from flask_login import (
    LoginManager, login_user, login_required,
    logout_user, current_user, UserMixin
)
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_wtf.csrf import CSRFProtect, generate_csrf
from sqlalchemy import (
    func, desc, case, or_, not_, extract, and_
)
from sqlalchemy.orm import joinedload
from datetime import datetime, date, timedelta
import io
import csv
import calendar
import atexit
from apscheduler.schedulers.background import BackgroundScheduler
import os
from os import path
from functools import wraps

# Correctly import all necessary models, including the new ones
from models import (
    User, Customer, Requirement,
    Farmer, Payment, MilkRate, Collection, Expense, CasualSale,
    Announcement, DailyCollection, FarmerPayout
)

# Correctly import all necessary forms, including the new ones
from forms import (
    CustomerForm, CustomerLoginForm, RequirementForm,
    FarmerForm, MilkRateForm, AdminDeactivationForm,
    PaymentForm, UserForm, MilkmanProfileForm, ExpenseForm, CasualSaleForm,
    AnnouncementForm, MilkCollectionForm, FarmerPayoutForm
)

from db import db  # Your database instance

# ------------------------
# Init App + Config
# ------------------------
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_here'
basedir = path.abspath(path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{path.join(basedir, "doodhflow.db")}'

# ------------------------
# Init Extensions
# ------------------------
db.init_app(app)
migrate = Migrate(app, db)
csrf = CSRFProtect(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
# ------------------------
# Global CSRF Token & User Loader
# ------------------------
@app.context_processor
def csrf_token_processor():
    return dict(csrf_token=generate_csrf)


# CORRECTED: Updated user loader to handle both User and Farmer models
@login_manager.user_loader
def load_user(user_id):
    if session.get('active_role') == 'farmer':
        return Farmer.query.get(int(user_id))
    else:
        return User.query.get(int(user_id))


# ------------------------
# Role-required decorator
# ------------------------
def role_required(role):
    def wrapper(f):
        @wraps(f)
        def decorated_view(*args, **kwargs):
            if not current_user.is_authenticated or current_user.role != role:
                abort(403)
            return f(*args, **kwargs)
        return decorated_view
    return wrapper


# ------------------------
# Routes
# ------------------------
@app.route('/')
def home():
    return render_template('admin/home.html')

#-------------------------------------------
#                MANAGE CUSTOMER
#-------------------------------------------
# In your app.py file

@app.route('/manage_customers', methods=['GET'])
@login_required
def manage_customers():
    if current_user.role not in ['milkman', 'admin']:
        flash("Access denied.", "danger")
        return redirect(url_for('home'))

    search = request.args.get('search', '').strip()

    # Base query for the current user's customers
    if current_user.role == 'milkman':
        query = Customer.query.filter_by(milkman_id=current_user.id)
    else:
        query = Customer.query

    # Apply search filter if a search term is provided
    if search:
        # Check if the search term is a number first
        if search.isdigit():
            # If it's a number, ONLY search by ID for an exact match
            query = query.filter(Customer.id == int(search))
        else:
            # If it's text, search the text fields
            like_term = f"%{search}%"
            query = query.filter(
                or_(
                    Customer.name.ilike(like_term),
                    Customer.phone.ilike(like_term),
                    Customer.address.ilike(like_term)
                )
            )

    customers = query.order_by(Customer.id).all()

    return render_template('admin/manage_customers.html', customers=customers, search=search)

# In your app.py file

@app.route('/manage_customers/requirements', methods=['GET', 'POST'])
@login_required
def manage_customers_requirements():
    if current_user.role not in ['milkman', 'admin']:
        flash("Access denied.", "danger")
        return redirect(url_for('home'))

    selected_date_str = request.args.get('date')
    try:
        selected_date = datetime.strptime(selected_date_str, '%Y-%m-%d').date() if selected_date_str else date.today()
    except ValueError:
        selected_date = date.today()

    session_name = request.args.get('session', 'morning').lower()
    if session_name not in ['morning', 'evening']:
        session_name = 'morning'

    # This part handles the notifications after saving, it's correct and remains the same.
    updated_customers_info = []
    if 'updated_customers' in session:
        updated_data = session.pop('updated_customers', {})
        if updated_data.get('date') == selected_date.strftime('%Y-%m-%d') and updated_data.get('session') == session_name:
            customer_ids = updated_data.get('ids', [])
            updated_customers_info = db.session.query(
                Customer.name, Customer.phone, Requirement.cow_qty, Requirement.buffalo_qty,
                Requirement.status,
                ((Requirement.cow_qty * Requirement.cow_rate_at_order) + (Requirement.buffalo_qty * Requirement.buffalo_rate_at_order)),
                Requirement.cow_rate_at_order, Requirement.buffalo_rate_at_order,
                Payment.id.label('payment_id')
            ).join(Requirement, Customer.id == Requirement.customer_id)\
             .outerjoin(Payment, Requirement.id == Payment.requirement_id)\
             .filter(
                Customer.id.in_(customer_ids),
                Requirement.date_requested == selected_date,
                Requirement.session == session_name
            ).all()

    # Base query for customers who do not have a requirement logged for the selected date and session.
    existing_customer_subquery = (
        db.session.query(Requirement.customer_id).filter(and_(
            Requirement.date_requested == selected_date, Requirement.session == session_name
        )).subquery()
    )
    query_customers = Customer.query.filter(Customer.active == True)
    if current_user.role == 'milkman':
        query_customers = query_customers.filter(Customer.milkman_id == current_user.id)
    
    # *** THIS IS THE CORRECTED SEARCH LOGIC ***
    search = request.args.get('search', '').strip()
    if search:
        if search.isdigit():
            # If the search term is a number, ONLY search by ID
            query_customers = query_customers.filter(Customer.id == int(search))
        else:
            # Otherwise, search by text fields
            like_term = f"%{search}%"
            query_customers = query_customers.filter(
                or_(
                    Customer.name.ilike(like_term),
                    Customer.phone.ilike(like_term),
                    Customer.address.ilike(like_term)
                )
            )

    customers_not_yet_entered = query_customers.filter(~Customer.id.in_(existing_customer_subquery)).order_by(Customer.name).all()
    
    existing_reqs = Requirement.query.filter(
        Requirement.customer_id.in_([c.id for c in customers_not_yet_entered]),
        Requirement.date_requested == selected_date,
        Requirement.session == session_name
    ).all()
    req_map = {req.customer_id: req for req in existing_reqs}

    if request.method == 'POST':
        # POST logic remains the same
        allowed_statuses = {'paid', 'unpaid'}
        customers_to_update_ids = []

        for customer in customers_not_yet_entered:
            cow_qty_raw = request.form.get(f'cow_{customer.id}')
            buffalo_qty_raw = request.form.get(f'buffalo_{customer.id}')
            status = request.form.get(f'status_{customer.id}', 'unpaid').lower()

            if status not in allowed_statuses: status = 'unpaid'
            if not cow_qty_raw and not buffalo_qty_raw: continue

            try:
                cow_qty = float(cow_qty_raw or 0)
                buffalo_qty = float(buffalo_qty_raw or 0)
            except ValueError:
                cow_qty, buffalo_qty = 0, 0

            if cow_qty == 0 and buffalo_qty == 0: continue

            customers_to_update_ids.append(customer.id)
            total_amount = (cow_qty * (customer.cow_rate or 0)) + (buffalo_qty * (customer.buffalo_rate or 0))
            req = req_map.get(customer.id)
            if not req:
                req = Requirement(customer_id=customer.id, date_requested=selected_date, session=session_name)
                db.session.add(req)

            req.cow_qty = cow_qty
            req.buffalo_qty = buffalo_qty
            req.status = status
            req.cow_rate_at_order = customer.cow_rate or 0
            req.buffalo_rate_at_order = customer.buffalo_rate or 0
            req.status_update_time = datetime.utcnow()

            if status == 'paid':
                existing_payment = Payment.query.filter_by(requirement_id=req.id).first()
                if not existing_payment:
                    payment = Payment(
                        customer_id=customer.id, requirement_id=req.id, amount=total_amount,
                        total_amount=total_amount, collected_by_id=current_user.id,
                        payment_mode='cash', remarks='Paid upon entry', bill_date=datetime.utcnow()
                    )
                    db.session.add(payment)

        if customers_to_update_ids:
            session['updated_customers'] = {
                'ids': customers_to_update_ids, 'date': selected_date.strftime('%Y-%m-%d'), 'session': session_name
            }

        db.session.commit()
        flash(f"Requirements for {selected_date.strftime('%d-%b-%Y')} ({session_name.capitalize()}) saved successfully.", "success")
        return redirect(url_for('manage_customers_requirements', date=selected_date.strftime('%Y-%m-%d'), session=session_name))

    return render_template(
        'admin/manage_customers_requirements.html',
        customers=customers_not_yet_entered, req_map=req_map, selected_date=selected_date,
        session_name=session_name, today=selected_date, updated_customers_info=updated_customers_info
    )


@app.route('/manage_customers/last')
@login_required
def manage_customers_last_requirement():
    if current_user.role not in ['milkman', 'admin']:
        flash("Access denied.", "danger")
        return redirect(url_for('home'))

    if current_user.role == 'milkman':
        customers = Customer.query.filter_by(milkman_id=current_user.id, active=True)
    else:
        customers = Customer.query.filter_by(active=True)

    customers = customers.order_by(Customer.name).all()

    # Define session ordering: morning = 1, evening = 2
    session_order = case(
        (Requirement.session == 'morning', 1),
        (Requirement.session == 'evening', 2),
        else_=0
    )

    last_req_map = {}
    for customer in customers:
        last_req = (
            Requirement.query
            .filter_by(customer_id=customer.id)
            .filter(Requirement.status.in_(['paid', 'unpaid', 'pending']))
            .order_by(
                desc(Requirement.date_requested),
                desc(session_order)
            )
            .first()
        )
        if last_req:
            last_req.total_amount = (
                (last_req.cow_qty or 0) * (last_req.cow_rate_at_order or 0) +
                (last_req.buffalo_qty or 0) * (last_req.buffalo_rate_at_order or 0)
            )
        last_req_map[customer.id] = last_req

    today = date.today()

    return render_template(
        'admin/manage_customers_last_requirement.html',
        customers=customers,
        last_req_map=last_req_map,
        today=today,
        now=datetime.utcnow()
    )

@app.route('/requirement/delete/<int:req_id>', methods=['POST'])
@login_required
def delete_requirement(req_id):
    # Only admin or milkman allowed
    if current_user.role not in ['admin', 'milkman']:
        abort(403)

    req = Requirement.query.get_or_404(req_id)
    customer = Customer.query.get(req.customer_id)

    # Milkman can delete only their customers' requirements
    if current_user.role == 'milkman' and customer.milkman_id != current_user.id:
        abort(403)

    # Check if requirement was updated less than 5 minutes ago
    if req.status_update_time is None:
        flash("Cannot delete requirement without update timestamp.", "warning")
        return redirect(url_for('manage_customers_last_requirement'))

    time_elapsed = datetime.utcnow() - req.status_update_time
    if time_elapsed > timedelta(minutes=60):
        flash("You can only delete requirements within 60 minutes of update.", "warning")
        return redirect(url_for('manage_customers_last_requirement'))

    # Delete the requirement and commit
    db.session.delete(req)
    db.session.commit()
    flash("Requirement deleted successfully.", "success")
    return redirect(url_for('manage_customers_last_requirement'))

@app.route('/customer/add', methods=['GET', 'POST'])
@login_required
def add_customer():
    if current_user.role not in ['milkman', 'admin']:
        flash("Access denied.", "danger")
        return redirect(url_for('home'))

    form = CustomerForm()
    if form.validate_on_submit():
        if User.query.filter_by(username=form.username.data).first():
            flash("Username already exists.", "danger")
            return render_template("customer/customer_form.html", form=form, action="Add")

        new_user = User(username=form.username.data, role='customer')
        new_user.set_password(form.password.data)

        new_customer = Customer(
            milkman_id=current_user.id,
            user=new_user,
            name=form.name.data,
            phone=form.phone.data,
            address=form.address.data,
            cow_rate=form.cow_rate.data,
            buffalo_rate=form.buffalo_rate.data,
            active=True
        )

        db.session.add(new_user)
        db.session.add(new_customer)
        db.session.commit()

        flash("Customer added.", "success")
        return redirect(url_for('manage_customers'))

    return render_template("customer/customer_form.html", form=form, action="Add")


@app.route('/customer/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_customer(id):
    customer = Customer.query.get_or_404(id)
    if customer.milkman_id != current_user.id:
        flash("Access denied.", "danger")
        return redirect(url_for('manage_customers'))

    form = CustomerForm(obj=customer)
    if request.method == 'GET' and customer.user:
        form.username.data = customer.user.username

    if form.validate_on_submit():
        customer.name = form.name.data
        customer.phone = form.phone.data
        customer.address = form.address.data
        customer.cow_rate = form.cow_rate.data
        customer.buffalo_rate = form.buffalo_rate.data

        user = customer.user
        if user:
            if user.username != form.username.data:
                if User.query.filter(User.username == form.username.data, User.id != user.id).first():
                    flash("Username taken.", "danger")
                    return render_template("customer/customer_form.html", form=form, action="Edit")
                user.username = form.username.data
            if form.password.data:
                user.set_password(form.password.data)

        db.session.commit()
        flash("Customer updated.", "success")
        return redirect(url_for('manage_customers'))

    return render_template("customer/customer_form.html", form=form, action="Edit")


@app.route('/customer/delete/<int:id>', methods=['POST'])
@login_required
def delete_customer(id):
    customer = Customer.query.get_or_404(id)
    if customer.milkman_id != current_user.id:
        flash("Access denied.", "danger")
        return redirect(url_for('manage_customers'))

    if customer.user:
        db.session.delete(customer.user)

    db.session.delete(customer)
    db.session.commit()
    flash("Customer deleted.", "info")
    return redirect(url_for('manage_customers'))


@app.route('/customer/activate/<int:id>', methods=['POST'])
@login_required
def activate_customer(id):
    customer = Customer.query.get_or_404(id)
    if customer.milkman_id != current_user.id:
        flash("Access denied.", "danger")
        return redirect(url_for('manage_customers'))

    customer.active = True
    db.session.commit()
    flash("Customer activated.", "success")
    return redirect(url_for('manage_customers'))


@app.route('/customer/deactivate/<int:id>', methods=['POST'])
@login_required
def deactivate_customer(id):
    customer = Customer.query.get_or_404(id)
    if customer.milkman_id != current_user.id:
        flash("Access denied.", "danger")
        return redirect(url_for('manage_customers'))

    customer.active = False
    db.session.commit()
    db.session.expire_all()
    flash("Customer deactivated.", "warning")
    return redirect(url_for('manage_customers'))

@app.route('/customer/<int:customer_id>/history')
@login_required
def admin_customer_order_history(customer_id):
    if current_user.role not in ['milkman', 'admin']:
        flash("Access denied", "danger")
        return redirect(url_for('home'))

    customer = Customer.query.get_or_404(customer_id)
    if current_user.role == 'milkman' and customer.milkman_id != current_user.id:
        flash("Permission denied", "danger")
        return redirect(url_for('manage_customers'))

    today = date.today()
    default_start_date = today.replace(day=1)
    try:
        start_date_str = request.args.get('start_date', default_start_date.strftime('%Y-%m-%d'))
        end_date_str = request.args.get('end_date', today.strftime('%Y-%m-%d'))
        start_date = datetime.strptime(start_date_str, "%Y-%m-%d").date()
        end_date = datetime.strptime(end_date_str, "%Y-%m-%d").date()
    except (ValueError, TypeError):
        start_date = default_start_date
        end_date = today

    session_name = request.args.get('session')
    status_filter = request.args.get('status')

    query = Requirement.query.filter(
        Requirement.customer_id == customer.id,
        Requirement.date_requested.between(start_date, end_date)
    )
    if session_name:
        query = query.filter(Requirement.session == session_name)
    if status_filter:
        query = query.filter(Requirement.status == status_filter)

    orders = query.order_by(Requirement.date_requested.desc()).all()

    outstanding_balance = db.session.query(
        func.sum((Requirement.cow_qty * Requirement.cow_rate_at_order) + (Requirement.buffalo_qty * Requirement.buffalo_rate_at_order))
    ).filter(
        Requirement.customer_id == customer.id,
        Requirement.status == 'unpaid',
        Requirement.date_requested.between(start_date, end_date)
    ).scalar() or 0.0

    return render_template(
        'customer/order_history.html',
        orders=orders,
        customer=customer,
        outstanding_balance=outstanding_balance,
        session_name=session_name,
        status_filter=status_filter,
        start_date=start_date,
        end_date=end_date
    )


@app.route('/admin/customer/order/<int:order_id>/mark_paid', methods=['POST'])
@login_required
def mark_order_paid(order_id):
    if current_user.role not in ['milkman', 'admin']:
        flash("Access denied.", "danger")
        return redirect(url_for('home'))

    order = Requirement.query.get_or_404(order_id)
    customer = Customer.query.get_or_404(order.customer_id)

    if current_user.role == 'milkman' and customer.milkman_id != current_user.id:
        flash("Permission denied.", "danger")
        return redirect(url_for('manage_customers'))

    payment = Payment.query.filter_by(requirement_id=order.id).first()

    if order.status.lower() == 'unpaid':
        order.status = 'paid'
        order.status_update_time = datetime.utcnow()

        if not payment:
            payment = Payment(
                customer_id=order.customer_id,
                requirement_id=order.id,
                amount=(order.cow_qty or 0) * (order.cow_rate_at_order or 0) +
                       (order.buffalo_qty or 0) * (order.buffalo_rate_at_order or 0),
                total_amount=(order.cow_qty or 0) * (order.cow_rate_at_order or 0) +
                             (order.buffalo_qty or 0) * (order.buffalo_rate_at_order or 0),
                collected_by_id=current_user.id,
                payment_mode='cash',
                remarks='Marked paid by admin',
                bill_date=datetime.utcnow()
            )
            db.session.add(payment)

        db.session.commit()
        flash("Order marked as paid and payment recorded.", "success")

    else:
        flash("Order is already marked as paid.", "info")

    if payment:
        return redirect(url_for('customer_view_bill', payment_id=payment.id))
    else:
        return redirect(url_for('admin_customer_order_history', customer_id=customer.id))


@app.route('/customer/<int:customer_id>/download_report')
@login_required
def download_order_report(customer_id):
    customer = Customer.query.get_or_404(customer_id)
    if current_user.role not in ['admin'] and (current_user.role == 'milkman' and customer.milkman_id != current_user.id) and (current_user.role == 'customer' and current_user.customer.id != customer_id):
        flash("Permission denied.", "danger")
        return redirect(url_for('home'))

    status_filter = request.args.get('status', 'all')

    query = Requirement.query.filter_by(customer_id=customer_id)

    if status_filter == 'paid':
        query = query.filter_by(status='paid')
    elif status_filter == 'unpaid':
        query = query.filter_by(status='unpaid')

    orders = query.order_by(Requirement.date_requested.desc()).all()

    output = io.StringIO()
    writer = csv.writer(output)

    header = ['Order ID', 'Date', 'Session', 'Cow Qty (L)', 'Buffalo Qty (L)', 'Total Amount', 'Status']
    writer.writerow(header)

    for order in orders:
        total = (order.cow_qty or 0) * (order.cow_rate_at_order or 0) + \
                (order.buffalo_qty or 0) * (order.buffalo_rate_at_order or 0)

        row = [
            order.id,
            order.date_requested.strftime('%Y-%m-%d'),
            order.session,
            order.cow_qty or 0,
            order.buffalo_qty or 0,
            f'{total:.2f}',
            order.status
        ]
        writer.writerow(row)

    output.seek(0)

    return Response(
        output,
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment;filename=orders_{customer.name.replace(' ','_')}_{status_filter}.csv"}
    )


# In your app.py file

@app.route('/customer/<int:customer_id>/generate_bill', methods=['POST'])
@login_required
def generate_customer_bill(customer_id):
    customer = Customer.query.get_or_404(customer_id)
    if current_user.role == 'milkman' and customer.milkman_id != current_user.id:
        flash('Permission denied.', 'danger')
        return redirect(url_for('manage_customers'))

    selected_ids = request.form.getlist('requirement_ids')
    if not selected_ids:
        flash("Please select at least one requirement.", "warning")
        return redirect(url_for('admin_customer_order_history', customer_id=customer_id))

    requirements = Requirement.query.filter(
        Requirement.id.in_(selected_ids),
        Requirement.customer_id == customer_id,
        Requirement.status == 'unpaid'
    ).order_by(Requirement.date_requested).all() # Order by date for a clean bill

    if not requirements:
        flash("No unpaid orders were selected for billing.", "warning")
        return redirect(url_for('admin_customer_order_history', customer_id=customer_id))

    total_amount = 0
    bill_details = [] # To store details for the WhatsApp message

    for req in requirements:
        req_amount = ((req.cow_qty or 0) * (req.cow_rate_at_order or 0) +
                      (req.buffalo_qty or 0) * (req.buffalo_rate_at_order or 0))
        total_amount += req_amount

        req.status = 'paid'
        req.status_update_time = datetime.utcnow()

        payment = Payment(
            customer_id=req.customer_id,
            requirement_id=req.id,
            amount=req_amount,
            total_amount=req_amount,
            collected_by_id=current_user.id,
            payment_mode='cash',
            remarks='Paid via bulk bill generation.',
            bill_date=datetime.utcnow()
        )
        db.session.add(payment)
        
        # Store details for the message
        bill_details.append({
            "date": req.date_requested.strftime('%d-%b-%Y'),
            "cow_qty": req.cow_qty or 0,
            "cow_rate": req.cow_rate_at_order or 0,
            "buffalo_qty": req.buffalo_qty or 0,
            "buffalo_rate": req.buffalo_rate_at_order or 0,
        })

    db.session.commit()

    # --- UPDATED WHATSAPP MESSAGE STRUCTURE ---
    whatsapp_message = f"*DoodhFlow Bill - Bulk Generation*\n"
    whatsapp_message += "--------------------\n"
    whatsapp_message += f"Hello {customer.name},\n"
    whatsapp_message += f"Here is your bill summary:\n\n"

    for detail in bill_details:
        cow_subtotal = detail['cow_qty'] * detail['cow_rate']
        buffalo_subtotal = detail['buffalo_qty'] * detail['buffalo_rate']
        
        whatsapp_message += f"Date: {detail['date']}\n"
        if detail['cow_qty'] > 0:
            whatsapp_message += f"Cow Milk: {detail['cow_qty']}L x ₹{detail['cow_rate']:.2f} = ₹{cow_subtotal:.2f}\n"
        if detail['buffalo_qty'] > 0:
            whatsapp_message += f"Buffalo Milk: {detail['buffalo_qty']}L x ₹{detail['buffalo_rate']:.2f} = ₹{buffalo_subtotal:.2f}\n"
        whatsapp_message += "\n"

    whatsapp_message += "--------------------\n"
    whatsapp_message += f"*Total Amount: ₹{total_amount:.2f}*\n"
    whatsapp_message += f"Status: Paid"
    # --- END UPDATED WHATSAPP MESSAGE STRUCTURE ---

    session['bulk_bill_notification'] = {
        'customer_name': customer.name,
        'customer_phone': customer.phone,
        'message': whatsapp_message
    }

    flash(f"Bill for ₹{total_amount:.2f} generated and {len(requirements)} orders marked as paid.", "success")

    return redirect(url_for('admin_customer_order_history', customer_id=customer_id))

@app.route('/customer/order_history')
@login_required
def customer_order_history_view():
    if current_user.role != 'customer':
        flash("Access denied.", "danger")
        return redirect(url_for('home'))

    customer = current_user.customer

    today = date.today()
    default_start_date = today - timedelta(days=30)
    try:
        start_date_str = request.args.get('start_date', default_start_date.strftime('%Y-%m-%d'))
        end_date_str = request.args.get('end_date', today.strftime('%Y-%m-%d'))
        start_date = datetime.strptime(start_date_str, '%Y-%m-%d').date()
        end_date = datetime.strptime(end_date_str, '%Y-%m-%d').date()
    except (ValueError, TypeError):
        start_date = default_start_date
        end_date = today

    session_name = request.args.get('session')
    status_filter = request.args.get('status')

    query = Requirement.query.filter(
        Requirement.customer_id == customer.id,
        Requirement.date_requested.between(start_date, end_date)
    )
    if session_name:
        query = query.filter(Requirement.session == session_name)
    if status_filter:
        query = query.filter(Requirement.status == status_filter)

    orders = query.order_by(Requirement.date_requested.desc()).all()

    outstanding_balance = db.session.query(
        func.sum((Requirement.cow_qty * Requirement.cow_rate_at_order) + (Requirement.buffalo_qty * Requirement.buffalo_rate_at_order))
    ).filter(
        Requirement.customer_id == customer.id,
        Requirement.status == 'unpaid',
        Requirement.date_requested.between(start_date, end_date)
    ).scalar() or 0.0

    return render_template(
        'customer/order_history.html',
        orders=orders,
        customer=customer,
        outstanding_balance=outstanding_balance,
        session_name=session_name,
        status_filter=status_filter,
        start_date=start_date,
        end_date=end_date
    )


@app.route('/customer/announcements')
@login_required
def customer_announcements():
    if current_user.role != 'customer':
        flash("Access denied.", "danger")
        return redirect(url_for('home'))
    
    # Ensure customer has a milkman assigned
    if not current_user.customer or not hasattr(current_user.customer, 'milkman_id'):
         announcements = []
    else:
        milkman_id = current_user.customer.milkman_id
        announcements = Announcement.query.filter_by(milkman_id=milkman_id).order_by(Announcement.date_posted.desc()).all()
    
    return render_template('customer/announcements.html', announcements=announcements)


@app.route('/customer/contact_milkman')
@login_required
def customer_contact_milkman():
    if current_user.role != 'customer':
        flash("Access denied.", "danger")
        return redirect(url_for('home'))

    milkman = current_user.customer.milkman

    if not milkman:
        flash("No milkman assigned to you currently.", "warning")
        return redirect(url_for('customer_dashboard'))

    return render_template('customer/contact_milkman.html', milkman=milkman)

@app.route('/customer/report_issue', methods=['GET', 'POST'])
@login_required
def customer_report_issue():
    if current_user.role != 'customer':
        flash("Access denied.", "danger")
        return redirect(url_for('home'))
    return render_template('customer/report_issue.html')

@app.route('/customer/payment_history')
@login_required
def customer_payment_history():
    if current_user.role != 'customer':
        flash('Access denied.', 'danger')
        return redirect(url_for('home'))
    payments = Payment.query.filter_by(customer_id=current_user.customer.id).order_by(Payment.bill_date.desc()).all()
    return render_template('customer/payment_history.html', payments=payments)

@app.route('/customer/analysis')
@login_required
def customer_analysis():
    if current_user.role != 'customer':
        flash("Access denied.", "danger")
        return redirect(url_for('home'))
    return render_template('customer/analysis.html')

# ------------------------
# CUSTOMER PAYMENT
# ------------------------
@app.route('/customer/payment/record/<int:requirement_id>', methods=['GET', 'POST'])
@login_required
def customer_record_payment(requirement_id):
    if current_user.role != 'customer':
        flash("Access denied.", "danger")
        return redirect(url_for('home'))

    req = Requirement.query.get_or_404(requirement_id)

    if req.customer_id != current_user.customer.id:
        flash("Permission denied.", "danger")
        return redirect(url_for('customer_dashboard'))

    form = PaymentForm()

    total_due = (
        (req.cow_qty or 0) * (req.cow_rate_at_order or 0) +
        (req.buffalo_qty or 0) * (req.buffalo_rate_at_order or 0)
    )
    paid_so_far = sum(p.amount for p in req.payments)
    remaining_due = total_due - paid_so_far

    if request.method == 'GET' and not form.amount.data:
        form.amount.data = remaining_due

    if form.validate_on_submit():
        payment = Payment(
            customer_id=req.customer_id,
            requirement_id=req.id,
            amount=form.amount.data,
            total_amount=total_due,
            collected_by_id=current_user.id,
            payment_mode='cash',
            remarks=form.remarks.data,
            bill_date=datetime.utcnow()
        )
        db.session.add(payment)
        db.session.commit()

        flash("Payment recorded successfully.", "success")
        return redirect(url_for('view_bill', payment_id=payment.id))

    return render_template(
        'payment/record_payment.html',
        form=form,
        requirement=req,
        total_due=total_due,
        remaining_due=remaining_due
    )



@app.route('/customer/payment/view/<int:payment_id>')
@login_required
def customer_view_bill(payment_id):
    payment = Payment.query.get_or_404(payment_id)

    is_owner = current_user.role == 'customer' and payment.customer_id == current_user.customer.id
    is_admin = current_user.role == 'admin'
    is_correct_milkman = current_user.role == 'milkman' and payment.customer.milkman_id == current_user.id

    if not (is_owner or is_admin or is_correct_milkman):
        abort(403)

    return render_template('payment/view_bill.html', payment=payment)


#------------------FARMER DASHBOARD--------------
# CORRECTED: Refactored Farmer routes to use Flask-Login
#------------------------------------------------

@app.route('/dashboard_farmer')
@login_required
def farmer_dashboard():
    if current_user.role != 'farmer':
        flash("Access denied.", "danger")
        return redirect(url_for('login'))

    farmer = current_user

    profile = {
        'name': farmer.name,
        'phone': farmer.phone,
        'address': farmer.address,
        'active': farmer.active,
        'milkman': farmer.milkman.username if farmer.milkman else None,
        'cow_rate': farmer.cow_rate or 0,
        'buffalo_rate': farmer.buffalo_rate or 0
    }

    entries_today = Collection.query.filter_by(
        farmer_id=farmer.id,
        date=date.today()
    ).all()
    today_supply = sum((e.cow_qty or 0) + (e.buffalo_qty or 0) for e in entries_today)

    first_day = date.today().replace(day=1)

    earnings_month = (
        db.session.query(func.sum(Collection.total_amount))
        .filter(
            Collection.farmer_id == farmer.id,
            Collection.status == 'paid',
            Collection.date >= first_day
        )
        .scalar() or 0
    )

    payment_due = (
        db.session.query(func.sum(Collection.total_amount))
        .filter(
            Collection.farmer_id == farmer.id,
            Collection.status == 'unpaid'
        )
        .scalar() or 0
    )

    return render_template(
        'farmer/dashboard_farmer.html',
        profile=profile,
        today_supply=today_supply,
        earnings_month=earnings_month,
        payment_due=payment_due,
        cow_rate=farmer.cow_rate or 0,
        buffalo_rate=farmer.buffalo_rate or 0,
    )


@app.route('/farmer/profile/edit', methods=['GET', 'POST'])
@login_required
def edit_farmer_profile():
    if current_user.role != 'farmer':
        flash("Access denied.", "danger")
        return redirect(url_for('login'))

    farmer = current_user
    form = FarmerForm(obj=farmer)

    if request.method == 'GET':
        form.password.data = None
        form.confirm_password.data = None

    if form.validate_on_submit():
        if form.username.data != farmer.username:
            existing_farmer = Farmer.query.filter_by(username=form.username.data).first()
            if existing_farmer:
                form.username.errors.append("Username already exists.")
                return render_template('farmer/farmer_form.html', form=form, title="Edit Profile")

        farmer.username = form.username.data
        farmer.name = form.name.data
        farmer.phone = form.phone.data
        farmer.address = form.address.data
        farmer.active = form.active.data

        if form.password.data:
            farmer.set_password(form.password.data)

        db.session.commit()
        flash("Profile updated successfully.", "success")
        return redirect(url_for('farmer_dashboard'))

    return render_template(
        'farmer/farmer_form.html',
        form=form,
        title="Edit Profile",
        cancel_url=url_for('farmer_dashboard')
    )


@app.route('/farmer/supply_history')
@login_required
def farmer_supply_history():
    if current_user.role != 'farmer':
        flash("Access denied.", "danger")
        return redirect(url_for('login'))

    farmer = current_user

    today = date.today()
    default_start_date = today - timedelta(days=30)
    try:
        start_date_str = request.args.get('start_date', default_start_date.strftime('%Y-%m-%d'))
        end_date_str = request.args.get('end_date', today.strftime('%Y-%m-%d'))
        start_date = datetime.strptime(start_date_str, '%Y-%m-%d').date()
        end_date = datetime.strptime(end_date_str, '%Y-%m-%d').date()
    except (ValueError, TypeError):
        start_date = default_start_date
        end_date = today

    session_name = request.args.get('session')
    status_filter = request.args.get('status')

    query = Collection.query.filter(
        Collection.farmer_id == farmer.id,
        Collection.date.between(start_date, end_date)
    )
    if session_name:
        query = query.filter(Collection.session == session_name)
    if status_filter:
        query = query.filter(Collection.status == status_filter)

    supplies_history = query.order_by(Collection.date.desc()).all()

    due_amount = (
        db.session.query(db.func.sum(Collection.total_amount))
        .filter(
            Collection.farmer_id == farmer.id,
            Collection.status.in_(['unpaid', 'partial']),
            Collection.date.between(start_date, end_date)
        )
        .scalar() or 0
    )

    return render_template(
        'farmer/supply_history.html',
        farmer=farmer,
        supplies_history=supplies_history,
        session_name=session_name,
        role=current_user.role,
        due_amount=due_amount,
        start_date=start_date,
        end_date=end_date
    )


@app.route('/farmer/announcements')
@login_required
def farmer_announcements():
    if current_user.role != 'farmer':
        flash("Access denied.", "danger")
        return redirect(url_for('login'))
        
    # Ensure farmer has a milkman assigned
    if not hasattr(current_user, 'milkman_id'):
        announcements = []
    else:
        milkman_id = current_user.milkman_id
        announcements = Announcement.query.filter_by(milkman_id=milkman_id).order_by(Announcement.date_posted.desc()).all()
        
    return render_template('farmer/announcements.html', announcements=announcements)

@app.route('/contact_milkman')
@login_required
def contact_milkman():
    # CORRECTED: Simplified logic for logged-in farmer
    if current_user.role != 'farmer':
        flash("Access denied.", "danger")
        return redirect(url_for('login'))

    farmer = current_user
    milkman = farmer.milkman

    return render_template('farmer/contact_milkman.html', milkman=milkman)


@app.route('/report_issue', methods=['GET', 'POST'])
@login_required
def report_issue():
    return "Report Issue page coming soon."


@app.route('/farmer/analysis')
@login_required
def farmer_analysis():
    if current_user.role != 'farmer':
        flash("Access denied.", "danger")
        return redirect(url_for('login'))

    farmer = current_user
    farmer_id = farmer.id

    from sqlalchemy import func, extract
    from datetime import date, timedelta

    year = date.today().year

    monthly_data = (
        db.session.query(
            extract('month', Collection.date).label('month'),
            func.sum(Collection.cow_qty).label('cow_qty'),
            func.sum(Collection.buffalo_qty).label('buffalo_qty'),
            func.sum(Collection.total_amount).label('earnings'),
            (func.sum(Collection.cow_qty) + func.sum(Collection.buffalo_qty)).label('total_qty'),
            func.sum(
                case(
                    (Collection.session == 'morning', Collection.cow_qty + Collection.buffalo_qty),
                    else_=0
                )
            ).label('morning_qty'),
            func.sum(
                case(
                    (Collection.session == 'evening', Collection.cow_qty + Collection.buffalo_qty),
                    else_=0
                )
            ).label('evening_qty')
        )
        .filter(
            Collection.farmer_id == farmer_id,
            extract('year', Collection.date) == date.today().year
        )
        .group_by('month')
        .order_by('month')
        .all()
    )

    status_summary = (
        db.session.query(
            Collection.status,
            func.count(Collection.id),
            func.sum(Collection.total_amount)
        )
        .filter(Collection.farmer_id == farmer_id)
        .group_by(Collection.status)
        .all()
    )

    today = date.today()
    last_30_days = today - timedelta(days=29)

    daily_supply_query = (
        db.session.query(
            Collection.date,
            Collection.session,
            func.sum(Collection.cow_qty),
            func.sum(Collection.buffalo_qty),
            func.sum(Collection.total_amount),
            Collection.status
        )
        .filter(
            Collection.farmer_id == farmer_id,
            Collection.date >= last_30_days
        )
        .group_by(Collection.date, Collection.session, Collection.status)
        .order_by(Collection.date.asc())
        .all()
    )

    daily_supply_for_chart = daily_supply_query
    daily_supply_for_table = sorted(daily_supply_query, key=lambda x: x[0], reverse=True)[:10]
    daily_totals_by_date = {}
    for row in daily_supply_for_chart:
        day = row[0]
        daily_totals_by_date[day] = daily_totals_by_date.get(day, 0) + (row[2] or 0) + (row[3] or 0)

    chart_dates = [day.strftime('%Y-%m-%d') for day in sorted(daily_totals_by_date.keys())]
    daily_total_milk = [daily_totals_by_date[day] for day in sorted(daily_totals_by_date.keys())]


    return render_template(
        'farmer/farmer_analysis.html',
        farmer=farmer,
        monthly_data=monthly_data,
        status_summary=status_summary,
        daily_supply_for_table=daily_supply_for_table,
        chart_dates=chart_dates,
        daily_total_milk=daily_total_milk
    )


# ------------------------
# FARMER MANAGEMENT
# ------------------------
@app.route('/manage_farmers', methods=['GET'])
@login_required
def manage_farmers():
    if current_user.role not in ['milkman', 'admin']:
        flash("Access denied.", "danger")
        return redirect(url_for('home'))

    search = request.args.get('search','').strip()
    query = Farmer.query.filter_by(milkman_id=current_user.id)
    if search:
        like = f"%{search}%"
        query = query.filter(
            or_(
                Farmer.name.ilike(like),
                Farmer.phone.ilike(like),
                Farmer.address.ilike(like),
                Farmer.id.cast(db.String).ilike(like)
            )
        )
    farmers = query.order_by(Farmer.id).all()

    return render_template('admin/manage_farmers.html', farmers=farmers)

@app.route('/manage_farmers/supply', methods=['GET', 'POST'])
@login_required
def manage_farmers_supply():
    if current_user.role not in ['milkman', 'admin']:
        flash("Access denied.", "danger")
        return redirect(url_for('home'))

    session_name = request.args.get('session', 'morning')
    search = request.args.get('search', '').strip()
    today = date.today()

    # --- NEW: Logic to display updated farmers from the session ---
    updated_farmers_info = []
    if 'updated_farmers' in session:
        updated_data = session.pop('updated_farmers', {})
        if updated_data.get('date') == today.strftime('%Y-%m-%d') and updated_data.get('session') == session_name:
            farmer_ids = updated_data.get('ids', [])

            # Query for the details of the farmers who were just updated
            updated_farmers_info = db.session.query(
                Farmer.name,
                Farmer.phone,
                Collection.cow_qty,
                Collection.buffalo_qty,
                Collection.status,
                Collection.total_amount,
                Farmer.cow_rate,
                Farmer.buffalo_rate
            ).join(Collection, Farmer.id == Collection.farmer_id)\
             .filter(
                Farmer.id.in_(farmer_ids),
                Collection.date == today,
                Collection.session == session_name
            ).all()
    # --- END NEW ---

    subquery = db.session.query(Collection.farmer_id).filter(
        Collection.date == today,
        Collection.session == session_name
    ).subquery()

    farmer_query = Farmer.query.filter_by(milkman_id=current_user.id, active=True) # Added active=True
    farmer_query = farmer_query.filter(not_(Farmer.id.in_(subquery)))

    if search:
        like = f"%{search}%"
        farmer_query = farmer_query.filter(
            or_(
                Farmer.id.cast(db.String).ilike(like),
                Farmer.name.ilike(like),
                Farmer.phone.ilike(like),
            )
        )

    farmers = farmer_query.order_by(Farmer.id).all()

    supplies = {
        c.farmer_id: c
        for c in Collection.query.filter_by(date=today, session=session_name).all()
    }

    if request.method == 'POST':
        # --- NEW: List to store IDs of updated farmers ---
        farmers_to_update_ids = []

        for farmer in farmers:
            cow_qty_raw = request.form.get(f'cow_{farmer.id}')
            buffalo_qty_raw = request.form.get(f'buffalo_{farmer.id}')

            if not cow_qty_raw and not buffalo_qty_raw:
                continue

            cow_qty = float(cow_qty_raw or 0)
            buffalo_qty = float(buffalo_qty_raw or 0)

            # Continue only if there is a supply
            if cow_qty == 0 and buffalo_qty == 0:
                continue

            # --- NEW: Add farmer ID to the list ---
            farmers_to_update_ids.append(farmer.id)

            status = request.form.get(f'status_{farmer.id}', default='unpaid')
            cow_amount = cow_qty * (farmer.cow_rate or 0)
            buffalo_amount = buffalo_qty * (farmer.buffalo_rate or 0)
            total_amount = cow_amount + buffalo_amount

            entry = Collection.query.filter_by(
                farmer_id=farmer.id,
                date=today,
                session=session_name
            ).first()

            if entry:
                entry.cow_qty = cow_qty
                entry.buffalo_qty = buffalo_qty
                entry.status = status
                entry.cow_amount = cow_amount
                entry.buffalo_amount = buffalo_amount
                entry.total_amount = total_amount
            else:
                db.session.add(Collection(
                    farmer_id=farmer.id,
                    date=today,
                    session=session_name,
                    cow_qty=cow_qty,
                    buffalo_qty=buffalo_qty,
                    status=status,
                    cow_amount=cow_amount,
                    buffalo_amount=buffalo_amount,
                    total_amount=total_amount
                ))

        # --- NEW: Save the list of updated farmer IDs to the session ---
        if farmers_to_update_ids:
            session['updated_farmers'] = {
                'ids': farmers_to_update_ids,
                'date': today.strftime('%Y-%m-%d'),
                'session': session_name
            }

        db.session.commit()
        flash(f"{session_name.capitalize()} supply updated!", "success")
        return redirect(url_for('manage_farmers_supply',
                                session=session_name,
                                search=search))

    return render_template(
        'admin/manage_farmers_supply.html',
        farmers=farmers,
        supplies=supplies,
        session_name=session_name,
        today=today,
        search=search,
        updated_farmers_info=updated_farmers_info # --- NEW: Pass data to template ---
    )

from datetime import datetime, date, time, timedelta, timezone
from sqlalchemy import case, desc

# ... (many other routes) ...

@app.route('/manage_farmers/last')
@login_required
def manage_farmers_last_supply():
    if current_user.role not in ['milkman', 'admin']:
        flash("Access denied.", "danger")
        return redirect(url_for('home'))

    farmers = Farmer.query.filter_by(milkman_id=current_user.id).all()

    session_order = case(
        (Collection.session == 'morning', 1),
        (Collection.session == 'evening', 2),
        else_=0
    )

    last_supply_map = {}
    for farmer in farmers:
        last_entry = (
            Collection.query.filter_by(farmer_id=farmer.id)
            .order_by(desc(Collection.date), desc(session_order))
            .first()
        )
        last_supply_map[farmer.id] = last_entry

    today = date.today()

    return render_template(
        'admin/manage_farmers_last_supply.html',
        farmers=farmers,
        last_supply_map=last_supply_map,
        today=today,
        # UPDATED: Use timezone-aware 'now'
        now=datetime.utcnow()
    )


@app.route('/supply/delete/<int:supply_id>', methods=['POST'])
@login_required
def delete_supply(supply_id):
    if current_user.role not in ['milkman', 'admin']:
        abort(403)

    supply = Collection.query.get_or_404(supply_id)
    farmer = Farmer.query.get(supply.farmer_id)

    if current_user.role == 'milkman' and farmer.milkman_id != current_user.id:
        abort(403)

    # UPDATED: Use timezone-aware 'now' and check against the record's timestamp
    time_elapsed = datetime.utcnow() - supply.timestamp
    if time_elapsed > timedelta(seconds=301): # Give a 1-second buffer
        flash("You can only delete a supply record within 5 minutes of its entry.", "warning")
        return redirect(url_for('manage_farmers_last_supply'))

    db.session.delete(supply)
    db.session.commit()
    flash("Supply record deleted successfully.", "success")
    return redirect(url_for('manage_farmers_last_supply'))



@app.route('/add_farmer', methods=['GET', 'POST'])
@login_required
def add_farmer():
    if current_user.role not in ['milkman', 'admin']:
        flash("Access denied.", "danger")
        return redirect(url_for('home'))

    form = FarmerForm()

    if form.validate_on_submit():
        if Farmer.query.filter_by(username=form.username.data).first():
            form.username.errors.append("Username already exists.")
            return render_template('farmer/farmer_form.html', form=form, title="Add Farmer", cancel_url=url_for('manage_farmers'))

        new_farmer = Farmer(
            username=form.username.data,
            name=form.name.data,
            phone=form.phone.data,
            address=form.address.data,
            active=form.active.data,
            milkman_id=current_user.id
        )

        if current_user.role in ['admin', 'milkman']:
            new_farmer.cow_rate = form.cow_rate.data or 0
            new_farmer.buffalo_rate = form.buffalo_rate.data or 0
        else:
            new_farmer.cow_rate = 0
            new_farmer.buffalo_rate = 0

        new_farmer.set_password(form.password.data)

        db.session.add(new_farmer)
        db.session.commit()

        flash("Farmer added successfully.", "success")
        return redirect(url_for('manage_farmers'))

    return render_template("farmer/farmer_form.html", form=form, title="Add Farmer", cancel_url=url_for('manage_farmers'))



@app.route('/edit_farmer/<int:farmer_id>', methods=['GET', 'POST'])
@login_required
def edit_farmer(farmer_id):
    if current_user.role not in ['milkman', 'admin', 'farmer']:
        flash("Access denied: Not authorized.", "danger")
        return redirect(url_for('home'))

    farmer = Farmer.query.get_or_404(farmer_id)

    if current_user.role in ['milkman', 'admin'] and farmer.milkman_id != current_user.id:
        flash("You don't have permission to edit this farmer.", "danger")
        return redirect(url_for('manage_farmers'))

    if current_user.role == 'farmer' and farmer.id != current_user.id:
        flash("You can only edit your own profile.", "danger")
        return redirect(url_for('farmer_dashboard'))

    form = FarmerForm(obj=farmer)

    if request.method == 'GET':
        form.password.data = None
        form.confirm_password.data = None

    if form.validate_on_submit():
        if form.username.data != farmer.username:
            existing_farmer = Farmer.query.filter_by(username=form.username.data).first()
            if existing_farmer:
                form.username.errors.append("Username already exists.")
                return render_template('farmer/farmer_form.html', form=form, title="Edit Farmer", cancel_url=url_for('manage_farmers'))

        farmer.username = form.username.data
        farmer.name = form.name.data
        farmer.phone = form.phone.data
        farmer.address = form.address.data
        farmer.active = form.active.data

        if current_user.role in ['admin', 'milkman']:
            farmer.cow_rate = form.cow_rate.data or 0
            farmer.buffalo_rate = form.buffalo_rate.data or 0

        if form.password.data:
            farmer.set_password(form.password.data)

        db.session.commit()
        flash("Farmer details updated successfully.", "success")

        if current_user.role == 'farmer':
            return redirect(url_for('farmer_dashboard'))
        else:
            return redirect(url_for('manage_farmers'))

    return render_template(
        'farmer/farmer_form.html',
        form=form,
        title="Edit Farmer",
        cancel_url=url_for('manage_farmers')
    )



@app.route('/delete_farmer/<int:id>', methods=['POST'])
@login_required
def delete_farmer(id):
    if current_user.role not in ['milkman', 'admin']:
        flash("Access denied: Not in milkman role.", "danger")
        return redirect(url_for('home'))

    farmer = Farmer.query.get_or_404(id)

    if farmer.milkman_id != current_user.id:
        flash("You don't have permission to delete this farmer.", "danger")
        return redirect(url_for('manage_farmers'))

    db.session.delete(farmer)
    db.session.commit()
    flash("Farmer deleted successfully.", "success")
    return redirect(url_for('manage_farmers'))


@app.route('/deactivate_farmer/<int:farmer_id>')
@login_required
def deactivate_farmer(farmer_id):
    farmer = Farmer.query.get_or_404(farmer_id)
    if current_user.role not in ['milkman', 'admin'] or farmer.milkman_id != current_user.id:
        flash("Access denied.", "danger")
        return redirect(url_for('manage_farmers'))
    farmer.active = False
    db.session.commit()
    flash("Farmer deactivated.", "info")
    return redirect(url_for('manage_farmers'))

@app.route('/activate_farmer/<int:farmer_id>')
@login_required
def activate_farmer(farmer_id):
    farmer = Farmer.query.get_or_404(farmer_id)
    if current_user.role not in ['milkman', 'admin'] or farmer.milkman_id != current_user.id:
        flash("Access denied.", "danger")
        return redirect(url_for('manage_farmers'))
    farmer.active = True
    db.session.commit()
    flash("Farmer activated.", "success")
    return redirect(url_for('manage_farmers'))


@app.route('/farmer/<int:farmer_id>/history')
@login_required
def farmer_history(farmer_id):
    if current_user.role not in ['milkman', 'admin']:
        flash("Access denied", "danger")
        return redirect(url_for('home'))

    farmer = Farmer.query.get_or_404(farmer_id)

    if current_user.role == 'milkman' and farmer.milkman_id != current_user.id:
        flash("Permission denied.", "danger")
        return redirect(url_for('manage_farmers'))

    today = date.today()
    default_start_date = today.replace(day=1)
    try:
        start_date_str = request.args.get('start_date', default_start_date.strftime('%Y-%m-%d'))
        end_date_str = request.args.get('end_date', today.strftime('%Y-%m-%d'))
        start_date = datetime.strptime(start_date_str, '%Y-%m-%d').date()
        end_date = datetime.strptime(end_date_str, '%Y-%m-%d').date()
    except (ValueError, TypeError):
        start_date = default_start_date
        end_date = today

    session_name = request.args.get('session')
    status_filter = request.args.get('status')

    query = Collection.query.filter(
        Collection.farmer_id == farmer.id,
        Collection.date.between(start_date, end_date)
    )
    if session_name:
        query = query.filter(Collection.session == session_name)
    if status_filter:
        query = query.filter(Collection.status == status_filter)

    supplies_history = query.order_by(Collection.date.desc()).all()

    due_amount = (
        db.session.query(db.func.sum(Collection.total_amount))
        .filter(
            Collection.farmer_id == farmer.id,
            Collection.status.in_(['unpaid', 'partial']),
            Collection.date.between(start_date, end_date)
        )
        .scalar() or 0
    )

    return render_template(
        'farmer/supply_history.html',
        farmer=farmer,
        supplies_history=supplies_history,
        session_name=session_name,
        role=current_user.role,
        due_amount=due_amount,
        start_date=start_date,
        end_date=end_date
    )

@app.route('/update_supply_status/<int:supply_id>', methods=['POST'])
@login_required
def update_supply_status(supply_id):
    if current_user.role not in ['milkman', 'admin']:
        flash("Access denied", "danger")
        return redirect(url_for('home'))

    supply = Collection.query.get_or_404(supply_id)
    farmer = Farmer.query.get(supply.farmer_id)

    if farmer.milkman_id != current_user.id:
        flash("Permission denied", "danger")
        return redirect(url_for('manage_farmers'))

    new_status = request.form.get('status', 'paid')
    supply.status = new_status
    db.session.commit()
    flash("Supply status updated successfully", "success")
    return redirect(request.referrer)


@app.route('/farmer/view_bill/<int:supply_id>')
@login_required
def farmer_view_bill(supply_id):
    if current_user.role not in ['milkman', 'admin']:
        flash("Access denied.", "danger")
        return redirect(url_for('home'))

    supply = Collection.query.get_or_404(supply_id)
    farmer = Farmer.query.get_or_404(supply.farmer_id)
    if farmer.milkman_id != current_user.id:
        flash("Permission denied.", "danger")
        return redirect(url_for('manage_farmers'))

    return render_template(
        'payment/view_bill.html',
        farmer=farmer,
        supply=supply
    )

@app.route('/farmer/<int:farmer_id>/generate_bill', methods=['POST'])
@login_required
def generate_farmer_bill(farmer_id):
    farmer = Farmer.query.get_or_404(farmer_id)
    if farmer.milkman_id != current_user.id and current_user.role != 'admin':
        flash("Permission denied.", "danger")
        return redirect(url_for('manage_farmers'))

    selected_ids = request.form.getlist('supply_ids')
    if not selected_ids:
        flash("Please select at least one supply.", "warning")
        return redirect(url_for('farmer_history', farmer_id=farmer_id))

    supplies = Collection.query.filter(
        Collection.id.in_(selected_ids),
        Collection.farmer_id == farmer_id,
        Collection.status == 'unpaid'
    ).all()

    if not supplies:
        flash("No unpaid supplies found for billing.", "danger")
        return redirect(url_for('farmer_history', farmer_id=farmer_id))

    total_amount = sum(s.total_amount for s in supplies)

    for supply in supplies:
        supply.status = 'paid'

    db.session.commit()

    flash(f"{len(supplies)} supplies marked as paid and bill generated successfully.", "success")

    return render_template(
        'farmer/farmer_bulk_bill.html',
        farmer=farmer,
        supplies=supplies,
        total_amount=total_amount
    )

@app.route('/farmer/<int:farmer_id>/download_report')
@login_required
def download_farmer_report(farmer_id):
    farmer = Farmer.query.get_or_404(farmer_id)
    if current_user.role not in ['admin'] and (current_user.role == 'milkman' and farmer.milkman_id != current_user.id):
        flash("Permission denied.", "danger")
        return redirect(url_for('manage_farmers'))

    status_filter = request.args.get('status', 'all')

    query = Collection.query.filter_by(farmer_id=farmer_id)

    if status_filter in ['paid', 'unpaid', 'partial']:
        query = query.filter_by(status=status_filter)

    supplies = query.order_by(Collection.date.desc()).all()

    output = io.StringIO()
    writer = csv.writer(output)

    header = ['Supply ID', 'Date', 'Session', 'Cow Qty (L)', 'Buffalo Qty (L)', 'Total Amount', 'Status']
    writer.writerow(header)

    for supply in supplies:
        row = [
            supply.id,
            supply.date.strftime('%Y-%m-%d'),
            supply.session,
            supply.cow_qty or 0,
            supply.buffalo_qty or 0,
            f'{supply.total_amount:.2f}',
            supply.status
        ]
        writer.writerow(row)

    output.seek(0)

    return Response(
        output,
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment;filename=supplies_{farmer.name.replace(' ','_')}_{status_filter}.csv"}
    )

# ------------------------
# MILK RATE MANAGEMENT
# ------------------------
@app.route('/milk_rates', methods=['GET', 'POST'])
@login_required
def milk_rates():
    if current_user.role not in ['milkman', 'admin']:
        flash("Access denied.", "danger")
        return redirect(url_for('home'))

    customers = Customer.query.order_by(Customer.name).all()
    farmers = Farmer.query.order_by(Farmer.name).all()

    selected_type = request.args.get('type', 'customer')
    selected_id = request.args.get('id')
    
    if selected_id is not None and selected_id != 'all':
        try:
            selected_id = int(selected_id)
        except ValueError:
            selected_id = None

    rates = []
    if selected_type == 'customer' and isinstance(selected_id, int):
        rates = MilkRate.query.filter_by(for_group='customer', customer_id=selected_id) \
                                .order_by(MilkRate.date_effective.desc()).all()
    elif selected_type == 'farmer' and isinstance(selected_id, int):
        rates = MilkRate.query.filter_by(for_group='farmer', farmer_id=selected_id) \
                                .order_by(MilkRate.date_effective.desc()).all()

    form = MilkRateForm()
    form.for_group.choices = [('customer', 'Customer'), ('farmer', 'Farmer')]

    if not form.for_group.data:
        form.for_group.data = selected_type

    if form.validate_on_submit():
        if selected_id == 'all':
            updated_entities = []
            if form.for_group.data == 'customer':
                all_customers = Customer.query.all()
                for customer in all_customers:
                    new_rate = MilkRate(
                        milkman_id=current_user.id,
                        for_group='customer',
                        customer_id=customer.id,
                        cow_rate=form.cow_rate.data,
                        buffalo_rate=form.buffalo_rate.data,
                        date_effective=form.date_effective.data
                    )
                    db.session.add(new_rate)
                    if form.date_effective.data <= date.today():
                        customer.cow_rate = form.cow_rate.data
                        customer.buffalo_rate = form.buffalo_rate.data
                    updated_entities.append({'name': customer.name, 'phone': customer.phone})
            else:  # farmer
                all_farmers = Farmer.query.all()
                for farmer in all_farmers:
                    new_rate = MilkRate(
                        milkman_id=current_user.id,
                        for_group='farmer',
                        farmer_id=farmer.id,
                        cow_rate=form.cow_rate.data,
                        buffalo_rate=form.buffalo_rate.data,
                        date_effective=form.date_effective.data
                    )
                    db.session.add(new_rate)
                    if form.date_effective.data <= date.today():
                        farmer.cow_rate = form.cow_rate.data
                        farmer.buffalo_rate = form.buffalo_rate.data
                    updated_entities.append({'name': farmer.name, 'phone': farmer.phone})

            db.session.commit()

            session['updated_rate_info_bulk'] = [
                {
                    'name': entity['name'],
                    'phone': entity['phone'],
                    'cow_rate': form.cow_rate.data,
                    'buffalo_rate': form.buffalo_rate.data,
                    'date_effective': form.date_effective.data.strftime('%d-%b-%Y')
                } for entity in updated_entities
            ]

            flash(f"Bulk rate update applied to all {form.for_group.data}s.", "success")
            return redirect(url_for('milk_rates', type=selected_type, id='all'))

        else:
            # Single customer/farmer update
            new_rate = MilkRate(
                milkman_id=current_user.id,
                for_group=form.for_group.data,
                cow_rate=form.cow_rate.data,
                buffalo_rate=form.buffalo_rate.data,
                date_effective=form.date_effective.data
            )

            entity_info = None
            if form.for_group.data == 'customer':
                new_rate.customer_id = selected_id
                customer = Customer.query.get(selected_id)
                if customer:
                    entity_info = {'name': customer.name, 'phone': customer.phone}
                    if form.date_effective.data <= date.today():
                        customer.cow_rate = form.cow_rate.data
                        customer.buffalo_rate = form.buffalo_rate.data
            else:
                new_rate.farmer_id = selected_id
                farmer = Farmer.query.get(selected_id)
                if farmer:
                    entity_info = {'name': farmer.name, 'phone': farmer.phone}
                    if form.date_effective.data <= date.today():
                        farmer.cow_rate = form.cow_rate.data
                        farmer.buffalo_rate = form.buffalo_rate.data

            db.session.add(new_rate)
            db.session.commit()

            if entity_info:
                session['updated_rate_info'] = {
                    'name': entity_info['name'],
                    'phone': entity_info['phone'],
                    'cow_rate': form.cow_rate.data,
                    'buffalo_rate': form.buffalo_rate.data,
                    'date_effective': form.date_effective.data.strftime('%d-%b-%Y')
                }

            flash("Milk rate updated successfully.", "success")
            return redirect(url_for('milk_rates', type=selected_type, id=selected_id))

    updated_rate_info = session.pop('updated_rate_info', None)
    updated_rate_info_bulk = session.pop('updated_rate_info_bulk', None)
    
    all_entities = []
    if selected_id == 'all':
        if selected_type == 'customer':
            all_entities = customers
        else:
            all_entities = farmers

    return render_template(
        'milk_rates.html',
        form=form,
        customers=customers,
        farmers=farmers,
        rates=rates,
        selected_type=selected_type,
        selected_id=selected_id,
        updated_rate_info=updated_rate_info,
        updated_rate_info_bulk=updated_rate_info_bulk,
        all_entities=all_entities,
        today_date=date.today().strftime('%Y-%m-%d')
    )

@app.route('/download_rates/<type>/<date_str>')
@login_required
def download_rates(type, date_str):
    if current_user.role not in ['milkman', 'admin']:
        flash("Access denied.", "danger")
        return redirect(url_for('home'))

    try:
        selected_date = datetime.strptime(date_str, '%Y-%m-%d').date()
    except ValueError:
        flash("Invalid date format.", "danger")
        return redirect(url_for('milk_rates'))

    if type == 'customer':
        entities = Customer.query.order_by(Customer.name).all()
    elif type == 'farmer':
        entities = Farmer.query.order_by(Farmer.name).all()
    else:
        flash("Invalid type.", "danger")
        return redirect(url_for('milk_rates'))

    output = io.StringIO()
    writer = csv.writer(output)

    header = ['Name', 'Cow Milk Rate (₹/L)', 'Buffalo Milk Rate (₹/L)']
    writer.writerow(header)

    for entity in entities:
        rate = MilkRate.query.filter(
            MilkRate.date_effective <= selected_date,
            (MilkRate.customer_id == entity.id) if type == 'customer' else (MilkRate.farmer_id == entity.id)
        ).order_by(MilkRate.date_effective.desc()).first()
        
        cow_rate = rate.cow_rate if rate else entity.cow_rate
        buffalo_rate = rate.buffalo_rate if rate else entity.buffalo_rate
        
        writer.writerow([entity.name, f'{cow_rate:.2f}', f'{buffalo_rate:.2f}'])

    output.seek(0)

    return Response(
        output,
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment;filename={type}_rates_{date_str}.csv"}
    )

# ------------------------
# Customer Dashboard & Profile
# ------------------------
@app.route('/customer/dashboard')
@login_required
def customer_dashboard():
    if current_user.role != 'customer':
        flash("Access denied.", "danger")
        return redirect(url_for('home'))

    if not current_user.customer:
        flash("No customer profile is associated with this user account.", "danger")
        return redirect(url_for('home'))

    customer = db.session.query(Customer).options(
        joinedload(Customer.milkman)
    ).filter_by(id=current_user.customer.id).first()

    if not customer:
        flash("Could not find customer details in the database.", "danger")
        return redirect(url_for('home'))

    profile = {
        'name': customer.name if customer.name else 'Name Not Provided',
        'phone': customer.phone,
        'address': customer.address,
        'active': customer.active,
        'milkman': customer.milkman.username if customer.milkman else 'Not assigned',
        'cow_rate': customer.cow_rate or 0,
        'buffalo_rate': customer.buffalo_rate or 0
    }

    today = date.today()
    first_of_month = today.replace(day=1)

    today_order = Requirement.query.filter_by(customer_id=customer.id, date_requested=today).first()
    today_supply = (today_order.cow_qty or 0) + (today_order.buffalo_qty or 0) if today_order else 0

    due_amount = db.session.query(
        func.coalesce(
            func.sum(
                Requirement.cow_qty * Requirement.cow_rate_at_order +
                Requirement.buffalo_qty * Requirement.buffalo_rate_at_order,
            ), 0.0)
    ).filter(
        Requirement.customer_id == customer.id,
        Requirement.status == 'unpaid',
        Requirement.date_requested >= first_of_month
    ).scalar()

    return render_template('customer/dashboard_customer.html',
                           profile=profile,
                           today_supply=today_supply,
                           due_this_month=due_amount)

@app.route('/customer/profile', methods=['GET', 'POST'])
@login_required
def customer_profile():
    if current_user.role != 'customer':
        flash("Access denied.", "danger")
        return redirect(url_for('home'))

    customer = Customer.query.get_or_404(current_user.customer.id)
    form = CustomerForm(obj=customer)

    if request.method == 'GET' and customer.user:
        form.username.data = customer.user.username

    if form.validate_on_submit():
        customer.name = form.name.data
        customer.phone = form.phone.data
        customer.address = form.address.data

        user = customer.user
        if user:
            if user.username != form.username.data:
                existing = User.query.filter_by(username=form.username.data).first()
                if existing and existing.id != user.id:
                    flash("Username already taken.", "danger")
                    return render_template("customer_form.html", form=form, action="Edit Profile")

            user.username = form.username.data

            if form.password.data:
                user.set_password(form.password.data)

        db.session.commit()
        flash("Profile updated successfully.", "success")
        return redirect(url_for('customer_dashboard'))

    if request.method == 'POST' and not form.validate():
        flash(f"Validation errors: {form.errors}", "danger")

    return render_template("customer/customer_form.html", form=form, action="Edit Profile")

# ------------------------
# Login/Logout
# ------------------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        if current_user.role in ['admin', 'milkman']:
            return redirect(url_for('milkman_dashboard'))
        elif current_user.role == 'customer':
            return redirect(url_for('customer_dashboard'))
        elif current_user.role == 'farmer':
            return redirect(url_for('farmer_dashboard'))
        return redirect(url_for('home'))

    form = CustomerLoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            session['active_role'] = user.role

            if user.role in ['admin', 'milkman']:
                return redirect(url_for('milkman_dashboard'))
            elif user.role == 'customer':
                flash("Login successful!", "success")
                return redirect(url_for('customer_dashboard'))
            return redirect(url_for('home'))

        farmer = Farmer.query.filter_by(username=form.username.data).first()
        if farmer and farmer.check_password(form.password.data):
            login_user(farmer)
            session['active_role'] = 'farmer'
            flash("Farmer login successful!", "success")
            return redirect(url_for('farmer_dashboard'))

        flash("Invalid username or password.", "danger")

    return render_template('admin/login.html', form=form)


@app.route('/switch_role/<role>')
@login_required
def switch_role(role):
    if role not in getattr(current_user, 'roles', [current_user.role]):
        flash("You do not have permission for that role.", "danger")
        return redirect(url_for(f"{session.get('active_role', 'customer')}_dashboard"))
    session['active_role'] = role
    flash(f"Switched to {role} role.", "success")
    return redirect(url_for(f"{role}_dashboard"))


@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for('login'))

# REMOVED: Redundant farmer_logout route is no longer needed.

# ------------------------
# Milkman/Admin Dashboard
# ------------------------
from flask_wtf import FlaskForm
@app.route('/dashboard_milkman')
@login_required
def milkman_dashboard():
    if session.get('active_role') not in ['milkman', 'admin']:
        flash("Access denied: Not authorized.", "danger")
        return redirect(url_for('home'))

    # ADD THIS LINE 👇
    form = FlaskForm()  # Creates a form instance for the template

    today = date.today()
    milkman_id = current_user.id

    active_customers = Customer.query.filter_by(milkman_id=milkman_id, active=True).count()
    active_farmers = Farmer.query.filter_by(milkman_id=milkman_id, active=True).count()

    def requirement_sum(milk_type, session_name):
        return (
            db.session.query(func.sum(getattr(Requirement, milk_type)))
            .join(Customer)
            .filter(
                Customer.milkman_id == milkman_id,
                Requirement.date_requested == today,
                Requirement.session == session_name,
                Requirement.status != 'cancelled'
            ).scalar() or 0
        )

    def collection_sum(milk_type, session_name):
        return (
            db.session.query(func.sum(getattr(Collection, milk_type)))
            .join(Farmer, Farmer.id == Collection.farmer_id)
            .filter(
                Farmer.milkman_id == milkman_id,
                Collection.date == today,
                Collection.session == session_name
            ).scalar() or 0
        )

    total_cow_required_morning = requirement_sum('cow_qty', 'morning')
    total_buffalo_required_morning = requirement_sum('buffalo_qty', 'morning')
    total_cow_collected_morning = collection_sum('cow_qty', 'morning')
    total_buffalo_collected_morning = collection_sum('buffalo_qty', 'morning')

    total_cow_required_evening = requirement_sum('cow_qty', 'evening')
    total_buffalo_required_evening = requirement_sum('buffalo_qty', 'evening')
    total_cow_collected_evening = collection_sum('cow_qty', 'evening')
    total_buffalo_collected_evening = collection_sum('buffalo_qty', 'evening')

    def percent(collected, required):
        return round((collected / required) * 100, 1) if required > 0 else 0

    cow_morning_percent = percent(total_cow_collected_morning, total_cow_required_morning)
    buffalo_morning_percent = percent(total_buffalo_collected_morning, total_buffalo_required_morning)
    cow_evening_percent = percent(total_cow_collected_evening, total_cow_required_evening)
    buffalo_evening_percent = percent(total_buffalo_collected_evening, total_buffalo_required_evening)

    return render_template(
        "admin/dashboard_milkman.html",
        form=form,  # AND ADD THIS LINE 👇 to pass the form
        active_customers=active_customers,
        active_farmers=active_farmers,
        today=today,

        total_cow_required_morning=total_cow_required_morning,
        total_buffalo_required_morning=total_buffalo_required_morning,
        total_cow_collected_morning=total_cow_collected_morning,
        total_buffalo_collected_morning=total_buffalo_collected_morning,

        total_cow_required_evening=total_cow_required_evening,
        total_buffalo_required_evening=total_buffalo_required_evening,
        total_cow_collected_evening=total_cow_collected_evening,
        total_buffalo_collected_evening=total_buffalo_collected_evening,

        cow_morning_percent=cow_morning_percent,
        buffalo_morning_percent=buffalo_morning_percent,
        cow_evening_percent=cow_evening_percent,
        buffalo_evening_percent=buffalo_evening_percent
    )


@app.route('/milkman/profile', methods=['GET', 'POST'])
@login_required
def milkman_profile():
    if current_user.role != 'milkman':
        flash("Access denied.", "danger")
        return redirect(url_for('home'))

    form = MilkmanProfileForm(obj=current_user)

    if form.validate_on_submit():
        current_user.name = form.name.data
        current_user.phone = form.phone.data
        current_user.email = form.email.data

        db.session.commit()
        flash("Profile updated successfully.", "success")
        return redirect(url_for('milkman_dashboard'))

    return render_template('admin/milkman_profile.html', form=form)


# ------------------------
# Admin self activation/deactivation
# ------------------------
@app.route('/milkman/deactivate', methods=['POST'])
@login_required
def milkman_deactivate_self():
    if current_user.role != 'milkman':
        flash("Unauthorized action.", "danger")
        return redirect(url_for('milkman_dashboard'))

    current_user.is_active_admin = False
    current_user.deactivation_reason = 'Deactivated by self'
    db.session.commit()
    flash("You have deactivated your admin functions.", "info")
    return redirect(url_for('milkman_dashboard'))

@app.route('/admin/reactivate')
@login_required
def admin_reactivate_self():
    if current_user.role not in ['milkman', 'admin']:
        flash("Access denied.", "danger")
        logout_user()
        return redirect(url_for('login'))

    current_user.is_active_admin = True
    current_user.deactivation_reason = None
    db.session.commit()
    flash("Your account has been reactivated successfully!", "success")

    if current_user.role == 'milkman':
        return redirect(url_for('milkman_dashboard'))
    else:
        return redirect(url_for('admin_dashboard'))

# ------------------------
# ADMIN ANALYSIS
# ------------------------
@app.route('/admin/analysis')
@login_required
def admin_analysis():
    if current_user.role not in ['admin', 'milkman']:
        abort(403)

    milkmen = []
    selected_milkman_id = None
    if current_user.role == 'admin':
        milkmen = User.query.filter_by(role='milkman').order_by(User.username).all()
        selected_milkman_id = request.args.get('milkman_id', type=int)

    today = date.today()
    default_start_date = today.replace(day=1)
    try:
        start_date = datetime.strptime(request.args.get('start_date', default_start_date.strftime('%Y-%m-%d')), '%Y-%m-%d').date()
        end_date = datetime.strptime(request.args.get('end_date', today.strftime('%Y-%m-%d')), '%Y-%m-%d').date()
    except (ValueError, TypeError):
        start_date = default_start_date
        end_date = today

    period_days = (end_date - start_date).days + 1
    prev_end_date = start_date - timedelta(days=1)
    prev_start_date = prev_end_date - timedelta(days=period_days - 1)

    def apply_milkman_filter(query, model):
        milkman_id = None
        if current_user.role == 'milkman':
            milkman_id = current_user.id
        elif current_user.role == 'admin' and selected_milkman_id:
            milkman_id = selected_milkman_id
        
        if milkman_id:
            if model == 'customer':
                query = query.filter(Customer.milkman_id == milkman_id)
            elif model == 'farmer':
                query = query.filter(Farmer.milkman_id == milkman_id)
            elif model == 'casual_sale':
                query = query.filter(CasualSale.milkman_id == milkman_id)
            elif model == 'expense':
                query = query.filter(Expense.milkman_id == milkman_id)
            elif model == 'daily_collection':
                query = query.filter(DailyCollection.milkman_id == milkman_id)
            elif model == 'farmer_payout':
                query = query.filter(FarmerPayout.milkman_id == milkman_id)
        return query

    def get_revenue(s, e):
        req_query = db.session.query(
            func.coalesce(func.sum(
                Requirement.cow_qty * Requirement.cow_rate_at_order +
                Requirement.buffalo_qty * Requirement.buffalo_rate_at_order), 0)
        ).join(Customer).filter(
            Requirement.status == 'paid',
            Requirement.date_requested.between(s, e)
        )
        req_query = apply_milkman_filter(req_query, 'customer')
        req_revenue = float(req_query.scalar())

        casual_query = db.session.query(
            func.coalesce(func.sum(CasualSale.amount_collected), 0)
        ).filter(CasualSale.date.between(s, e))
        casual_query = apply_milkman_filter(casual_query, 'casual_sale')
        casual_revenue = float(casual_query.scalar())
        
        return req_revenue + casual_revenue

    revenue_current = get_revenue(start_date, end_date)
    revenue_previous = get_revenue(prev_start_date, prev_end_date)

    def percent_change(new, old):
        if old == 0:
            return None
        return round(((new - old) / old) * 100, 1)

    revenue_percent_change = percent_change(revenue_current, revenue_previous)

    payouts_query = db.session.query(
        func.coalesce(func.sum(FarmerPayout.amount), 0)
    ).filter(
        FarmerPayout.payment_date.between(start_date, end_date)
    )
    payouts_query = apply_milkman_filter(payouts_query, 'farmer_payout')
    farmer_payouts = float(payouts_query.scalar())

    expenses_query = db.session.query(
        func.coalesce(func.sum(Expense.amount), 0)
    ).filter(
        Expense.date.between(start_date, end_date)
    )
    expenses_query = apply_milkman_filter(expenses_query, 'expense')
    total_expenses = float(expenses_query.scalar())

    procured_individual_query = db.session.query(
        func.coalesce(func.sum(Collection.cow_qty + Collection.buffalo_qty), 0)
    ).join(Farmer).filter(
        Collection.date.between(start_date, end_date)
    )
    procured_individual_query = apply_milkman_filter(procured_individual_query, 'farmer')
    milk_procured_individual = float(procured_individual_query.scalar())

    procured_daily_query = db.session.query(
        func.coalesce(func.sum(DailyCollection.total_milk), 0)
    ).filter(
        DailyCollection.date.between(start_date, end_date)
    )
    procured_daily_query = apply_milkman_filter(procured_daily_query, 'daily_collection')
    milk_procured_daily = float(procured_daily_query.scalar())
    
    milk_procured = milk_procured_individual + milk_procured_daily

    sold_query = db.session.query(
         func.coalesce(func.sum(Requirement.cow_qty + Requirement.buffalo_qty), 0)
    ).join(Customer).filter(
        Requirement.status == 'paid',
        Requirement.date_requested.between(start_date, end_date)
    )
    sold_query = apply_milkman_filter(sold_query, 'customer')
    milk_sold = float(sold_query.scalar())

    total_spent = func.coalesce(func.sum(
        Requirement.cow_qty * Requirement.cow_rate_at_order +
        Requirement.buffalo_qty * Requirement.buffalo_rate_at_order), 0).label('total_spent')

    customers_query = db.session.query(
        Customer.name,
        total_spent
    ).join(Requirement).filter(
        Requirement.status == 'paid',
        Requirement.date_requested.between(start_date, end_date)
    )
    customers_query = apply_milkman_filter(customers_query, 'customer')

    top_customers = customers_query.group_by(Customer.id, Customer.name) \
                    .order_by(desc(total_spent)) \
                    .limit(5).all()

    total_supplied = func.coalesce(func.sum(Collection.cow_qty + Collection.buffalo_qty), 0).label('total_supplied')

    farmers_query = db.session.query(
        Farmer.name,
        total_supplied
    ).join(Collection).filter(
        Collection.date.between(start_date, end_date)
    )
    farmers_query = apply_milkman_filter(farmers_query, 'farmer')

    top_farmers = farmers_query.group_by(Farmer.id, Farmer.name) \
                    .order_by(desc(total_supplied)) \
                    .limit(5).all()

    total_value_individual_unpaid_q = db.session.query(func.coalesce(func.sum(Collection.total_amount), 0)).join(Farmer).filter(Collection.status == 'unpaid')
    total_value_individual_unpaid_q = apply_milkman_filter(total_value_individual_unpaid_q, 'farmer')
    total_value_individual_unpaid = float(total_value_individual_unpaid_q.scalar())

    total_value_consolidated_q = db.session.query(func.coalesce(func.sum(DailyCollection.total_amount), 0))
    total_value_consolidated_q = apply_milkman_filter(total_value_consolidated_q, 'daily_collection')
    total_value_consolidated = float(total_value_consolidated_q.scalar())

    total_paid_out_q = db.session.query(func.coalesce(func.sum(FarmerPayout.amount), 0))
    total_paid_out_q = apply_milkman_filter(total_paid_out_q, 'farmer_payout')
    total_paid_out = float(total_paid_out_q.scalar())

    remaining_due_pay = (total_value_individual_unpaid + total_value_consolidated) - total_paid_out

    due_collect_query = db.session.query(
        func.coalesce(func.sum(
            Requirement.cow_qty * Requirement.cow_rate_at_order +
            Requirement.buffalo_qty * Requirement.buffalo_rate_at_order), 0)
    ).join(Customer).filter(
        Requirement.status == 'unpaid',
        Requirement.date_requested.between(start_date, end_date)
    )
    due_collect_query = apply_milkman_filter(due_collect_query, 'customer')
    remaining_to_collect = float(due_collect_query.scalar())

    revenue_data = [{"month": calendar.month_abbr[m], "revenue": 0, "payout": 0, "profit": 0} for m in range(1, 13)]
    milk_flow_data = []

    total_milk_transacted = float(milk_procured or 0)

    return render_template('admin/admin_analysis.html',
        milkmen=milkmen,
        selected_milkman_id=selected_milkman_id,
        start_date=start_date,
        end_date=end_date,
        revenue_current=revenue_current,
        revenue_previous=revenue_previous,
        revenue_percent_change=revenue_percent_change,
        farmer_payouts=farmer_payouts,
        total_expenses=total_expenses,
        milk_procured=milk_procured,
        milk_sold=milk_sold,
        remaining_due_pay=remaining_due_pay,
        remaining_to_collect=remaining_to_collect,
        top_customers=top_customers,
        top_farmers=top_farmers,
        revenue_data=revenue_data,
        milk_flow_data=milk_flow_data,
        total_milk_transacted=total_milk_transacted)

# ------------------------
# ADMIN MANAGEMENT
# ------------------------
@app.route('/admin/milkmen')
@login_required
def manage_milkmen():
    if current_user.role != 'admin':
        abort(403)
    users = User.query.filter(User.role != 'customer').order_by(User.id).all()
    return render_template('admin/manage_milkmen.html', users=users)

@app.route('/admin/milkmen/add', methods=['GET', 'POST'])
@login_required
def add_milkman():
    if current_user.role != 'admin':
        abort(403)
    form = UserForm()
    if form.validate_on_submit():
        existing_user = User.query.filter_by(username=form.username.data).first()
        if existing_user:
            flash('Username already exists.', 'danger')
        elif not form.password.data:
            flash('Password is required for new users.', 'danger')
        else:
            new_user = User(
                username=form.username.data,
                role=form.role.data,
                is_active_admin=form.is_active_admin.data
            )
            new_user.set_password(form.password.data)
            db.session.add(new_user)
            db.session.commit()
            flash('Milkman account created successfully.', 'success')
            return redirect(url_for('manage_milkmen'))
    return render_template('admin/milkman_form.html', form=form, action='Add Milkman')

@app.route('/admin/milkmen/edit/<int:user_id>', methods=['GET', 'POST'])
@login_required
def edit_milkman(user_id):
    if current_user.role != 'admin':
        abort(403)
    user = User.query.get_or_404(user_id)
    form = UserForm(obj=user)
    if form.validate_on_submit():
        if user.username != form.username.data:
            existing_user = User.query.filter_by(username=form.username.data).first()
            if existing_user:
                flash('Username already exists.', 'danger')
                return render_template('admin/milkman_form.html', form=form, action='Edit Milkman')

        user.username = form.username.data
        user.role = form.role.data
        user.is_active_admin = form.is_active_admin.data
        if form.password.data:
            user.set_password(form.password.data)
        db.session.commit()
        flash('Milkman account updated successfully.', 'success')
        return redirect(url_for('manage_milkmen'))
    return render_template('admin/milkman_form.html', form=form, action='Edit Milkman')

@app.route('/admin/milkmen/toggle_status/<int:user_id>', methods=['POST'])
@login_required
def toggle_milkman_status(user_id):
    if current_user.role != 'admin':
        abort(403)
    user = User.query.get_or_404(user_id)
    user.is_active_admin = not user.is_active_admin
    db.session.commit()
    flash(f'Account for {user.username} has been {"activated" if user.is_active_admin else "deactivated"}.', 'info')
    return redirect(url_for('manage_milkmen'))

@app.route('/daily_log', methods=['GET', 'POST'])
@login_required
def daily_log():
    if current_user.role not in ['milkman', 'admin']:
        flash("Access denied.", "danger")
        return redirect(url_for('home'))

    expense_form = ExpenseForm(prefix='expense')
    sale_form = CasualSaleForm(prefix='sale')
    collection_form = MilkCollectionForm(prefix='collection')

    selected_date_str = request.args.get('date', date.today().strftime('%Y-%m-%d'))
    try:
        selected_date = datetime.strptime(selected_date_str, '%Y-%m-%d').date()
    except ValueError:
        selected_date = date.today()

    if expense_form.validate_on_submit() and expense_form.submit_expense.data:
        new_expense = Expense(
            milkman_id=current_user.id,
            date=selected_date,
            expense_type=expense_form.expense_type.data,
            amount=expense_form.amount.data,
            remarks=expense_form.remarks.data
        )
        db.session.add(new_expense)
        db.session.commit()
        flash("Expense recorded successfully.", "success")
        return redirect(url_for('daily_log', date=selected_date_str))

    if sale_form.validate_on_submit() and sale_form.submit_sale.data:
        new_sale = CasualSale(
            milkman_id=current_user.id,
            date=selected_date,
            session=sale_form.session.data,
            cow_qty=sale_form.cow_qty.data,
            buffalo_qty=sale_form.buffalo_qty.data,
            amount_collected=sale_form.amount_collected.data
        )
        db.session.add(new_sale)
        db.session.commit()
        flash("Casual sale recorded successfully.", "success")
        return redirect(url_for('daily_log', date=selected_date_str))

    if collection_form.validate_on_submit() and collection_form.submit_collection.data:
        new_collection = DailyCollection(
            milkman_id=current_user.id,
            date=selected_date,
            session=collection_form.session.data,
            total_milk=collection_form.total_milk.data,
            total_amount=collection_form.total_value.data
        )
        db.session.add(new_collection)
        db.session.commit()
        flash("Consolidated collection value recorded successfully.", "success")
        return redirect(url_for('daily_log', date=selected_date_str))

    expenses = Expense.query.filter_by(milkman_id=current_user.id, date=selected_date).all()
    casual_sales = CasualSale.query.filter_by(milkman_id=current_user.id, date=selected_date).all()
    daily_collections = DailyCollection.query.filter_by(milkman_id=current_user.id, date=selected_date).all()

    return render_template(
        'admin/daily_log.html',
        expense_form=expense_form,
        sale_form=sale_form,
        collection_form=collection_form,
        expenses=expenses,
        casual_sales=casual_sales,
        daily_collections=daily_collections,
        selected_date=selected_date
    )


def apply_future_rates():
    """
    Job to apply milk rates that are due to become effective today.
    """
    with app.app_context():
        today = date.today()
        print(f"[{datetime.now()}] Running scheduled job: Applying milk rates for {today.strftime('%Y-%m-%d')}")

        rates_to_update = MilkRate.query.filter_by(date_effective=today).all()
        if not rates_to_update:
            print("No new milk rates to apply today.")
            return

        customer_rates = {}
        farmer_rates = {}

        for rate in rates_to_update:
            if rate.for_group == 'customer' and rate.customer_id:
                # If multiple rates for the same customer, last one wins
                customer_rates[rate.customer_id] = (rate.cow_rate, rate.buffalo_rate)
            elif rate.for_group == 'farmer' and rate.farmer_id:
                farmer_rates[rate.farmer_id] = (rate.cow_rate, rate.buffalo_rate)

        if customer_rates:
            for customer_id, (cow_rate, buffalo_rate) in customer_rates.items():
                customer = Customer.query.get(customer_id)
                if customer:
                    customer.cow_rate = cow_rate
                    customer.buffalo_rate = buffalo_rate
                    print(f"Updated rates for Customer {customer.id} ({customer.name})")

        if farmer_rates:
            for farmer_id, (cow_rate, buffalo_rate) in farmer_rates.items():
                farmer = Farmer.query.get(farmer_id)
                if farmer:
                    farmer.cow_rate = cow_rate
                    farmer.buffalo_rate = buffalo_rate
                    print(f"Updated rates for Farmer {farmer.id} ({farmer.name})")

        db.session.commit()
        print(f"Successfully applied {len(rates_to_update)} new milk rates.")


@app.route('/manage_announcements', methods=['GET', 'POST'])
@login_required
def manage_announcements():
    if current_user.role not in ['milkman', 'admin']:
        flash("Access denied.", "danger")
        return redirect(url_for('home'))

    form = AnnouncementForm()
    if form.validate_on_submit():
        announcement = Announcement(
            title=form.title.data,
            content=form.content.data,
            milkman_id=current_user.id
        )
        db.session.add(announcement)
        db.session.commit()
        flash('Your announcement has been created!', 'success')
        return redirect(url_for('manage_announcements'))

    announcements = Announcement.query.filter_by(milkman_id=current_user.id).order_by(Announcement.date_posted.desc()).all()
    return render_template('admin/manage_announcements.html', form=form, announcements=announcements)

@app.route('/farmer_payouts', methods=['GET', 'POST'])
@login_required
def farmer_payouts():
    if current_user.role not in ['milkman', 'admin']:
        abort(403)

    form = FarmerPayoutForm()
    
    if form.validate_on_submit():
        new_payout = FarmerPayout(
            milkman_id=current_user.id,
            amount=form.amount.data,
            payment_date=form.payment_date.data,
            remarks=form.remarks.data
        )
        db.session.add(new_payout)
        db.session.commit()
        flash("Payout recorded successfully.", "success")
        return redirect(url_for('farmer_payouts'))

    # Calculate outstanding due
    total_value_collected = db.session.query(func.sum(DailyCollection.total_amount)).filter_by(milkman_id=current_user.id).scalar() or 0
    total_paid = db.session.query(func.sum(FarmerPayout.amount)).filter_by(milkman_id=current_user.id).scalar() or 0
    outstanding_due = total_value_collected - total_paid

    payouts = FarmerPayout.query.filter_by(milkman_id=current_user.id).order_by(FarmerPayout.payment_date.desc()).all()

    return render_template(
        'admin/farmer_payouts.html',
        form=form,
        payouts=payouts,
        outstanding_due=outstanding_due
    )

# ------------------------
# Run App
# ------------------------
if __name__ == '__main__':
    scheduler = BackgroundScheduler(daemon=True)
    # Schedule job to run daily at 5:30 AM
    scheduler.add_job(apply_future_rates, 'cron', hour=5, minute=30)
    scheduler.start()
    # Shut down the scheduler when exiting the app
    atexit.register(lambda: scheduler.shutdown())

    with app.app_context():
        db.create_all()
    app.run(debug=True)
