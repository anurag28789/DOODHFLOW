from flask_wtf import FlaskForm
from wtforms import (
    StringField, FloatField, SubmitField, SelectField,
    DateField, PasswordField, TextAreaField, BooleanField,
    IntegerField, SelectMultipleField
)
from wtforms.validators import (
    DataRequired, NumberRange, Optional, Length, AnyOf, EqualTo, InputRequired, Email
)
from datetime import date
# ✅ CSRF is automatically enabled by FlaskForm + CSRFProtect in app.py

# ---------------------- ADMIN DEACTIVATION FORM ----------------------
class AdminDeactivationForm(FlaskForm):
    reason = TextAreaField('Reason for Deactivation', validators=[DataRequired()])
    submit = SubmitField('Deactivate Myself')

class MilkmanProfileForm(FlaskForm):
    name = StringField('Full Name', validators=[DataRequired(), Length(max=150)])
    phone = StringField('Phone Number', validators=[Optional(), Length(max=20)])
    email = StringField('Email', validators=[Optional(), Email(), Length(max=150)])
    submit = SubmitField('Save Changes')

# ---------------------- CUSTOMER FORM ----------------------
class CustomerForm(FlaskForm):
    """
    An improved customer form with password confirmation and custom date validation.
    """
    # --- Basic Information ---
    name = StringField(
        "Name",
        validators=[DataRequired(), Length(min=2, max=50)]
    )
    phone = StringField(
        "Phone Number",
        validators=[DataRequired(), Length(min=10, max=15)]
    )
    address = StringField(
        "Address",
        validators=[DataRequired(), Length(min=5, max=100)]
    )

    # --- Milk Rates ---
    cow_rate = FloatField(
        "Cow Milk Rate (₹ per litre)",
        validators=[DataRequired(), NumberRange(min=0)]
    )
    buffalo_rate = FloatField(
        "Buffalo Milk Rate (₹ per litre)",
        validators=[DataRequired(), NumberRange(min=0)]
    )

    # --- User Credentials ---
    username = StringField(
        "Username",
        validators=[DataRequired(), Length(min=4, max=25)]
    )
    password = PasswordField(
        "New Password",
        # 'Optional' means this field is not required, which is useful for an edit form
        # where the password isn't always being changed.
        validators=[Optional(), Length(min=4)]
    )
    confirm_password = PasswordField(
        "Confirm New Password",
        # This ensures the value of this field matches the 'password' field.
        validators=[EqualTo('password', message='Passwords must match.')]
    )

    # --- Customer Vacation/Pause Period ---
    pause_start = DateField(
        "Vacation Start",
        format="%Y-%m-%d",
        validators=[Optional()]
    )
    pause_end = DateField(
        "Vacation End",
        format="%Y-%m-%d",
        validators=[Optional()]
    )

    submit = SubmitField("Submit")

    def validate_pause_end(self, field):
        """
        Custom validator to ensure the pause_end date is not before the pause_start date.
        This method is automatically called by WTForms on the 'pause_end' field.
        """
        if field.data and self.pause_start.data:
            if field.data < self.pause_start.data:
                raise ValidationError("Vacation end date cannot be before the start date.")




# ---------------------- LOGIN FORMS ----------------------
class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Length(max=150)])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")


class CustomerLoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Length(max=150)])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")


# ---------------------- REQUIREMENT FORM ----------------------
class RequirementForm(FlaskForm):
    """
    Form for submitting milk requirements with conditional validation
    depending on whether it is a single order or recurring subscription.
    """

    session = SelectField(
        "Session",
        choices=[
            ('morning', 'Morning'),
            ('evening', 'Evening')
        ],
        validators=[DataRequired(message="Please select a session.")]
    )

    date_requested = DateField(
        "Date",
        validators=[Optional()]  # Conditionally required in validate()
    )

    cow_qty = IntegerField(
        "Cow Milk Quantity (liters)",
        validators=[
            InputRequired(message="Enter cow milk quantity (0 allowed)"),
            NumberRange(min=0, message="Quantity cannot be negative")
        ]
    )

    buffalo_qty = IntegerField(
        "Buffalo Milk Quantity (liters)",
        validators=[
            InputRequired(message="Enter buffalo milk quantity (0 allowed)"),
            NumberRange(min=0, message="Quantity cannot be negative")
        ]
    )

    is_recurring = BooleanField('Subscribe')

    recurrence_pattern = SelectMultipleField(
        'Days of Week',
        choices=[
            ('mon', 'Monday'),
            ('tue', 'Tuesday'),
            ('wed', 'Wednesday'),
            ('thu', 'Thursday'),
            ('fri', 'Friday'),
            ('sat', 'Saturday'),
            ('sun', 'Sunday')
        ],
        validators=[Optional()]
    )
    repeat_start_date = DateField('Repeat Start', validators=[Optional()])
    repeat_end_date = DateField('Repeat End', validators=[Optional()])

    submit = SubmitField("Submit Requirement")

    def validate(self, extra_validators=None):
        """
        Extended validation to enforce:
        - Single orders require date_requested and no recurrence fields.
        - Recurring orders require no date_requested but require days, start and end dates.
        - Repeat start date cannot be after repeat end date.
        """
        rv = super().validate(extra_validators=extra_validators)
        if not rv:
            return False

        # Trim and normalize session field if needed
        if self.session.data:
            self.session.data = self.session.data.strip().lower()

        if self.is_recurring.data:
            # Recurring order validation rules
            if self.date_requested.data:
                self.date_requested.errors.append("Single date should be empty for recurring orders.")
                return False

            if not self.recurrence_pattern.data:
                self.recurrence_pattern.errors.append("Select at least one day of the week for recurrence.")
                return False

            if not self.repeat_start_date.data:
                self.repeat_start_date.errors.append("Repeat start date is required for recurring orders.")
                return False

            if not self.repeat_end_date.data:
                self.repeat_end_date.errors.append("Repeat end date is required for recurring orders.")
                return False

            if self.repeat_start_date.data > self.repeat_end_date.data:
                self.repeat_end_date.errors.append("Repeat end date must be after start date.")
                return False

        else:
            # Single order validation rules
            if not self.date_requested.data:
                self.date_requested.errors.append("Date is required for single orders.")
                return False

            if self.recurrence_pattern.data:
                self.recurrence_pattern.errors.append("Days of Week should be empty for single orders.")
                return False

            if self.repeat_start_date.data or self.repeat_end_date.data:
                self.repeat_start_date.errors.append("Repeat start/end dates should be empty for single orders.")
                return False

        return True

# ---------------------- MILK RATE FORM ----------------------
class MilkRateForm(FlaskForm):
    for_group = SelectField(
        "For Group",
        choices=[("customer", "Customer"), ("farmer", "Farmer")],
        validators=[DataRequired(), AnyOf(["customer", "farmer"])]
    )
    cow_rate = FloatField("Cow Milk Rate (₹/Litre)", validators=[DataRequired(), NumberRange(min=0)])
    buffalo_rate = FloatField("Buffalo Milk Rate (₹/Litre)", validators=[DataRequired(), NumberRange(min=0)])
    date_effective = DateField("Effective Date", format="%Y-%m-%d", validators=[DataRequired()])
    submit = SubmitField("Set Rate")


# ---------------------- DELIVERY FORM ----------------------
class DeliveryForm(FlaskForm):
    customer_id = StringField("Customer ID", validators=[DataRequired()])
    date = DateField("Delivery Date", format="%Y-%m-%d", validators=[DataRequired()])
    cow_qty = FloatField("Cow Milk Delivered (L)", validators=[DataRequired(), NumberRange(min=0)])
    buffalo_qty = FloatField("Buffalo Milk Delivered (L)", validators=[DataRequired(), NumberRange(min=0)])
    total_price = FloatField("Total Price Collected (₹)", validators=[DataRequired(), NumberRange(min=0)])
    remarks = StringField("Remarks", validators=[Optional()])
    submit = SubmitField("Log Delivery")


# ---------------------- COLLECTION FORM ----------------------
class CollectionForm(FlaskForm):
    farmer_id = StringField("Farmer ID", validators=[DataRequired()])
    date = DateField("Collection Date", format="%Y-%m-%d", validators=[DataRequired()])
    cow_qty = FloatField("Cow Milk Collected (L)", validators=[DataRequired(), NumberRange(min=0)])
    buffalo_qty = FloatField("Buffalo Milk Collected (L)", validators=[DataRequired(), NumberRange(min=0)])
    total_paid = FloatField("Cash Paid (₹)", validators=[DataRequired(), NumberRange(min=0)])
    remarks = StringField("Remarks", validators=[Optional()])
    submit = SubmitField("Log Collection")


# ---------------------- PAYMENT FORM ----------------------
class PaymentForm(FlaskForm):
    amount = FloatField("Amount Collected (₹)", validators=[DataRequired(), NumberRange(min=0.01)])
    remarks = TextAreaField("Remarks (optional)")
    submit = SubmitField("Record Payment")


#----------------------FARMER FORM-----------------------------
class FarmerForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=150)])
    password = PasswordField('Password', validators=[Optional(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[Optional(), EqualTo('password', message='Passwords must match')])
    # Farmer basic info
    name = StringField('Name', validators=[DataRequired()])
    phone = StringField('Phone', validators=[DataRequired()])
    address = StringField('Address', validators=[Optional()])
    # 🆕 Individual milk rates — per farmer
    cow_rate = FloatField('Cow Milk Rate (₹/L)', validators=[Optional(), NumberRange(min=0)])
    buffalo_rate = FloatField('Buffalo Milk Rate (₹/L)', validators=[Optional(), NumberRange(min=0)])
    active = BooleanField('Active', default=True)
    submit = SubmitField('Save')

# ---------------------- USER MANAGEMENT FORM ----------------------
class UserForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=25)])
    password = PasswordField('Password', validators=[
        Optional(),
        Length(min=6),
        EqualTo('confirm_password', message='Passwords must match')
    ])
    confirm_password = PasswordField('Confirm Password')
    role = SelectField('Role', choices=[('milkman', 'Milkman'), ('admin', 'Admin')], validators=[DataRequired()])
    is_active_admin = BooleanField('Is Active', default=True)
    submit = SubmitField('Save User')

class ExpenseForm(FlaskForm):
    expense_type = SelectField(
        "Expense Type",
        choices=[
            ('Fuel', 'Fuel'),
            ('Vehicle Maintenance', 'Vehicle Maintenance'),
            ('Packaging', 'Packaging'),
            ('Other', 'Other')
        ],
        validators=[DataRequired()]
    )
    amount = FloatField("Amount (₹)", validators=[DataRequired(), NumberRange(min=0)])
    remarks = StringField("Remarks", validators=[Optional(), Length(max=255)])
    submit_expense = SubmitField("Add Expense")

class CasualSaleForm(FlaskForm):
    session = SelectField(
        "Session",
        choices=[('morning', 'Morning'), ('evening', 'Evening')],
        validators=[DataRequired()]
    )
    cow_qty = FloatField("Cow Milk (L)", validators=[Optional(), NumberRange(min=0)], default=0.0)
    buffalo_qty = FloatField("Buffalo Milk (L)", validators=[Optional(), NumberRange(min=0)], default=0.0)
    amount_collected = FloatField("Amount Collected (₹)", validators=[DataRequired(), NumberRange(min=0)])
    submit_sale = SubmitField("Add Sale")

class AnnouncementForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired(), Length(max=100)])
    content = TextAreaField('Content', validators=[DataRequired()])
    submit = SubmitField('Post Announcement')

class FarmerPayoutForm(FlaskForm):
    """Form for recording payouts to farmers."""
    amount = FloatField("Amount Paid (₹)", validators=[DataRequired(), NumberRange(min=0.01)])
    payment_date = DateField("Payment Date", format="%Y-%m-%d", validators=[DataRequired()], default=date.today)
    remarks = StringField("Remarks", validators=[Optional(), Length(max=255)])
    submit_payout = SubmitField("Record Payout")

class MilkCollectionForm(FlaskForm):
    """Form for logging the daily consolidated milk collection value."""
    total_milk = FloatField("Total Milk Collected (L)", validators=[DataRequired(), NumberRange(min=0)])
    total_value = FloatField("Total Value of Milk (₹)", validators=[DataRequired(), NumberRange(min=0)])
    session = SelectField(
        "Session",
        choices=[('morning', 'Morning'), ('evening', 'Evening')],
        validators=[DataRequired()]
    )
    submit_collection = SubmitField("Add Collection Value")
