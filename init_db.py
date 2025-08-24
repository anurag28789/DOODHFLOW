from flask import Flask
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)

app.config['SECRET_KEY'] = 'your-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///doodhflow.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Correct Customer model
class Customer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    phone = db.Column(db.String(30), nullable=False)
    address = db.Column(db.String(250), nullable=False)
    cow_qty = db.Column(db.Float, default=0.0)
    buffalo_qty = db.Column(db.Float, default=0.0)
    preferences = db.Column(db.String(128))
    milkman_id = db.Column(db.Integer, nullable=False)

with app.app_context():
    db.drop_all()
    db.create_all()
    print("✅ Fresh doodhflow.db created with Customer table that includes name, phone, and address.")
import os
print("📁 File created at:", os.path.abspath("doodhflow.db"))
