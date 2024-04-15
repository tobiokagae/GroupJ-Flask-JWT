import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager
from flask_migrate import Migrate  # Tambahkan ini

import secrets

app = Flask(__name__)

# Generate a secure random key
secret_key = secrets.token_urlsafe(32)
app.config['SECRET_KEY'] = secret_key  # Ubah ke 'SECRET_KEY'

app.config["SQLALCHEMY_DATABASE_URI"] = "mysql://root:@localhost/db_repositori"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Inisialisasi SQLAlchemy
db = SQLAlchemy(app)

# Inisialisasi Flask-Migrate
migrate = Migrate(app, db)  # Tambahkan ini

# Inisialisasi Flask-JWT-Extended
jwt = JWTManager(app)

