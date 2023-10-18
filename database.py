from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt

db = SQLAlchemy()
bcrypt = Bcrypt()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    email= db.Column(db.String(50))
    role = db.Column(db.String(50))

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    file_name = db.Column(db.String(255), nullable=False)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    file_path = db.Column(db.String(60))
    upload_date = db.Column(db.String(60))
    file_size= db.Column(db.String(60))
    sha256sum= db.Column(db.Integer)
    # ... Other file-related columns ...

class Permission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey('file.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    permission_level = db.Column(db.String(20), nullable=False)
    # ... Other permission-related columns ...
