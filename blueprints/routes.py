from flask import Blueprint, render_template, redirect, url_for, request, flash, session ,jsonify
import os
from database import db, bcrypt , User
from utils import calculate_sha256, encrypt_file , decrypt_file , login_required , admin_required



web = Blueprint('web', __name__)
api = Blueprint('api', __name__)


@web.route("/")
@login_required
def index():
    return redirect(url_for("web.dashboard"))

@web.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html")

@web.route("/upload")
@login_required
def upload():
    return render_template("upload.html")

@web.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        
        # Check if the user exists
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password, password):
            session["user_id"] = user.id
            flash("You are now logged in!", "success")
            return redirect(url_for("web.dashboard"))  # Redirect to the profile route
        else:
            return "Incorrect username or password"

    return render_template("login.html")

@web.route("/register", methods=["GET", "POST"])
@admin_required
def register():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        # Check if the username is already taken
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash("Username already taken. Please choose another username.", "danger")
        else:
            # Hash the password and create a new user
            hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")
            new_user = User(username=username, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            flash("Your account has been created! You can now log in.", "success")
            return redirect(url_for("web.login"))  # Redirect to the login route

    return render_template("register.html")

@web.route("/profile")
@login_required
def profile():
    if "user_id" in session:
        user = User.query.get(session["user_id"])
        return f"Welcome, {user.username}!"
    else:
        flash("You must be logged in to access this page.", "warning")
        return redirect(url_for("web.login"))  # Redirect to the login route

@web.route("/logout")
def logout():
    session.pop("user_id", None)
    flash("You have been logged out.", "success")
    return redirect(url_for("web.login")) 

@web.route("/admin")
@admin_required  # Apply the decorator to protect this admin route
def admin():
    return render_template("admin.html") 




@api.route("/viewFiles")
@login_required
def viewFile():
     # List files in the 'uploads' directory
    upload_dir = 'uploads'
    file_names = os.listdir(upload_dir)
    return jsonify(file_names)
    
    

@api.route("/addFiles", methods=['POST'])
@login_required
def addUser():
    if 'file' not in request.files:
        return 'No file part'

    file = request.files['file']

    if file.filename == '':
        return 'No selected file'

    # Save the file in the 'uploads' directory
    file_path = os.path.join('uploads', file.filename)
    file.save(file_path)

    #encrypt file
    success, message = encrypt_file(file_path)

    # Calculate the SHA-256 hash of the file
    sha256_hash = calculate_sha256(file_path)

    return f"sha256sum is {sha256_hash}"
    

@api.route("/deleteFiles",methods=['POST'])
@login_required
def deleteFile():
    file_name = request.form.get('file_name')

    if file_name:
        file_path = os.path.join('uploads', file_name)

        if os.path.exists(file_path):
            os.remove(file_path)
            return f'File {file_name} has been deleted'

    return 'File not found or could not be deleted'


@api.route('/download/<file_name>')
@login_required
def download_file(file_name):
    file_path = os.path.join('uploads', file_name)

    # Decrypt the file and get the Flask response
    success, response = decrypt_file(file_path)

    if success:
        return response
    else:
        return f'Failed to decrypt the file'
