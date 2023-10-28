from flask import Blueprint, render_template, redirect, url_for, request, flash, session ,jsonify
import os
from database import db, bcrypt , User , File
from utils import calculate_sha256, encrypt_file , decrypt_file , login_required , admin_required
import datetime
#from itsdangerous import URLSafeTimedSerializer
#
# Initialize the serializer with a secret key  will import from main
#serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"])


web = Blueprint('web', __name__)
api = Blueprint('api', __name__)


@web.route("/")
@login_required
def index():
    return redirect(url_for("web.dashboard"))

@web.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html", username=session['username'])

@web.route("/upload")
@login_required
def upload():
    return render_template("upload.html")

@web.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")
        
        # Check if the user exists
        user = User.query.filter((User.username == email) | (User.email == email)).first()

        if user:
            # Check if the user is approved
            if user.is_approved == "True":
                if bcrypt.check_password_hash(user.password, password):
                    session["user_id"] = user.id
                    session["username"] = user.username
                    session["role"] = user.role
                    if user.role == "admin":
                        return redirect(url_for("web.admin"))
                    else:
                        return redirect(url_for("web.dashboard"))  # Redirect to the profile route
                else:
                    return render_template("login.html", message="Incorrect username or password")
            else:
                return render_template("login.html", message="Await admin approval")
        else:
            return render_template("login.html", message="Incorrect username or password")

    return render_template("login.html")


@web.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        email = request.form.get("email")
        role = request.form.get("role")


        # Check if the username is already taken
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            return "Username already taken. Please choose another username."
        else:
            # Hash the password and create a new user
            hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")
            new_user = User(username=username, password=hashed_password , email=email, role="user", is_approved="False")
            db.session.add(new_user)
            db.session.commit()
            return render_template("login.html", message="Await admin approval") # Redirect to the login route

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
    session.pop("user_id",None)
    session.pop("username",None)
    session.pop("role",None)
    return redirect(url_for("web.login")) 

@web.route("/admin")
@admin_required  # Apply the decorator to protect this admin route
def admin():
    user = User.query.all()
    files = File.query.all()

    return render_template("admin.html", username= session["username"]) 




@api.route("/viewFiles")
@login_required
def viewFile():
     # List files in the 'uploads' directory
    upload_dir = 'uploads/'+session['username']
    file_names = os.listdir(upload_dir)
    return jsonify(file_names)
    
    

@api.route("/addFiles", methods=['POST'])
@login_required
def addFiles():
    if 'file' not in request.files:
        return 'No file part'

    file = request.files['file']
    permission_level= request.form.get("permission_level")

    if file.filename == '':
        return 'No selected file'

    # Save the file in the 'uploads/username' directory
    file_path = os.path.join('uploads/',session['username'], file.filename)
    file.save(file_path)

    #encrypt file
    success, message = encrypt_file(file_path)

    # Calculate the SHA-256 hash of the file
    sha256_hash = calculate_sha256(file_path)

    new_file = File(owner_id=session['user_id'],file_name=file.filename, file_path=file_path,upload_date=datetime.datetime.now(),file_size=file.content_length,sha256sum=sha256_hash,is_pending_deletion="False",permission_level=permission_level)
    db.session.add(new_file)
    db.session.commit()


    return render_template("upload.html",status=sha256_hash)
    

@api.route("/deleteFiles", methods=["POST"])
@login_required
def delete_file():
    file_name = request.form.get("file_name")

    if file_name:
        file_path = os.path.join("uploads", session["username"], file_name)

        if os.path.exists(file_path):
            # Mark the file as pending for deletion in the database
            file = File.query.filter_by(file_name=file_name).first()

            if file:
                file.is_pending_deletion = "True"
                db.session.commit()
                return "Deletion of file pending approval"
            else:
                return "File not found or could not be marked for deletion in the database"



@api.route('/download/<file_name>')
@login_required
def download_file(file_name):
    file_path = os.path.join('uploads',session['username'], file_name)

    # Decrypt the file and get the Flask response
    success, response = decrypt_file(file_path)

    if success:
        return response
    else:
        return f'Failed to decrypt the file {response}'

##admin functionaties



@api.route('/pending_users', methods=['GET'])
@admin_required
def get_pending_users():
    # Query the database to get pending user registrations
    pending_users = User.query.filter_by(is_approved="False").all()
    # Create a list to store user details
    pending_user_details = []

    for user in pending_users:
        user_detail = {
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'role': user.role,
        }
        pending_user_details.append(user_detail)

    # Return the pending user details in JSON format using jsonify
    return jsonify(pending_user_details)

@api.route("/pending_deletion_requests", methods=["GET"])
@admin_required
def get_pending_deletion_requests():
    # Find all files that are pending deletion
    pending_deletion_files = File.query.filter_by(is_pending_deletion="True").all()
    
    # Check if there are pending deletion files
    if pending_deletion_files:
        # Extract file names from the list of pending deletion files
        pending_files_data = [{"file_name": file.file_name} for file in pending_deletion_files]
        return jsonify(pending_files_data)
    else:
        return jsonify({"message": "No files pending deletion."})


@api.route("/approve_deletion/<string:file_name>", methods=["POST"])
@admin_required
def approve_deletion(file_name):
    # Find the file by name
    file = File.query.filter_by(file_name=file_name).first()

    if file and file.is_pending_deletion:
        # Perform the actual file deletion
        # Here, you can add code to delete the file from the file system
        # For example, if you're using the os module, you can do:
        
        os.remove(file.file_path)

        # Delete the file record from the database
        db.session.delete(file)
        db.session.commit()

        return jsonify({"message": "File deleted and record removed."})
    else:
        return jsonify({"message": "File not found or not pending deletion."})




@api.route('/approve_user/<int:user_id>', methods=['POST'])
@admin_required
def approve_user(user_id):
    # Check if the request is a POST request
    if request.method == 'POST':
        # Find the user by ID
        user = User.query.get(user_id)
        
        if user:
            # Mark the user as approved
            user.is_approved = "True"
            db.session.commit()
            user_folder = os.path.join("uploads", user.username)
            os.makedirs(user_folder, exist_ok=True)
            return jsonify({'message': 'User has been approved.'}), 200
        else:
            return jsonify({'error': 'User not found.'}), 404

    return jsonify({'error': 'Invalid request method.'}), 405


from flask import request

@web.route("/users", methods=["GET", "POST"])
@admin_required
def manage_users():
    if request.method == "POST":
        # Handle the user deletion based on the submitted form data
        user_id_to_delete = request.form.get("user_id_to_delete")
        
        # Check if the user_id_to_delete is valid (e.g., exists and is not the admin)
        user_to_delete = User.query.get(user_id_to_delete)
        user_to_delete_files = File.query.filter_by(owner_id=user_id_to_delete)
        if user_to_delete and user_to_delete.role != "admin":
            db.session.delete(user_to_delete)
            db.session.commit()
            #db.session.delete(user_to_delete_files)
            #db.session.commit
            #user_folder = os.path.join("uploads", user_to_delete.username)
            #os.rmdir(user_folder, exist_ok=True)
            

            # Redirect to the same page after user deletion
            return redirect(url_for("web.manage_users"))

    # Retrieve a list of all users from the database
    users = User.query.all()

    return render_template("users.html", users=users)

@web.route("/files", methods=["GET"])
@admin_required
def files():
    files = File.query.all()

    return render_template("files.html", files=files)

## backup

@web.route("/backup", methods=["GET"])
@admin_required
def backup():
    return "backup"

# TO-DO


# Route for requesting a password reset
#@web.route("/forgot_password", methods=["GET", "POST"])
#def forgot_password():
#    if request.method == "POST":
#        username_or_email = request.form.get("username_or_email")
#        user = User.query.filter((User.username == username_or_email) | (User.email == username_or_email)).first()
#        
#        if user:
#            # Generate a token for password reset
#            token = serializer.dumps(user.username, salt='password-reset')
#            
#            # Send an email with a link containing the token
#            # Use Flask-Mail or another email library to send the email
#            send_password_reset_email(user.email, token)
#
#        flash("If the provided email/username exists, you will receive an email with instructions to reset your password.", "info")
#
#    return render_template("forgot_password.html")
#
## Route for resetting the password
#@web.route("/reset_password/<token>", methods=["GET", "POST"])
#def reset_password(token):
#    try:
#        # Verify and decode the token
#        username = serializer.loads(token, salt='password-reset', max_age=3600)
#        user = User.query.filter_by(username=username).first()
#    except Exception:
#        flash("The reset link is invalid or has expired.", "danger")
#        return redirect(url_for("web.login"))
#
#    if request.method == "POST":
#        new_password = request.form.get("new_password")
#        hashed_password = bcrypt.generate_password_hash(new_password).decode("utf-8")
#        user.password = hashed_password
#        db.session.commit()
#
#        flash("Your password has been reset. You can now log in with your new password.", "success")
#        return redirect(url_for("web.login"))
#
#    return render_template("reset_password.html")
#