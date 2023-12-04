from flask import Flask
from database import db, bcrypt
from blueprints.routes import web, api
from database import User , Permission , Role # Replace 'YourModel' with your actual model
from datetime import timedelta
#from flask_sslify import SSLify

app = Flask(__name__)
#sslify = SSLify(app)

app.permanent_session_lifetime = timedelta(minutes=5)

# Load your Flask app configuration here
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.secret_key = 'IAMTHEADMIN' # should be sored in environ

# Initialize Flask extensions
db.init_app(app)
bcrypt.init_app(app)

# Register your blueprints
app.register_blueprint(web, url_prefix='/')
app.register_blueprint(api, url_prefix='/api')

# Function to insert a default record
def add_default_record():
    with app.app_context():
        # Create a default record using your model
        default_admin = User(username="admin", password="$2b$12$o04Lx6GDKPszf9jAGU/p6Odd.V1/iy1lvKg4rrc2vWEniF7qIggya" , email="admin@admin.com", role_id=1, is_approved="True")
        db.session.add(default_admin)
        default_user = User(username="test", password="$2b$12$Ao/3PraUlRgGsrbGx/KaEOTRudI83.F/6dX0n2waaXLVRLnauu9Ni" , email="test@test.com", role_id=2, is_approved="True")
        db.session.add(default_user)
        admin_role = Role(id=1 , role_name="admin")
        db.session.add(admin_role)
        user_role = Role(id=2 , role_name="user")
        db.session.add(user_role)
        admission_role = Role(id=3 , role_name="admission officer")
        db.session.add(admission_role)
        exams_role = Role(id=4 , role_name="Exams officer")
        db.session.add(exams_role)
        private_perm = Permission(id=1 , permission="private")
        db.session.add(private_perm)
        public_perm = Permission(id=2 , permission="public")
        db.session.add(public_perm)
        db.session.commit()

if __name__ == "__main__":
    with app.app_context():
        db.drop_all()  #for testing purposes
        db.create_all()
        add_default_record()  # for testing purposes
    app.run(host="0.0.0.0", port=1234, debug=True)#,ssl_context=('https_certs/cert.pem', 'https_certs/key.pem'))
