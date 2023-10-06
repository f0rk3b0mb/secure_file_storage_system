from flask import Flask
from database import db, bcrypt
from blueprints.routes import web, api

app = Flask(__name__)

# Load your Flask app configuration here
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.secret_key = 'your_secret_key_here'

# Initialize Flask extensions
db.init_app(app)
bcrypt.init_app(app)

# Register your blueprints
app.register_blueprint(web, url_prefix='/')
app.register_blueprint(api, url_prefix='/api')

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(host="127.0.0.1", port=1234, debug=True)

