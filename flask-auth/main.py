from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
import werkzeug
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from flask_login import LoginManager



app = Flask(__name__)

login_manager = LoginManager()
login_manager.init_app(app)


app.config['SECRET_KEY'] = 'any-secret-key-you-choose'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

##CREATE TABLE IN DB
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))
#Line below only required once, when creating DB. 
with app.app_context():
    db.create_all()



@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

@app.route('/')
def home():
    return render_template("index.html", logged_in=current_user.is_authenticated)


@app.route('/register', methods=['GET', 'POST'])
@app.route('/register')
def register():
    if request.method == "POST":
        name = request.form["name"]
        email = request.form["email"]
        password = request.form["password"]
        salted_pw = werkzeug.security.generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)
        user = User(email=email, password=salted_pw, name=name)

        
        if User.query.filter_by(email=email).first():
            #User already exists
            flash("You've already signed up with that email, log in instead!")
            return redirect(url_for('login'))
        
        db.session.add(user)
        db.session.commit()
        login_user(user)
        return render_template("secrets.html",name=name, logged_in=current_user.is_authenticated)
    else:    
        return render_template("register.html")


@app.route('/login')
@app.route('/login', methods=["POST","GET"])
def login():

    if request.method == "POST":
        email = request.form.get('email')
        password = request.form.get('password')

        
        #Find user by email entered.
        user = User.query.filter_by(email=email).first()
        #Email doesn't exist
        if not user:
            flash("That email does not exist, please try again.")
            return redirect(url_for('login'))
        #Password incorrect
        elif not check_password_hash(user.password, password):
            flash('Password incorrect, please try again.')
            return redirect(url_for('login'))
        #Email exists and password correct
        else:
            login_user(user)
            return render_template("secrets.html",name=user.name, logged_in=current_user.is_authenticated)
    return render_template("login.html")


@app.route('/secrets',)
@login_required
def secrets():
    return render_template("secrets.html", logged_in=True)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route('/download/<path:filename>')
@login_required
def download(filename):
    path = "static/files"
    return send_from_directory(path,filename)


if __name__ == "__main__":
    app.run(debug=True)
