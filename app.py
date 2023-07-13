from flask import Flask, render_template, url_for, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt



app = Flask(__name__)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
# for connecting the database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
# for creating a session cookie, we need a secret
app.config['SECRET_KEY'] = 'hi'


# for logging in user
login_manager = LoginManager() #flask login
login_manager.init_app(app)
login_manager.login_view = 'login'
# used to load/reload objects from the stored session
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))



# creating user db
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    # hashed password is longer..
    password  = db.Column(db.String(80), nullable=False)
# after writing this, go to terminal, import db variable, then give db.create_all() to create all tables.

# user validation when he inputs username and passwd(register page)
class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4,max=20)], render_kw={'placeholder':'Username'})
    password = PasswordField(validators=[InputRequired(), Length(min=4,max=20)], render_kw={'placeholder':'Password'})
    submit = SubmitField("Register")

    # checking for existing user
    def validate_username(self, username):
        existing_username = User.query.filter_by(username=username.data).first()
        if existing_username:
            raise ValidationError("Username already exists")

# for login page
class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4,max=20)], render_kw={'placeholder':'Username'})
    password = PasswordField(validators=[InputRequired(), Length(min=4,max=20)], render_kw={'placeholder':'Password'})
    submit = SubmitField("Login")



@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login', methods = ['GET','POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user=User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('dashboard'))



    return render_template('login.html', form=form)

@app.route('/dashboard', methods=['GET','POST'])
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/logout', methods=['GET','POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/register', methods = ['GET','POST'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('register.html', form=form)


if __name__ == '__main__':
    app.run(debug=True)