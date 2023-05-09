from flask import Flask, render_template, redirect, url_for,request
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm 
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length
from flask_sqlalchemy  import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import numpy as np
import pickle

db = SQLAlchemy()
app = Flask(__name__)
app.config['SECRET_KEY'] = "SECRET_KEY"
app.config["SQLALCHEMY_DATABASE_URI"] = 'sqlite:///database.db'

app.app_context().push()
db.init_app(app)
Bootstrap(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
model = pickle.load(open('ml_Model.pickle','rb'))

class User(db.Model,UserMixin):
    id = db.Column(db.Integer,primary_key = True)
    username = db.Column(db.String(15),unique = True)
    email = db.Column(db.String(50),unique = True)
    password = db.Column(db.String(80),unique = True)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class LoginForm(FlaskForm):
    username = StringField('username',validators=[InputRequired(),Length(min=4)])
    password = PasswordField('password',validators=[InputRequired(),Length(min=4,max=80)])


class RegisterForm(FlaskForm):
    username = StringField('username',validators=[InputRequired(),Length(min=4)])
    email = StringField('email',validators=[InputRequired(),Email(message="Invalid email"),Length(max=50)])
    password = PasswordField('password',validators=[InputRequired(),Length(min=4,max=80)])


@app.route('/')
def home():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user)
                return render_template('form.html', result="")
        return '<h1>Invalid username or password</h1>'
    return render_template('login.html', form=form)


@app.route('/contact')
def contact():
    return render_template('contact.html')


@app.route('/blogs')
def blogs():
    return render_template('blogs.html')



@app.route('/predict',methods=["GET","POST"])
def predict():
    int_features = [int(x) for x in request.form.values()]
    final = [np.array(int_features)]
    for x in final:
        print(x)
    prediction = model.predict(final)
    output = prediction
    if output == 1:
        return render_template('result.html')
    else:
        return render_template('form.html',result="You are in a good mental health")

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user)
                return render_template('form.html', result="")
        return '<h1>Invalid username or password</h1>'
    return render_template('login.html', form=form)

@app.route('/signup',methods=['GET','POST'])
def signup():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return render_template('form.html', result="")
    return render_template("signup.html",form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    return render_template("dashboard.html")


if __name__ == "__main__":
    app.run()