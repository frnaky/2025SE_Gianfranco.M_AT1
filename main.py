from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import bcrypt
from datetime import datetime
import os
import re

basedir = os.path.abspath(os.path.dirname(__file__))
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
#db
# app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///databaseFiles/database.db' #keep eye on this, might need to alter to fit database.db file location
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{os.path.join(basedir, "databaseFiles", "database.db")}' #testing weird solution on stackoverflow, might change after
db = SQLAlchemy(app)


login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    user_id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False)

    def set_password(self, password):
    #hash
        self.password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    def check_password(self, password):
    #veriby password
        return bcrypt.checkpw(password.encode('utf-8'), self.password_hash.encode('utf-8'))
    
    def get_id(self):
        return str(self.user_id)

class Log(db.Model):
    __tablename__ = 'logs'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    project_name = db.Column(db.String(100), nullable=False)
    code_language = db.Column(db.String(50), nullable=False)
    repository = db.Column(db.String(100), nullable=False)
    log_content = db.Column(db.Text, nullable=False)
    start_date = db.Column(db.DateTime, nullable=False)
    date = db.Column(db.DateTime, nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    return render_template('home.html')	

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        if User.query.filter_by(username=username).first() or User.query.filter_by(email=email).first():
            flash('User Already Exists.', 'danger')
            return redirect(url_for('signup'))

        #creation
        new_user = User(username=username, email=email, created_at=datetime.utcnow())
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()

        flash('Account Created, Proceed to Log-In.', 'success')
        return redirect(url_for('login'))

    return render_template('signup.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$' #regeualr expression for email valid
        if not re.match(email_regex, email):
            flash('Please enter a valid email.', 'danger') 
            return redirect(url_for('login'))

        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            login_user(user)
            flash('Logged-In.', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid Log-In, Please Retry.', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged-Out.', 'success')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', user=current_user)

# check if userexist... test later within the signup function
#        if User.query.filter_by(username=username).first() or User.query.filter_by(email=email).first():
#            flash('Username or email already exists', 'error')
#            return redirect(url_for('signup'))

@app.route('/create_log', methods=['GET', 'POST'])
@login_required
def create_log():
    if request.method == 'POST':
        project_name = request.form['project_name']
        code_language = request.form['code_language']
        repository = request.form['repository']
        log_content = request.form['log_content']
        start_date = datetime.strptime(request.form['start_date'], '%Y-%m-%dT%H:%M') #not sure if timeformat work

        new_log = Log(
            user_id=current_user.id,
            project_name=project_name,
            code_language=code_language,
            repository=repository,
            log_content=log_content,
            start_date=start_date,
            date=datetime.utcnow()
        )
        db.session.add(new_log)
        db.session.commit()

        flash('Log Created!', 'success')
        return redirect(url_for('dashboard'))

    return render_template('create_log.html')

@app.route('/search_logs', methods=['GET'])
@login_required
def search_logs():
    query = request.args.get('query', '')
    logs = Log.query.filter(
        (Log.project_name.contains(query)) |
        (Log.code_language.contains(query)) |
        (Log.repository.contains(query)),
        Log.user_id == current_user.id
    ).all()
    return render_template('search_logs.html', logs=logs, query=query)

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
