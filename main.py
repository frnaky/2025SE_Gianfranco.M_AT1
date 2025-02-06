from flask import Flask, render_template, redirect, url_for, request, flash, send_file, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from datetime import datetime
import os, re, bcrypt
from io import StringIO, BytesIO
import csv
from flask import current_app as app
from itsdangerous import URLSafeTimedSerializer
from flask_mail import Mail, Message
from dotenv import load_dotenv

basedir = os.path.abspath(os.path.dirname(__file__))
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'default_secret_key')

# DATABASE CONFIGURATION
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{os.path.join(basedir, "databaseFiles", "database.db")}' #testing weird solution on stackoverflow, might change after
db = SQLAlchemy(app)

# FLASK MAIL CONFIGURATION
load_dotenv()
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = 'no-reply@logvault.com'
mail = Mail(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    user_id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False)
    team_id = db.Column(db.Integer, db.ForeignKey('teams.team_id'), nullable=True)

    def set_password(self, password):
        # BCRYPT HASHING + SALT
        self.password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    def check_password(self, password):
        # BCRYPT CHECK
        return bcrypt.checkpw(password.encode('utf-8'), self.password_hash.encode('utf-8'))
    
    def get_id(self):
        return str(self.user_id)

class Log(db.Model):
    __tablename__ = 'logs'
    log_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    username = db.Column(db.String(50), nullable=False, default="N/A")
    project_name = db.Column(db.String(100), nullable=False)
    code_language = db.Column(db.String(50), nullable=False)
    start_date = db.Column(db.DateTime, nullable=False)
    end_date = db.Column(db.DateTime, nullable=False)
    date = db.Column(db.DateTime, nullable=False)
    time_worked = db.Column(db.Float, nullable=False)
    repository = db.Column(db.String(100), nullable=False)
    dev_notes = db.Column(db.Text, nullable=False)
    log_content = db.Column(db.Text, nullable=False)
    team_id = db.Column(db.Integer, db.ForeignKey('teams.team_id'), nullable=False)
    user = db.relationship('User', backref=db.backref('logs', lazy=True))
    team = db.relationship('Team', backref=db.backref('logs', lazy=True))


class Team(db.Model):
    __tablename__ = 'teams'
    team_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password):
        self.password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    def check_password(self, password):
        return bcrypt.checkpw(password.encode('utf-8'), self.password_hash.encode('utf-8'))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# HOME PAGE

@app.route('/')
def index():
    return render_template('home.html')	

# SIGNUP PAGE + FUNCTIONALITY

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        team_name = request.form['team_name']
        team_password = request.form['team_password']

    # REGULAR EXPRESSION FOR USERNAME VALIDATION
        username_regex = r'^[A-Za-z0-9]{1,20}$'

        if not re.match(username_regex, username):
            flash('Username CANNOT have spaces and must not exceed 20 characters!', 'danger')
            return redirect(url_for('signup'))
        
    # REGULAR EXPRESSION FOR PASSWORD VALIDATION
        password_regex = r'^(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{8,}$'
        
        if not re.match(password_regex, password):
            flash('Password has to be atleast 8 characters long, and include 1 number, 1 special character, and 1 capital letter.', 'danger')
            return redirect(url_for('signup'))

        if User.query.filter_by(username=username).first() or User.query.filter_by(email=email).first():
            flash('User Already Exists.', 'danger')
            return redirect(url_for('signup'))
        
    #TEAM functionality    
        team = Team.query.filter_by(name=team_name).first()
        if team:
            if not team.check_password(team_password):
                flash('Incorrect Team Password. You might need to create a new team, or retry credentials.', 'danger')
                return redirect(url_for('signup'))
        else:
            #TEAM CREATION    
            team = Team(name=team_name)
            team.set_password(team_password)
            db.session.add(team)
            db.session.commit()

        new_user = User(username=username, email=email, created_at=datetime.utcnow(), team_id=team.team_id)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()

        flash('Account Created, Proceed to Log-In.', 'success')
        return redirect(url_for('login'))

    return render_template('signup.html')

#LOGIN PAGE + FUNCTIONALITY

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        # REGULAR EXPRESSION FOR EMAIL VALIDATION
        email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$' 
        if not re.match(email_regex, email):
            flash('Please Enter a Valid Email', 'danger') 
            return redirect(url_for('login'))

        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            # REAUTHENTICATION EVERY 3600 SECONDS/1 HOUR
            login_user(user, duration=3600)
            flash('Logged-In.', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid Log-In, Please Retry.', 'danger')
    return render_template('login.html')

# LOGOUT FUNCTIONALITY

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged-Out.', 'success')
    return redirect(url_for('index'))

# DASHBOARD

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', user=current_user)

# CREATE LOGS PAGE + FUNCTIONALITY

@app.route('/create_log', methods=['GET', 'POST'])
@login_required
def create_log():
    if request.method == 'POST':
        project_name = request.form['project_name']
        code_language = request.form['code_language']

        if code_language == "other":
            code_language = request.form['custom_language'].strip()

        start_date_str = request.form['start_date']
        end_date_str = request.form['end_date']


    # ENSURE START AND DART ARE FILLED
        if not start_date_str or not end_date_str:
            flash("Start Date and End Date needed.", "danger")
            return redirect(url_for('create_log'))
        
        # CONVERSION OF TIME TO DATETIME OBJECT
        start_date = datetime.strptime(start_date_str, '%Y-%m-%dT%H:%M')
        end_date = datetime.strptime(end_date_str, '%Y-%m-%dT%H:%M')

        repository = request.form['repository']
        dev_notes = request.form['dev_notes']
        log_content = request.form['log_content']

    # ROUNDING SYSTEM FOR CLIENT BILLING PURPOSES
        delta = end_date - start_date
        minutes_worked = delta.total_seconds() / 60
        rounded_minutes = (round(minutes_worked / 15)) * 15 
        time_worked = rounded_minutes / 60
        
        new_log = Log(
            user_id=current_user.user_id,
            username=current_user.username,
            project_name=project_name,
            code_language=code_language,
            start_date=start_date,
            end_date=end_date,
            date=datetime.utcnow(),
            time_worked=time_worked,
            repository=repository,
            dev_notes=dev_notes,
            log_content=log_content,
            team_id=current_user.team_id 
        )
        db.session.add(new_log)
        db.session.commit()

        flash('Log Created!', 'success')
        return redirect(url_for('dashboard'))

    return render_template('create_log.html')

# VIEW LOGS PAGE + FUNCTIONALITY

@app.route('/search_logs', methods=['GET'])
@login_required
def search_logs():
    general_query = request.args.get('query', '')
    code_language = request.args.get('code_language', '')
    username = request.args.get('username', '')
    project_name = request.args.get('project_name', '')
    repository = request.args.get('repository', '')
    date_from = request.args.get('date_from', '')
    date_to = request.args.get('date_to', '')

    query = Log.query.filter(Log.team_id == current_user.team_id)

    if general_query:
        query = query.filter(
            (Log.project_name.contains(general_query)) |
            (Log.code_language.contains(general_query)) |
            (Log.repository.contains(general_query)) |
            (Log.log_content.contains(general_query))
        )
    if code_language:
        query = query.filter(Log.code_language == code_language)
    if username:
        query = query.filter(Log.username == username)
    if project_name:
        query = query.filter(Log.project_name == project_name)
    if repository:
        query = query.filter(Log.repository == repository)
    if date_from:
        query = query.filter(Log.start_date >= datetime.strptime(date_from, '%Y-%m-%d'))
    if date_to:
        query = query.filter(Log.end_date <= datetime.strptime(date_to + ' 23:59:59', '%Y-%m-%d %H:%M:%S'))

    unique_languages = db.session.query(Log.code_language).distinct().all()
    unique_usernames = db.session.query(Log.username).distinct().all()
    unique_projects = db.session.query(Log.project_name).distinct().all()
    unique_repositories = db.session.query(Log.repository).distinct().all()

    logs = query.all()

    return render_template('search_logs.html',
                         logs=logs,
                         query=general_query,
                         unique_languages=unique_languages,
                         unique_usernames=unique_usernames,
                         unique_projects=unique_projects,
                         unique_repositories=unique_repositories)

# PRIVACY POLICY PAGE

@app.route('/privacy')
def privacy():
    return render_template('privacy.html')

# DOWNLAODING DATA FUNCTIONALITY

@app.route('/download_data', methods=['GET'])
@login_required
def download_data():
    if not current_user.is_authenticated:
        flash("You Have to be Logged-In to do this.", "danger")
        return redirect(url_for('login'))
    
    user_logs = Log.query.filter_by(user_id=current_user.user_id).all()
    if not user_logs:
        return jsonify({"error": "No Data Found."}), 404

    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(['Project Name', 'Code Language', 'Start Date', 'End Date', 'Time Worked', 'Repository', 'Developer Notes', 'Log Content'])

    for log in user_logs:
        writer.writerow([
            log.project_name,
            log.code_language,
            log.start_date,
            log.end_date,
            log.time_worked,
            log.repository,
            log.dev_notes,
            log.log_content
        ])

    output.seek(0)
    byte_output = BytesIO(output.getvalue().encode('utf-8'))
    return send_file(byte_output, as_attachment=True, download_name="user_logs.csv", mimetype="text/csv")

# DELETE ACCOUNT FUNCTIONALITY

@app.route('/delete_account', methods=['POST'])
@login_required
def delete_account():
    if not current_user.is_authenticated:
        flash("You must be logged in to an account to delete an account. Muppet." "danger")
        return redirect(url_for('login'))

    Log.query.filter_by(user_id=current_user.user_id).delete()
    db.session.delete(current_user)
    db.session.commit()
    logout_user()

    flash("Account Deleted.", "success")
    return redirect(url_for('dashboard'))

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        if user:
            s = URLSafeTimedSerializer(app.config['SECRET_KEY'])
            token = s.dumps(email, salt='password-reset')

            reset_link = url_for('reset_password', token=token, _external=True)

            msg = Message('Password Reset Request',
                          sender=app.config['MAIL_DEFAULT_SENDER'],
                          recipients=[email])
            msg.body = (
                f"Hello LogVault User!,\n\n"
                "You have FORGOTTTEN your password.. "
                "If you initiated this request, please click the link below to reset your password:\n\n"
                f"{reset_link}\n\n"
                "If you DID NOT request a password reset, please ignore this email.\n\n"
                "Cheers,\n"
                "Gianfranco from LogVault"
            )
            mail.send(msg)

            flash('A password reset link has been sent to your email. Check your Spam.', 'info')
            return redirect(url_for('login'))
        else:
            flash('Email Not Found!', 'danger')
            return redirect(url_for('forgot_password'))

    return render_template('forgot_password.html')

# RESET PASSWORD FUNCTIONALITY

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        s = URLSafeTimedSerializer(app.config['SECRET_KEY'])
        email = s.loads(token, salt='password-reset', max_age=3600)  # token expires in 1 hour
        user = User.query.filter_by(email=email).first()
        
        if request.method == 'POST':
            new_password = request.form['password']
            user.set_password(new_password)
            db.session.commit()
            flash('Your password has been reset successfully!', 'success')
            return redirect(url_for('login'))

        return render_template('reset_password.html', token=token)
    
    except SignatureExpired:
        flash('The reset link has expired.', 'danger')
        return redirect(url_for('forgot_password'))

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
