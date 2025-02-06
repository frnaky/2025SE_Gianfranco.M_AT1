from flask import Flask, render_template, redirect, url_for, request, flash, send_file, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import bcrypt
from datetime import datetime
import os
import re
from io import StringIO, BytesIO
import csv

basedir = os.path.abspath(os.path.dirname(__file__))
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
#database file link
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
    #hashing using bcrypt
        self.password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    def check_password(self, password):
    #veriying password forlogin
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

    #only can have letters and numbers, no spaces max 10 characters
        username_regex = r'^[A-Za-z0-9]{1,20}$'

        if not re.match(username_regex, username):
            flash('Username CANNOT have spaces and must not exceed 20 characters!', 'danger')
            return redirect(url_for('signup'))
        
    #password regular expression validation
        password_regex = r'^(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{8,}$'
        
        if not re.match(password_regex, password):
            flash('Password has to be atleast 8 characters long, and include 1 number, 1 special character, and 1 capital letter.', 'danger')
            return redirect(url_for('signup'))

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
            flash('Please Enter a Valid Email', 'danger') 
            return redirect(url_for('login'))

        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            login_user(user, duration=3600) #reauthentication every hour, and after closing tab
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


#ensure start and end date are not empty   
        if not start_date_str or not end_date_str:
            flash("Start Date and End Date needed.", "danger")
            return redirect(url_for('create_log'))

        #conversion
        start_date = datetime.strptime(start_date_str, '%Y-%m-%dT%H:%M')
        end_date = datetime.strptime(end_date_str, '%Y-%m-%dT%H:%M')

        repository = request.form['repository']
        dev_notes = request.form['dev_notes']
        log_content = request.form['log_content']

#calculate rounding up 15 mins for client billing purposes
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
            log_content=log_content
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
        Log.user_id == current_user.user_id
    ).all()
    return render_template('search_logs.html', logs=logs, query=query)

@app.route('/privacy')
def privacy():
    return render_template('privacy.html')

#pirvacy policy page
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


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
