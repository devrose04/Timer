from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///hiit_timer.db'
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)

class Timer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    sets = db.Column(db.Integer, nullable=False)
    high_intensity = db.Column(db.Integer, nullable=False)
    high_intensity_color = db.Column(db.String(7), nullable=False)
    low_intensity = db.Column(db.Integer, nullable=False)
    low_intensity_color = db.Column(db.String(7), nullable=False)
    warmup = db.Column(db.Integer, nullable=False)
    cooldown = db.Column(db.Integer, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for('home'))
        flash('Invalid username or password')
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists')
        else:
            new_user = User(username=username, password_hash=generate_password_hash(password))
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            return redirect(url_for('home'))
    return render_template('signup.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/create_timer', methods=['GET', 'POST'])
@login_required
def create_timer():
    if request.method == 'POST':
        new_timer = Timer(
            name=request.form.get('name'),
            sets=int(request.form.get('sets')),
            high_intensity=int(request.form.get('high_intensity')),
            high_intensity_color=request.form.get('high_intensity_color'),
            low_intensity=int(request.form.get('low_intensity')),
            low_intensity_color=request.form.get('low_intensity_color'),
            warmup=int(request.form.get('warmup')),
            cooldown=int(request.form.get('cooldown')),
            user_id=current_user.id
        )
        db.session.add(new_timer)
        db.session.commit()
        flash('Timer created successfully!')
        return redirect(url_for('view_timers'))
    return render_template('create_timer.html')

@app.route('/view_timers')
@login_required
def view_timers():
    timers = Timer.query.filter_by(user_id=current_user.id).all()
    return render_template('view_timers.html', timers=timers)

@app.route('/start_timer/<int:timer_id>')
@login_required
def start_timer(timer_id):
    timer = Timer.query.get_or_404(timer_id)
    if timer.user_id != current_user.id:
        flash('You do not have permission to access this timer.')
        return redirect(url_for('view_timers'))
    
    # Pass the necessary values to the template
    return render_template('start_timer.html',
                           timer_name=timer.name,
                           warmup_duration=timer.warmup,
                           high_duration=timer.high_intensity,
                           low_duration=timer.low_intensity,
                           cooldown_duration=timer.cooldown,
                           sets=timer.sets,
                           warmup_color=timer.low_intensity_color,  # Update colors as needed
                           high_color=timer.high_intensity_color,
                           low_color=timer.low_intensity_color,
                           cooldown_color="#00FF00")  # Default or fixed color


@app.route('/edit_timer/<int:timer_id>', methods=['GET', 'POST'])
@login_required
def edit_timer(timer_id):
    timer = Timer.query.get_or_404(timer_id)
    if timer.user_id != current_user.id:
        flash('You do not have permission to edit this timer.')
        return redirect(url_for('view_timers'))
    
    if request.method == 'POST':
        timer.name = request.form.get('name')
        timer.sets = int(request.form.get('sets'))
        timer.high_intensity = int(request.form.get('high_intensity'))
        timer.high_intensity_color = request.form.get('high_intensity_color')
        timer.low_intensity = int(request.form.get('low_intensity'))
        timer.low_intensity_color = request.form.get('low_intensity_color')
        timer.warmup = int(request.form.get('warmup'))
        timer.cooldown = int(request.form.get('cooldown'))
        
        db.session.commit()
        flash('Timer updated successfully!')
        return redirect(url_for('view_timers'))
    
    return render_template('edit_timer.html', timer=timer)

@app.route('/stopwatch')
def stopwatch():
    return render_template('stopwatch.html')


@app.route('/delete_timer/<int:timer_id>', methods=['POST'])
@login_required
def delete_timer(timer_id):
    timer = Timer.query.get_or_404(timer_id)
    if timer.user_id != current_user.id:
        flash('You do not have permission to delete this timer.')
        return redirect(url_for('view_timers'))
    db.session.delete(timer)
    db.session.commit()
    flash('Timer deleted successfully!')
    return redirect(url_for('view_timers'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)