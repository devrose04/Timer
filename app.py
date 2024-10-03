from flask import Flask, render_template, request, redirect, url_for, flash,jsonify
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import os
import firebase_admin
from firebase_admin import credentials, firestore
from password_reset import handle_password_reset_request,reset_codes

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)

# Initialize Firebase Admin SDK
cred = credentials.Certificate("accountkey.json")  # Replace with your Firebase service account key
firebase_admin.initialize_app(cred)
db = firestore.client()

login_manager = LoginManager(app)
login_manager.login_view = 'login'

# User model (stored in Firestore)
class User(UserMixin):
    def __init__(self, id, username, password_hash, role='user'):
        self.id = id
        self.username = username
        self.password_hash = password_hash
        self.role = role

# Timer model (stored in Firestore)
class Timer:
    def __init__(self, id, name, sets, high_intensity, high_intensity_color,
                 low_intensity, low_intensity_color, warmup,warmup_color,cooldown_color, cooldown, user_id, intervals=None, custom=False):
        self.id = id
        self.name = name
        self.sets = sets
        self.high_intensity = high_intensity
        self.high_intensity_color = high_intensity_color
        self.low_intensity = low_intensity
        self.low_intensity_color = low_intensity_color
        self.warmup = warmup
        self.cooldown = cooldown
        self.warmup_color = warmup_color
        self.cooldown_color = cooldown_color
        self.user_id = user_id
        self.intervals = intervals if intervals is not None else []  # Default to an empty list if None
        self.custom = custom

class CustomTimer:
    def __init__(self, name, intervals):
        self.name = name
        self.intervals = intervals


@login_manager.user_loader
def load_user(user_id):
    user_ref = db.collection('users').document(user_id)
    user_doc = user_ref.get()
    if user_doc.exists:
        user_data = user_doc.to_dict()
        return User(user_doc.id, user_data['username'], user_data['password_hash'], user_data['role'])
    return None

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            flash('You do not have permission to access this page.')
            return redirect(url_for('dashboard'))  # Redirect to the dashboard
        return f(*args, **kwargs)
    return decorated_function

@app.route('/reset_page', methods=['GET'])
def reset_page():
    return render_template("reset_password.html")

@app.route('/reset_password', methods=['POST'])
def reset_password():
    email = request.json.get('email')
    if email:
        handle_password_reset_request(email)
        return jsonify({"success": True, "message": "Reset code sent to your email."}), 200
    return jsonify({"success": False, "message": "Email is required."}), 400


@app.route('/change_password', methods=['POST'])
def change_password():
    email = request.json.get('email')
    reset_code = request.json.get('resetCode')
    new_password = request.json.get('newPassword')

    # Validate input
    if not email or not reset_code or not new_password:
        return jsonify({"success": False, "message": "Email, reset code, and new password are required."}), 400

    # Check if the reset code is valid
    print(reset_codes)
    if str(reset_codes[email]) != str(reset_code):
        return jsonify({"success": False, "message": "Invalid reset code."}), 400

    try:
        # Fetch the user by email
        user_ref = db.collection('users').where('username', '==', email).limit(1).get()
        
        if user_ref:
            user_doc = user_ref[0]
            user_id = user_doc.id
            
            # Hash the new password
            new_password_hash = generate_password_hash(new_password)
            # Update the user's password in Firestore
            db.collection('users').document(user_id).update({
                'password_hash': new_password_hash
            })
            
            # Remove the used reset code
            del reset_codes[email]

            return jsonify({"success": True, "message": "Password reset successful."}), 200

        return jsonify({"success": False, "message": "User not found."}), 404

    except Exception as e:
        print(f"Error during password reset: {e}")
        return jsonify({"success": False, "message": "Password reset succesfull"}), 500



@app.route('/confirm_reset', methods=['POST'])
def confirm_reset():
    email = request.json.get('email')
    reset_code = request.json.get('code')
    new_password = request.json.get('new_password')

    # Validate input
    if not email or not reset_code or not new_password:
        return jsonify({"success": False, "message": "Email, reset code, and new password are required"}), 400

    # Check if the reset code is valid
    if email not in reset_codes or reset_codes[email] != reset_code:
        return jsonify({"success": False, "message": "Invalid reset code"}), 400

    try:
        # Fetch the user by email and update the password
        user_ref = db.collection('users').where('email', '==', email).limit(1).get()
        
        if user_ref:
            user_doc = user_ref[0]
            user_id = user_doc.id
            
            # Update the user's password (hash the new password)
            new_password_hash = generate_password_hash(new_password)
            db.collection('users').document(user_id).update({
                'password_hash': new_password_hash
            })
            
            # Remove the used reset code
            del reset_codes[email]

            return jsonify({"success": True, "message": "Password reset successful"}), 200

        return jsonify({"success": False, "message": "User not found"}), 404

    except Exception as e:
        print(f"Error during password reset: {e}")
        return jsonify({"success": False, "message": "Failed to reset password"})




@app.route('/')
def home():
    if current_user.is_authenticated:
        return redirect(url_for('view_timers'))
    return render_template('login.html')  # This will show login/signup options for unauthenticated users

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Fetch the user document from Firestore
        user_ref = db.collection('users').document(username)
        user_data = user_ref.get()

        # Check if the user exists
        if user_data.exists:
            user_dict = user_data.to_dict()
            # Verify the password
            if check_password_hash(user_dict['password_hash'], password):
                user = User(user_data.id, user_dict['username'], user_dict['password_hash'], user_dict['role'])
                login_user(user)
                return redirect(url_for('view_timers'))  # Redirect to the dashboard after login
        
        flash('Invalid username or password')
    return render_template('login.html')


@app.route('/delete_user/<user_id>', methods=['POST'])
@login_required
@admin_required
def delete_user(user_id):
    # Prevent self-deletion
    if current_user.id == user_id:
        flash('You cannot delete yourself!', 'error')
        return redirect(url_for('admin_users'))
    
    user_ref = db.collection('users').document(user_id)
    user_doc = user_ref.get()
    
    if user_doc.exists:
        user_ref.delete()
        flash('User deleted successfully!', 'success')
    else:
        flash('User not found!', 'error')
    
    return redirect(url_for('admin_users'))

@app.route('/secret', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # Check if the user already exists in Firestore
        user_ref = db.collection('users').document(username)
        existing_user = user_ref.get()

        if existing_user.exists:
            flash('Username already exists')
        else:
            # Hash the password and save the user to Firestore
            password_hash = generate_password_hash(password, method='pbkdf2:sha256')
            user_ref.set({
                'username': username,
                'password_hash': password_hash,
                'role': 'user'  # Set default role to user
            })

            # Create a new User object and log in the user
            new_user = User(username, username, password_hash, 'user')
            login_user(new_user)

            return redirect(url_for('view_timers'))  # Redirect to the dashboard after signup

    return render_template('signup.html')

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# Timer Dashboard (after login)
@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('view_timers.html')

@app.route('/create_timer', methods=['GET', 'POST'])
@login_required
@admin_required  # Only admins can create timers
def create_timer():
    if request.method == 'POST':
        # Add the new timer to Firestore
        new_timer_ref = db.collection('timers').add({
            'name': request.form.get('name'),
            'sets': int(request.form.get('sets')),
            'high_intensity': int(request.form.get('high_intensity')),
            'high_intensity_color': request.form.get('high_intensity_color'),
            'low_intensity': int(request.form.get('low_intensity')),
            'low_intensity_color': request.form.get('low_intensity_color'),
            'warmup': int(request.form.get('warmup')),
            'warmup_color': request.form.get('warmup_color'),
            'cooldown': int(request.form.get('cooldown')),
            'cooldown_color': request.form.get('cooldown_color'),
            'user_id': current_user.id,
            'custom': False  # Default to False for standard timers
        })
        flash('Timer created successfully!')
        return redirect(url_for('view_timers'))  # Redirect to view all timers after creation
    return render_template('create_timer.html')

@app.route('/create_custom_timer', methods=['POST'])
def create_custom_timer():
    name = request.form.get('name')
    
    # Collect intervals
    interval_names = request.form.getlist('interval_name[]')
    interval_seconds = request.form.getlist('interval_seconds[]')
    interval_colors = request.form.getlist('interval_color[]')

    intervals = []
    for i in range(len(interval_names)):
        interval = {
            'name': interval_names[i],
            'duration': int(interval_seconds[i]),
            'color': interval_colors[i]
        }
        intervals.append(interval)

    # Prepare the custom timer data
    custom_timer_data = {
        'custom': True,
        'name': name,
        'user_id': current_user.id,  # Save the current user's ID
        'intervals': intervals
    }

    # Save the custom timer to the database (Firebase)
    timers_ref = db.collection('timers')
    timers_ref.add(custom_timer_data)

    return redirect(url_for('view_timers'))




@app.route('/view_timers')
@login_required
def view_timers():
    timers_ref = db.collection('timers').stream()

    timers = []
    custom_timers = []
    stopwatch_timers = []

    for timer_doc in timers_ref:
        timer_data = timer_doc.to_dict()
        if timer_data.get('custom', False):
            custom_timer_data = {
                'id': timer_doc.id,
                'name': timer_data.get('name', 'Unknown'),
                'intervals': timer_data.get('intervals', []),
            }
            custom_timers.append(custom_timer_data)
        elif 'warmup_duration' in timer_data:  # Check if it's a stopwatch timer
            stopwatch_timer_data = {
                'id': timer_doc.id,
                'name': timer_data.get('name', 'Unknown'),
                'warmup_duration': timer_data.get('warmup_duration', 0),
                'high_intensity_duration': timer_data.get('high_intensity_duration', 0),
                'cooldown_duration': timer_data.get('cooldown_duration', 0),
                'high_intensity_color': timer_data.get('high_intensity_color', '#ff0000'),
                'low_intensity_color': timer_data.get('low_intensity_color', '#00ff00'),
                'warmup_color': timer_data.get('warmup_color', '#ffff00'),
                'cooldown_color': timer_data.get('cooldown_color', '#0000ff'),
            }
            stopwatch_timers.append(stopwatch_timer_data)
        else:
            normal_timer_data = {
                'id': timer_doc.id,
                'name': timer_data.get('name', 'Unknown'),
                'sets': timer_data.get('sets', 0),
                'high_intensity': timer_data.get('high_intensity', 0),
                'high_intensity_color': timer_data.get('high_intensity_color', '#ff0000'),
                'low_intensity': timer_data.get('low_intensity', 0),
                'low_intensity_color': timer_data.get('low_intensity_color', '#00ff00'),
                'warmup': timer_data.get('warmup', 0),
                'cooldown': timer_data.get('cooldown', 0),
            }
            timers.append(normal_timer_data)

    return render_template('view_timers.html', timers=timers, custom_timers=custom_timers, stopwatch_timers=stopwatch_timers)


@app.route('/start_stopwatch/<timer_id>')
@login_required
def start_stopwatch(timer_id):
    timer_ref = db.collection('timers').document(timer_id)
    timer_doc = timer_ref.get()
    if timer_doc.exists:
        timer_data = timer_doc.to_dict()
        return render_template('start_stopwatch.html',
            timer_name=timer_data['name'],
            warmup_duration=timer_data['warmup_duration'],
            high_intensity_duration=timer_data['high_intensity_duration'],
            cooldown_duration=timer_data['cooldown_duration'],
            warmup_color=timer_data['warmup_color'],
            high_intensity_color=timer_data['high_intensity_color'],
            cooldown_color=timer_data['cooldown_color'])
    flash('Stopwatch timer not found!')
    return redirect(url_for('view_timers'))

@app.route('/edit_stopwatch/<timer_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_stopwatch(timer_id):
    timer_ref = db.collection('timers').document(timer_id)
    timer_doc = timer_ref.get()
    if not timer_doc.exists:
        flash('Stopwatch timer not found!')
        return redirect(url_for('view_timers'))
    
    timer_data = timer_doc.to_dict()
    
    if request.method == 'POST':
        timer_ref.update({
            'name': request.form.get('name'),
            'warmup_duration': int(request.form.get('warmup_duration')),
            'high_intensity_duration': int(request.form.get('high_intensity_duration')),
            'cooldown_duration': int(request.form.get('cooldown_duration')),
            'high_intensity_color': request.form.get('high_intensity_color'),
            'warmup_color': request.form.get('warmup_color'),
            'cooldown_color': request.form.get('cooldown_color'),
        })
        flash('Stopwatch timer updated successfully!')
        return redirect(url_for('view_timers'))
    
    return render_template('edit_stopwatch.html', timer=timer_data)







@app.route('/start_timer/<timer_id>')
@login_required
def start_timer(timer_id):
    timer_ref = db.collection('timers').document(timer_id)
    timer_doc = timer_ref.get()
    if timer_doc.exists:
        timer = Timer(timer_doc.id, **timer_doc.to_dict())
        return render_template('start_timer.html',
            timer_name=timer.name,
            warmup_duration=timer.warmup,
            high_duration=timer.high_intensity,
            low_duration=timer.low_intensity,
            cooldown_duration=timer.cooldown,
            sets=timer.sets,
            warmup_color=timer.warmup_color,
            high_color=timer.high_intensity_color,
            low_color=timer.low_intensity_color,
            cooldown_color=timer.cooldown_color,
            intervals=timer.intervals if timer.custom else None)
    flash('Timer not found!')
    return redirect(url_for('view_timers'))

@app.route('/start_custom_timer/<timer_id>')
@login_required
def start_custom_timer(timer_id):
    timer_ref = db.collection('timers').document(timer_id)
    timer_doc = timer_ref.get()

    if timer_doc.exists:
        timer_data = timer_doc.to_dict()

        # Check if the timer is custom or standard
        if timer_data.get('custom'):
            # Handle custom timer initialization
            intervals = timer_data.get('intervals', [])
            return render_template('custom_timer_view.html',
                                   timer_name=timer_data['name'],
                                   intervals=intervals)
        else:
            # Handle standard timer initialization
            timer = Timer(timer_doc.id,
                          sets=timer_data['sets'],
                          high_intensity=timer_data['high_intensity'],
                          high_intensity_color=timer_data['high_intensity_color'],
                          low_intensity=timer_data['low_intensity'],
                          low_intensity_color=timer_data['low_intensity_color'],
                          warmup=timer_data['warmup'],
                          cooldown=timer_data['cooldown'])
            return render_template('start_timer.html',
                                   timer_name=timer.name,
                                   warmup_duration=timer.warmup,
                                   high_duration=timer.high_intensity,
                                   low_duration=timer.low_intensity,
                                   cooldown_duration=timer.cooldown,
                                   sets=timer.sets,
                                   warmup_color=timer.low_intensity_color,
                                   high_color=timer.high_intensity_color,
                                   low_color=timer.low_intensity_color,
                                   intervals=None)  # No intervals for standard timer

    flash('Timer not found!')
    return redirect(url_for('view_timers'))




@app.route('/edit_timer/<timer_id>', methods=['GET', 'POST'])
@login_required
@admin_required  # Only admins can edit timers
def edit_timer(timer_id):
    timer_ref = db.collection('timers').document(timer_id)
    timer_doc = timer_ref.get()
    if not timer_doc.exists:
        flash('Timer not found!')
        return redirect(url_for('view_timers'))
    
    # Create a dictionary with default values for new fields
    timer_data = {
        'warmup_color': '#FFFFFF',  # Default to white
        'cooldown_color': '#FFFFFF',  # Default to white
        **timer_doc.to_dict()  # Overwrite with existing data
    }
    
    timer = Timer(timer_doc.id, **timer_data)
    
    if request.method == 'POST':
        timer_ref.update({
            'name': request.form.get('name'),
            'sets': int(request.form.get('sets')),
            'high_intensity': int(request.form.get('high_intensity')),
            'high_intensity_color': request.form.get('high_intensity_color'),
            'low_intensity': int(request.form.get('low_intensity')),
            'low_intensity_color': request.form.get('low_intensity_color'),
            'warmup': int(request.form.get('warmup')),
            'warmup_color': request.form.get('warmup_color'),
            'cooldown': int(request.form.get('cooldown')),
            'cooldown_color': request.form.get('cooldown_color'),
        })
        flash('Timer updated successfully!')
        return redirect(url_for('view_timers'))
    
    return render_template('edit_timer.html', timer=timer)


@app.route('/edit_custom_timer/<timer_id>', methods=['GET', 'POST'])
def edit_custom_timer(timer_id):
    # Fetch timer details from Firestore
    timer_ref = db.collection('timers').document(timer_id)
    timer_doc = timer_ref.get()

    if not timer_doc.exists:
        flash('Timer not found!', 'error')
        return redirect(url_for('view_timers'))

    timer = timer_doc.to_dict()

    if request.method == 'POST':
        # Get form data
        name = request.form.get('name')
        print(name)
        interval_names = request.form.getlist('interval_name[]')
        interval_durations = request.form.getlist('interval_seconds[]')
        interval_colors = request.form.getlist('interval_color[]')

        # Build the intervals list
        intervals = []
        for intervalname, duration, color in zip(interval_names, interval_durations, interval_colors):
            interval = {
                'name': intervalname,
                'duration': int(duration),
                'color': color
            }
            intervals.append(interval)
        print(name)
        # Update timer details in Firestore
        updated_timer = {
            'name': name,
            'intervals': intervals,
            'custom': True,  # Ensure this timer is marked as custom
            'user_id': timer['user_id']  # Keep the same user_id
        }
        print(updated_timer)

        timer_ref.update(updated_timer)

        flash('Timer updated successfully!', 'success')
        return redirect(url_for('view_timers'))

    return render_template('edit_custom_timer.html', timer=timer)


@app.route('/delete_timer/<timer_id>', methods=['POST'])
@login_required
@admin_required  # Only admins can delete timers
def delete_timer(timer_id):
    timer_ref = db.collection('timers').document(timer_id)
    timer_ref.delete()
    flash('Timer deleted successfully!')
    return redirect(url_for('view_timers'))

@app.route('/admin/users')
@login_required
@admin_required
def admin_users():
    users_ref = db.collection('users').stream()
    users = [User(user.id, **user.to_dict()) for user in users_ref]
    return render_template('admin_users.html', users=users)

@app.route('/admin/promote/<user_id>')
@login_required
@admin_required
def promote_user(user_id):
    user_ref = db.collection('users').document(user_id)
    user_ref.update({'role': 'admin'})
    flash('User promoted to admin successfully!')
    return redirect(url_for('admin_users'))

@app.route('/admin/demote/<user_id>')
@login_required
@admin_required
def demote_user(user_id):
    user_ref = db.collection('users').document(user_id)
    user_ref.update({'role': 'user'})
    flash('User demoted to user successfully!')
    return redirect(url_for('admin_users'))

@app.route('/stopwatch', methods=['GET', 'POST'])
def stopwatch():
    if request.method == 'POST':
        # Get data from the form
        name = request.form['name']
        warmup_duration = request.form['warmup']
        high_intensity_duration = request.form['high_intensity']
        cooldown_duration = request.form['cooldown']
        high_intensity_color = request.form['high_intensity_color']
        warmup_color = request.form['warmup_color']
        cooldown_color = request.form['cooldown_color']

        # Create a new stopwatch timer in Firebase
        timers_ref = db.collection('timers')
        timers_ref.add({
            'name': name,
            'warmup_duration': warmup_duration,
            'high_intensity_duration': high_intensity_duration,
            'cooldown_duration': cooldown_duration,
            'high_intensity_color': high_intensity_color,
            'warmup_color': warmup_color,
            'cooldown_color': cooldown_color
        })

        return redirect(url_for('home'))

    return render_template('stopwatch.html')  

@app.route('/custom_timer')
def custom_timer():
    return render_template('create_custom_timer.html')


if __name__ == '__main__':
    app.run(debug=True)
