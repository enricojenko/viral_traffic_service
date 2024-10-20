# app.py
from flask import Flask

app = Flask(__name__)

@app.before_first_request
def before_first_request_func():
    print("This runs before the first request.")

@app.route('/')
def index():
    return "Hello, World!"

if __name__ == '__main__':
    app.run(debug=True)
==========================================================
import os
import logging
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_required, login_user, logout_user, current_user
from flask_migrate import Migrate
from models import db, User, Ad, AdAnalytics
from flask import render_template
from flask_login import current_user, login_required
from models import AdminSettings

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secure_secret_key'  # Replace with a secure key

# Set the database path to the 'instance' folder
basedir = os.path.abspath(os.path.dirname(__file__))
db_path = os.path.join(basedir, 'instance', 'viral_traffic_service.db')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + db_path
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

print("Database Path:", db_path)

# Initialize extensions
db.init_app(app)
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Set up logging
logging.basicConfig(level=logging.DEBUG)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    # Check if the user is logged in
    if current_user.is_authenticated:
        # Show content for logged-in users
        return render_template('index.html', user=current_user, logged_in=True)
    else:
        # Show content for logged-out users
        return render_template('index.html', logged_in=False)


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        promoted_link = request.form.get('promoted_link')

        # Check if email or password is missing
        if not email or not password:
            logging.debug("Signup failed: Missing email or password")
            flash("Invalid input, please try again.", "danger")
            return render_template('signup.html'), 400

        # Log email to debug issue
        logging.debug(f"Checking if email {email} is already in use")

        # Check if the email is already registered
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            logging.debug(f"Signup failed: Email {email} already exists")
            flash("Email already registered. Please log in or use a different email.", "danger")
            return render_template('signup.html'), 400

        # Hash the password
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(email=email, password=hashed_password, promoted_link=promoted_link)

        try:
            db.session.add(new_user)
            db.session.commit()

            # Add the user's promoted link to the ads table
            if promoted_link:
                new_ad = Ad(url=promoted_link)
                db.session.add(new_ad)
                db.session.commit()

            login_user(new_user)
            logging.debug(f"New user created and logged in: {new_user.email}")
            flash("Signup successful!", "success")
            return redirect(url_for('view_ads', ad_id=1))
        except Exception as e:
            logging.error(f"Error in signup: {e}")
            db.session.rollback()
            flash("Signup failed, please try again.", "danger")
            return render_template('signup.html'), 400

    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        # Query the user based on the provided email
        user = User.query.filter_by(email=email).first()

        if user is None:
            logging.debug(f"Login failed: No account found for email {email}")
            flash("Invalid email or password.", "danger")
            return render_template('login.html'), 400

        # Verify the password
        try:
            if bcrypt.check_password_hash(user.password, password):
                login_user(user)
                logging.debug(f"User logged in: {user.email}")
                return redirect(url_for('view_ads', ad_id=1))
            else:
                logging.debug(f"Login failed: Incorrect password for email {email}")
                flash("Invalid email or password.", "danger")
                return render_template('login.html'), 400
        except ValueError as e:
            logging.error(f"Error during password verification: {e}")
            flash("An error occurred while logging in. Please try again.", "danger")
            return render_template('login.html'), 500

    return render_template('login.html')
@app.route('/view_ads/<int:ad_id>', methods=['GET', 'POST'])
@login_required
def view_ads(ad_id):
    user = current_user

    # Fetch all ads, sponsor ad, and member ads as before
    ads = Ad.query.order_by(Ad.id.desc()).all()  # Fetch all ads (you can filter by certain conditions)

    # Retrieve the number of ads to show from admin settings (default to 5)
    setting = AdminSettings.query.filter_by(setting_name='num_ads_to_show').first()
    num_ads_to_show = int(setting.setting_value) if setting and str(setting.setting_value).isdigit() else 5

    # Get the ads that the user has not viewed during this session
    ads_viewed = user.ads_viewed.split(",") if user.ads_viewed else []
    ads_to_view = [ad for ad in ads if str(ad.id) not in ads_viewed]

    # Limit the ads to view by the number of ads configured by admin settings
    ads_to_view = ads_to_view[:num_ads_to_show]

    # Check if all ads have been viewed, if yes, end the session
    if not ads_to_view:
        flash("You've completed the process!", "success")
        user.ads_viewed = ""  # Reset the ads viewed for the next session
        db.session.commit()
        return redirect(url_for('index'))

    # Get the current ad to be viewed
    current_ad = ads_to_view[0]

    # Calculate the correct ad number within the session (reset to 1 for new session)
    ad_number_in_session = len(ads_viewed) % num_ads_to_show + 1

    if request.method == 'POST':
        # Update user's ads viewed history if not already viewed
        if str(current_ad.id) not in ads_viewed:
            user.ads_viewed += f"{current_ad.id},"
            current_ad.view_count += 1

            # Create an AdAnalytics entry for tracking ad views
            analytics_entry = AdAnalytics(
                ad_id=current_ad.id,
                user_id=user.id,
                view_time=datetime.utcnow(),
                views=1
            )
            db.session.add(analytics_entry)

        try:
            db.session.commit()
            # Redirect to the next ad, or complete the process
            next_ad_id = ads_to_view[1].id if len(ads_to_view) > 1 else None
            if next_ad_id:
                return redirect(url_for('view_ads', ad_id=next_ad_id))
            else:
                flash("You've completed the process!", "success")
                return redirect(url_for('index'))
        except Exception as e:
            logging.error(f"Error viewing ad: {e}")
            db.session.rollback()
            flash("Failed to record ad view.", "danger")
            return render_template('view_ads.html', ad=current_ad, ad_number=ad_number_in_session), 500

    return render_template('view_ads.html', ad=current_ad, ad_number=ad_number_in_session)

@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin():
    user = current_user

    # Ensure only admins can access this page
    if not user.is_admin:
        flash("You do not have permission to access this page.", "danger")
        return redirect(url_for('index'))

    # Fetch current settings
    setting = AdminSettings.query.filter_by(setting_name='num_ads_to_show').first()
    num_ads_to_show = setting.setting_value if setting else 5

    if request.method == 'POST':
        # Update the number of ads to show setting
        new_num_ads = request.form.get('num_ads_to_show')
        if new_num_ads and new_num_ads.isdigit():
            if setting:
                setting.setting_value = new_num_ads
            else:
                setting = AdminSettings(setting_name='num_ads_to_show', setting_value=new_num_ads)
                db.session.add(setting)

            try:
                db.session.commit()
                flash("Settings updated successfully!", "success")
            except Exception as e:
                logging.error(f"Error updating settings: {e}")
                db.session.rollback()
                flash("Failed to update settings. Please try again.", "danger")

    return render_template('admin_settings.html', num_ads_to_show=num_ads_to_show)

@app.route('/')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for('signup'))

if __name__ == '__main__':
    app.run(debug=True)

