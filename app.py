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

        logging.debug(f"Signup attempt for email: {email}")

        # Check if the email is already registered
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            logging.debug(f"Signup failed: Email {email} already exists")
            flash("Email already registered. Please log in or use a different email.", "danger")
            return render_template('signup.html'), 400

        # Capture sponsor referral ID from URL (if any)
        sponsor_id = request.args.get('ref')
        sponsor = None

        if sponsor_id:
            logging.debug(f"Referral link provided with sponsor ID: {sponsor_id}")
            sponsor = User.query.filter_by(id=sponsor_id).first()
            if sponsor:
                logging.debug(f"Sponsor found for {email}: {sponsor.email} (ID: {sponsor.id})")
            else:
                logging.warning(f"Invalid sponsor referral ID: {sponsor_id} for user {email}")
        else:
            logging.debug(f"No sponsor ID found for user {email}")

        # Hash the password and create the new user
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(email=email, password=hashed_password, promoted_link=promoted_link)

        # Assign the sponsor ID (if found) to the new user
        if sponsor:
            logging.debug(f"Assigning sponsor ID {sponsor.id} to user {email}")
            new_user.sponsor_id = sponsor.id
        else:
            logging.debug(f"No sponsor assigned for user {email}")

        try:
            db.session.add(new_user)
            db.session.commit()

            # Verify if the sponsor_id was properly assigned and saved
            logging.debug(f"User {new_user.email} created with sponsor_id: {new_user.sponsor_id}")

            # Generate the referral link for the new user
            referral_link = url_for('signup', _external=True) + f"?ref={new_user.id}"
            new_user.referral_link = referral_link
            db.session.commit()

            logging.debug(f"Referral link generated for {new_user.email}: {referral_link}")

            # Add the user's promoted link to the ads table
            if promoted_link:
                new_ad = Ad(url=promoted_link)
                db.session.add(new_ad)
                db.session.commit()
                logging.debug(f"Promoted link added to ads table for user {new_user.email}: {promoted_link}")

            # Log the user in after successful signup
            login_user(new_user)
            logging.debug(f"User {new_user.email} logged in after signup")
            flash("Signup successful! Check your email for your referral link.", "success")

            # Redirect to view the first ad
            return redirect(url_for('view_ads', ad_id=1))

        except Exception as e:
            logging.error(f"Error in signup: {e}")
            db.session.rollback()
            flash("Signup failed, please try again.", "danger")
            return render_template('signup.html'), 400

    # Log the referral link of the signup page being viewed
    referral_link = request.args.get('ref', None)
    logging.debug(f"Viewing signup page with referral link: {referral_link}")

    # Render the signup page
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

    logging.debug(f"User {user.email} is accessing ad with ID {ad_id}")

    # Fetch all ads
    ads = Ad.query.order_by(Ad.id.desc()).all()
    logging.debug(f"Total ads in the system: {len(ads)}")

    # Retrieve number of ads to show from settings
    setting = AdminSettings.query.filter_by(setting_name='num_ads_to_show').first()
    num_ads_to_show = int(setting.setting_value) if setting and str(setting.setting_value).isdigit() else 5
    logging.debug(f"Number of ads to show: {num_ads_to_show}")

    # Get ads that the user has already viewed
    ads_viewed = [ad_id for ad_id in user.ads_viewed.split(",") if ad_id]  # Clean empty strings
    logging.debug(f"Ads already viewed: {ads_viewed}")

    # Get ads that have not yet been viewed by the user
    ads_to_view = [ad for ad in ads if str(ad.id) not in ads_viewed]
    logging.debug(f"Ads available for viewing: {[ad.id for ad in ads_to_view]}")

    # Limit the ads to view by the number configured in settings
    ads_to_view = ads_to_view[:num_ads_to_show]
    logging.debug(f"Ads to be viewed: {[ad.id for ad in ads_to_view]}")

    # Check if all ads have been viewed
    if not ads_to_view:
        logging.info(f"User {user.email} has completed all ad views")
        flash("You've completed the process!", "success")
        user.ads_viewed = ""  # Reset for the next session
        db.session.commit()
        return redirect(url_for('index'))

    # Get the current ad to be viewed
    current_ad = ads_to_view[0]
    logging.debug(f"Current ad being displayed: {current_ad.id}, URL: {current_ad.url}")

    # Calculate the ad number in the session based on the ads viewed so far
    ad_number_in_session = len(ads_viewed) + 1  # Increment based on ads viewed
    logging.debug(f"Ad number in session: {ad_number_in_session}")

    if request.method == 'POST':
        logging.debug(f"User {user.email} is submitting a view for ad ID {current_ad.id}")

        # Update user's ads viewed history if not already viewed
        if str(current_ad.id) not in ads_viewed:
            user.ads_viewed += f"{current_ad.id},"
            current_ad.view_count += 1
            logging.debug(f"User {user.email} viewed ad {current_ad.id}. Total views for this ad: {current_ad.view_count}")

            # Log analytics entry for tracking ad views
            analytics_entry = AdAnalytics(
                ad_id=current_ad.id,
                user_id=user.id,
                view_time=datetime.utcnow(),
                views=1
            )
            db.session.add(analytics_entry)
            logging.debug(f"AdAnalytics entry created for ad ID {current_ad.id}, user {user.email}")

        try:
            db.session.commit()
            logging.info(f"Ad view for ad ID {current_ad.id} successfully recorded for user {user.email}")

            # Check if the user has viewed the required number of ads
            if len(ads_viewed) + 1 >= num_ads_to_show:
                logging.info(f"User {user.email} has completed viewing the required number of ads")
                flash("You've completed viewing all the required ads!", "success")
                user.ads_viewed = ""  # Reset for the next session
                db.session.commit()
                return redirect(url_for('index'))

            # Redirect to the next ad
            next_ad_id = ads_to_view[1].id if len(ads_to_view) > 1 else None
            if next_ad_id:
                logging.debug(f"Redirecting user {user.email} to next ad ID {next_ad_id}")
                return redirect(url_for('view_ads', ad_id=next_ad_id))
            else:
                logging.info(f"User {user.email} has completed all available ads")
                flash("You've completed the process!", "success")
                return redirect(url_for('index'))
        except Exception as e:
            logging.error(f"Error recording ad view for user {user.email}: {e}")
            db.session.rollback()
            flash("Failed to record ad view.", "danger")
            return render_template('view_ads.html', ad=current_ad, ad_number=ad_number_in_session), 500

    logging.debug(f"Displaying ad ID {current_ad.id} to user {user.email} as advertisement number {ad_number_in_session}")

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

