from flask import Flask, render_template, redirect, url_for, flash, request, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt
import logging

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///viral_traffic_service.db'
db = SQLAlchemy(app)
login_manager = LoginManager(app)
bcrypt = Bcrypt(app)

# Model definitions for User and Ad
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    referral_link = db.Column(db.String(255), nullable=True)
    promoted_link = db.Column(db.String(255), nullable=True)
    sponsor_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    sponsor = db.relationship('User', remote_side=[id], backref='referrals')

class Ad(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(255), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)

# The home/index route
@app.route('/')
def index():
    return render_template('index.html')

# User landing page
@app.route('/<int:user_id>')
def user_landing_page(user_id):
    user = User.query.get(user_id)
    if not user:
        abort(404)

    user_ad = Ad.query.filter_by(user_id=user.id).first()
    downline_ads = Ad.query.filter(Ad.user_id.in_([u.id for u in user.referrals])).all()

    ads_to_display = [user_ad] + downline_ads

    return render_template('landing_page.html', ads=ads_to_display, user=user)

# Admin settings page
@app.route('/admin/settings', methods=['GET', 'POST'])
@login_required
def admin_settings():
    # Example admin settings logic
    num_ads_to_show = 5
    if request.method == 'POST':
        num_ads_to_show = request.form.get('num_ads_to_show')
        if num_ads_to_show:
            setting = AdminSettings.query.filter_by(setting_name='num_ads_to_show').first()
            if setting:
                setting.setting_value = num_ads_to_show
            else:
                setting = AdminSettings(setting_name='num_ads_to_show', setting_value=num_ads_to_show)
                db.session.add(setting)
            try:
                db.session.commit()
                flash("Settings updated successfully!", "success")
            except Exception as e:
                logging.error(f"Error updating settings: {e}")
                db.session.rollback()
                flash("Failed to update settings. Please try again.", "danger")
    return render_template('admin_settings.html', num_ads_to_show=num_ads_to_show)

# Logout route
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for('signup'))

# Signup route (this should include the referral link generation, etc.)
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        promoted_link = request.form.get('promoted_link')
        sponsor_ref = request.args.get('ref')

        if not email or not password:
            logging.debug("Signup failed: Missing email or password")
            flash("Invalid input, please try again.", "danger")
            return render_template('signup.html'), 400

        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            logging.debug(f"Signup failed: Email {email} already exists")
            flash("Email already registered. Please log in or use a different email.", "danger")
            return render_template('signup.html'), 400

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(email=email, password=hashed_password, promoted_link=promoted_link)

        if sponsor_ref:
            sponsor = User.query.get(sponsor_ref)
            if sponsor:
                new_user.sponsor = sponsor

        try:
            db.session.add(new_user)
            db.session.commit()

            referral_link = f"https://yourservice.com/signup?ref={new_user.id}"
            new_user.referral_link = referral_link
            db.session.add(new_user)
            db.session.commit()

            if promoted_link:
                new_ad = Ad(url=promoted_link, user_id=new_user.id)
                db.session.add(new_ad)
                db.session.commit()
                logging.debug(f"Promoted link added to ads table for user {new_user.email}: {promoted_link}")

            login_user(new_user)
            logging.debug(f"User {new_user.email} logged in after signup")
            flash("Signup successful!", "success")
            return redirect(url_for('view_ads', ad_id=1))

        except Exception as e:
            logging.error(f"Error in signup: {e}")
            db.session.rollback()
            flash("Signup failed, please try again.", "danger")
            return render_template('signup.html'), 400

    return render_template('signup.html')

if __name__ == '__main__':
    app.run(debug=True)

