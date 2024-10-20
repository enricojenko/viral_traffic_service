# models.py

from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin

db = SQLAlchemy()

class User(UserMixin, db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    ads_viewed = db.Column(db.String, default="")
    promoted_link = db.Column(db.String, nullable=True)
    priority = db.Column(db.Integer, default=0)
    has_completed = db.Column(db.Boolean, default=False)
    sponsor_id = db.Column(db.Integer, nullable=True)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    referral_link = db.Column(db.String(255))  # This field must exist to store the referral link

    def __repr__(self):
        return f"<User {self.email}>"

class Ad(db.Model):
    __tablename__ = 'ads'

    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String, nullable=False)
    view_count = db.Column(db.Integer, default=0)

    def __repr__(self):
        return f"<Ad {self.id} - {self.url}>"

class AdAnalytics(db.Model):
    __tablename__ = 'ad_analytics'

    id = db.Column(db.Integer, primary_key=True)
    ad_id = db.Column(db.Integer, db.ForeignKey('ads.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    view_time = db.Column(db.DateTime, nullable=False)
    click_time = db.Column(db.DateTime, nullable=True)
    views = db.Column(db.Integer, nullable=False, default=1)
    ad = db.relationship('Ad', backref='analytics')
    user = db.relationship('User', backref='analytics')

    def __repr__(self):
        return f"<AdAnalytics AdID={self.ad_id} UserID={self.user_id}>"

class AdminSettings(db.Model):
    __tablename__ = 'admin_settings'

    id = db.Column(db.Integer, primary_key=True)
    setting_name = db.Column(db.String(100), unique=True, nullable=False)
    setting_value = db.Column(db.String(255), nullable=False)

    def __repr__(self):
        return f"<AdminSettings {self.setting_name}={self.setting_value}>"

