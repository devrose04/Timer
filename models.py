from app import db

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)

class Timer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    sets = db.Column(db.Integer)
    high_duration = db.Column(db.String(10))
    low_duration = db.Column(db.String(10))
    warmup_duration = db.Column(db.String(10))
    cooldown_duration = db.Column(db.String(10))
    high_color = db.Column(db.String(7))
    low_color = db.Column(db.String(7))
    warmup_color = db.Column(db.String(7))
    cooldown_color = db.Column(db.String(7))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
