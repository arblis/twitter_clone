from flask import Flask, request, render_template
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import date
from flask_socketio import SocketIO, send
import re

# =========      initialzing the app     ===========
app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
login_manager = LoginManager()
login_manager.init_app(app)
socketio = SocketIO(app)

# =========      Connect to the DB      ==============
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///faketwitter.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


# ========       Configure Tables      ================
class User(db.Model, UserMixin):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(250), nullable=False, unique=True)
    password = db.Column(db.String, nullable=False)
    name = db.Column(db.String(250), nullable=False)
    tweets = relationship('Tweets', back_populates='author')
    

class Tweets(db.Model):
    __tablename__ = 'tweets'
    id = db.Column(db.Integer, primary_key=True)
    # creat a foreign key to users.id
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    # creat a referance to the User object
    author = relationship('User', back_populates='tweets')
    date = db.Column(db.String(250), nullable=False)
    tweet = db.Column(db.Text, nullable=False)

# db.create_all()

# ========    check email in proper format    ================
def is_email(email):
    if email:
        regular_exprestion = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        if (re.fullmatch(regular_exprestion, email)):
            return True
        else: return False
    else:
        return False

#  creating the login manager
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

# ==============    Login Rout    ================
@app.route('/login', methods=['GET'])
def login():
    email = request.args.get('email')
    password = request.args.get('password')
    if email and password:
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(pwhash=user.password, password=password):
            login_user(user)
            return 'login successful', 200
        else:
            return 'Email or password is not correct please try again.', 400
    else:
        return 'Username and Password cant be empty.', 400


# ==============    Logout Rout    ================
@app.route('/logout')
def logout():
    logout_user()
    return 'Logedout'


# ==============    Register Rout    ================
@app.route('/register', methods=['POST'])
def register():
    email = request.args.get('email')
    password = request.args.get('password')
    name = request.args.get('name')
    if email or password or name:
        if is_email(email):
            if User.query.filter_by(email=email).first():
                return 'Email already exists please log in.', 400
            else:
                encrypted_pw = generate_password_hash(password=password, method='pbkdf2:sha256', salt_length=8)
                new_user = User(
                    email=email,
                    password=encrypted_pw,
                    name=name
                )
                db.session.add(new_user)
                db.session.commit()
                return 'User created successfyly.', 200
        else:
            return 'Incorrect Email', 400
    else:
        return 'Please Provide Email Password and Name.', 400


# ==============    creat a tweet Rout    ================
@app.route('/tweet', methods=['POST'])
# @login_required
def tweet():
    if not current_user.is_authenticated:
        return 'You need to Login first.', 400
    else:
        tweet = request.args.get('tweet')

        new_tweet = Tweets(
            author = current_user,
            date = date.today().strftime("%B %d, %Y"),
            tweet = tweet
        )
        db.session.add(new_tweet)
        db.session.commit()
        return 'Tweeted!', 200


# ==============    Delete a tweet Rout    ================
@app.route('/delete/<int:tweet_id>', methods=['DELETE'])
def delete_tweet(tweet_id):
    tweet_to_delete = Tweets.query.get(tweet_id)
    if tweet_to_delete:
        db.session.delete(tweet_to_delete)
        db.session.commit()
        return 'Deleted', 200
    else:
        return 'Tweet id not found', 400


# ==============    Update a tweet Rout    ================
@app.route('/edit-tweet/<int:tweet_id>', methods=['PUT'])
def edit_tweet(tweet_id):
    updated_tweet = request.args.get('updated_tweet')
    old_tweet = Tweets.query.get(tweet_id)
    if old_tweet:
        old_tweet.tweet = updated_tweet
        db.session.commit()
        return 'Updated', 200
    else:
        return 'Tweet id not found', 400


# ==============    chat Rout    ================
@app.route('/chat', methods=['GET', 'POST'])
def chat():
    user = current_user
    room = request.args.get('room')
    return render_template('index.html', username=user)


# ==============    The msg handler    ================
@socketio.on('message')
def handleMessage(msg):
	print('Message: ' + msg)
	send(msg, broadcast=True)
    

if __name__ == '__main__':
    # app.debug = True
    # app.run(host='localhost', port=5000)
    socketio.run(app, debug=True)