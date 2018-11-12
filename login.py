from flask import Flask, render_template, url_for, request, session, redirect
from flask_pymongo import PyMongo
from flask_bcrypt import Bcrypt

app= Flask(__name__)

app.config['MONGO_DBNAME'] = 'mongologin'
app.config['MONGO_URI'] = 'mongodb://geordie:Wookie#66@ds159273.mlab.com:59273/users'

mongo = PyMongo(app)
flask_bcrypt = Bcrypt(app)
@app.route('/')
def index():
	if'username' in session:
		return "<a href='logout'> logout <a>"

	return render_template('index.html')

@app.route('/login', methods=['POST'])
def login():
	users = mongo.db.users;
	login_user = users.find_one({'name': request.form ['username']})
	if login_user:
		pw_hash = flask_bcrypt.generate_password_hash(request.form['pass']).decode('utf-8')
		if flask_bcrypt.check_password_hash(login_user['password'],request.form['pass']):
			session['username'] = request.form['username']
			return redirect(url_for('index'))

	return 'Invailed username/password combinations'

@app.route('/logout')
def logout():
	if'username' in session:
		session.pop('username', None)
		return redirect(url_for('index'))
	return 'You are not logged in'

@app.route('/register', methods=['POST','GET'])
def register():
	if request.method == 'POST':
		users = mongo.db.users
		existing_user = users.find_one({'name': request.form['username']})
		if existing_user is None:
			hashpass = flask_bcrypt.generate_password_hash(request.form['pass']).decode('utf-8')
			users.insert({'name' : request.form['username'], 'password' : hashpass, 'active' : True, 'permissions': 'content creator'})
			session['username'] = request.form['username']
			return redirect(url_for('index'))
		return 'That username already exists'

	return render_template('register.html')

if __name__ == '__main__':
	app.secret_key = 'mysecret'
	app.run(debug=True)
