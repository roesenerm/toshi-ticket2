from flask import Flask, render_template, redirect, url_for, request, jsonify, make_response, session, flash
import pymongo
from pymongo import MongoClient
from functools import *
import json
import requests
from time import gmtime, strftime
import os
from pyshorteners.shorteners import Shortener
import string
import random
from bitcoin import *

def connect():
	connection = MongoClient('ds031792.mongolab.com', 31792)
	handle = connection["dbone"]
	handle.authenticate('matthewroesener','namoku8807')
	return handle

app = Flask(__name__)
app.secret_key = "temp secret"

handle = connect()

tokens = handle.tokens
posts = handle.posts
accounts = handle.accounts


CLIENT_ID = '40335456568a0fd8a01e934b18b83df11a58b0cf1bb7adfaa4dfeb57e247652e'
CLIENT_SECRET = '591828d95d35aa6179316409b9e016f3a1dd78af14bfe142efff2a3aa9bd40ef'
YOUR_CALLBACK_URL = 'http://localhost:5000/consumer_auth'

def login_required(f):
	@wraps(f)
	def wrap(*args, **kwargs):
		if 'logged_in' in session:
			return f(*args, **kwargs)
		else:
			flash('You need to login first.')
			return redirect(url_for('login'))
	return wrap

#Login Page
@app.route('/login', methods=['GET', 'POST'])
def login():
	auth_url = 'https://www.coinbase.com/oauth/authorize?response_type=code&client_id='+ CLIENT_ID +'&redirect_uri='+ YOUR_CALLBACK_URL

	error = None

	if request.method == 'POST':
		username = request.form['username']
		account_password = request.form['account_password']

		if accounts.find_one({'username':username}) == None and accounts.find_one({'account_password':account_password}) == None:

			error = 'Invalid Credentials. Please try again.'

		else:
			session['logged_in'] = True
			session['username'] = username

			return redirect(url_for('explore'))

	return render_template('login.html', error=error, auth_url=auth_url)

@app.route('/signup', methods=['GET', 'POST'])
def signup():

	error = None

	if request.method == 'POST':
		username = request.form['username']
		account_password = request.form['account_password']
		confirm_password = request.form['confirm_password']
		my_address = request.form['my_address']

		if account_password == confirm_password:

			handle.accounts.insert({'username':username, 'acccount_password':account_password, 'my_address':my_address})

			session['logged_in'] = True
			session['username'] = username

		return redirect(url_for('explore'))

	return render_template('signup.html', error=error)

#Logout
@app.route('/logout')
@login_required
def logout():

	session.pop('logged_in', None)

	flash('You were just logged out!')

	return redirect(url_for('login'))


@app.route('/consumer_auth')
def recieve_token():

	oauth_code = request.args['code']

	url = 'https://www.coinbase.com/oauth/token?grant_type=authorization_code&code='+oauth_code+'&redirect_uri='+YOUR_CALLBACK_URL+'&client_id='+CLIENT_ID+'&client_secret='+CLIENT_SECRET

	r = requests.post(url)

	data = r.json()

	access_token = data['access_token']

	refresh_token = data['refresh_token']

	if access_token == None:

		return redirect(url_for('home'))

	else:
		session['logged_in'] = True

		t = strftime("%Y-%m-%d %H:%M:%S", gmtime())

		handle.tokens.insert({'created_at':t,'token': access_token})

		lastToken = tokens.find().sort([("created_at", pymongo.DESCENDING)])

		return redirect(url_for('explore'))

#Cover Page
@app.route('/')
def home():
	auth_url = 'https://www.coinbase.com/oauth/authorize?response_type=code&client_id='+ CLIENT_ID +'&redirect_uri='+ YOUR_CALLBACK_URL

	return render_template("cover.html", auth_url=auth_url)


@app.route('/explore', methods=['GET', 'POST'])
#@login_required
def explore():

	username = session['username']

	session_user = accounts.find_one({'username':username})

	my_address = session_user['my_address']

	posts = handle.posts.find()

	error = None
	if request.method == 'POST':

		from_address = str(request.form['bitcoin_address'])

		asset_id = str(request.form['asset_id'])

		ticket_price = str(request.form['ticket_price'])

		transfer_amount = int(request.form['transfer_amount'])

		payload = {'fee': 1000, 'from': from_address, 'to':[{'address':my_address,'amount': transfer_amount, 'asset_id' : asset_id}]}

		r = requests.post('http://testnet.api.coloredcoins.org:80/v2/sendasset', data=json.dumps(payload), headers={'Content-Type':'application/json'})

		response = r.json()

		tx_hex = response['txHex']

		#Get Permission To Purchase Asset/ Asset Owner must sign transaction with Private key

		private_key = ""

		tx_key = private_key

		if str(r) == '<Response [200]>':

			signed_tx = sign_tx(tx_hex, tx_key)

			tx_id = broadcast_tx(signed_tx)

			return render_template("transfer_coin.html", tx_id=tx_id)

		else:
			error = "Error transferring coin"

			return render_template("transfer_coin.html", error=error)

	return render_template("explore.html", posts=posts)


#Profile Page
@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():

	username = session['username']

	session_user = accounts.find_one({'username':username})

	my_address = session_user['my_address']

	r = requests.get('http://testnet.api.coloredcoins.org/v2/addressinfo/' + my_address)

	response = r.json()

	bitcoin_address = response['address']

	utxos = response['utxos']

	return render_template("profile.html", bitcoin_address=bitcoin_address, utxos=utxos)

# Create unique coin
@app.route('/issue', methods=['GET', 'POST'])
@login_required
def issue():
	username = session['username']

	session_user = accounts.find_one({'username':username})

	my_address = session_user['my_address']

	error = None
	if request.method == 'POST':

		issued_amount = request.form['issued_amount']

		description = request.form['description']

		image = request.form['image']

		ticket_price = request.form['ticket_price']

		name = request.form['coin_name']

		payload = {
		    "issueAddress": my_address,
		    "amount": issued_amount,
		    "divisibility": 0,
		    "fee": 1000,
		    "metadata": {
		        "userData": {
		        	"meta": [
		        		{"ID": 1},
		            	{"Name": name},
		            	{"Description": description},
		            	{"Price": ticket_price},
		            	{"Image": image},
		            	{"Type": "Ticket"}
		        	]
		        }
		    }
		}

		r = requests.post('http://testnet.api.coloredcoins.org:80/v2/issue', data=payload, headers={'Content-Type':'application/json'})

		response = r.json()

		print (response)

		tx_hex = response['txHex']

		asset_id = response['assetId']

		tx_key = request.form['private_key']

		if str(r) == '<Response [200]>':

			signed_tx = sign_tx(tx_hex, tx_key)

			tx_id = broadcast_tx(signed_tx)

			posts.insert({'bitcoin_address':my_address, 'asset_address':asset_id, 'tx_id':tx_id})

			return render_template("issuance.html", name=name, image=image, ticket_price=ticket_price, description=description, issued_amount=issued_amount)

		else:
			error = "Error issuing ticket"
			return render_template("issue_coin.html", error=error)

	return render_template("issue.html", error=error)


def sign_tx(tx_hex, tx_key):

	raw_tx = sign(tx_hex, 0, tx_key)

	return raw_tx

def broadcast_tx(signed_tx):

	payload = str(signed_tx)

	r = requests.post('http://testnet.api.coloredcoins.org:80/v2/broadcast', data=json.dumps(payload), headers={'Content-Type':'application/json'})

	response = r.json()

	tx_id = response['txid']

	return tx_id


# Check coin balance
@app.route('/check_ticket_issuer', methods=['GET', 'POST'])
#@login_required
def check_ticket_issuer():
	error = None
	if request.method == 'POST':

		public_address = request.form['from_public_address']

		r = requests.get('http://testnet.api.coloredcoins.org/v2/addressinfo/' + public_address)

		response = r.json()

		bitcoin_address = response['address']

		utxos = response['utxos']

		return render_template("ticket_issuer.html", bitcoin_address=bitcoin_address, utxos=utxos)

	return render_template("check_ticket_issuer.html")

@app.route('/check_ticket', methods=['GET', 'POST'])
#@login_required
def check_ticket():
	error = None
	if request.method == 'POST':
		headers = {'Content-Type':'application/json'}

		asset_id = request.form['asset_id']
		tx_id = request.form['tx_id']
		utxo = tx_id + ":1"

		r = requests.get('http://testnet.api.coloredcoins.org:80/v2/assetmetadata/' + asset_id + '/' + utxo)

		response = r.json()

		asset_id = response['assetId']
		name = response['metadataOfIssuence']['name']
		description = response['metadataOfIssuence']['description']

		return render_template("ticket.html", asset_id=asset_id, name=name, description=description, error=error)

	return render_template("check_ticket.html")


@app.route('ticket_id/<asset_id>')
#@login_required
def metadata(asset_id):

	if posts.find_one({'asset_id':asset_id}) == None:

		error = "No Asset ID Found"

		return render_template("ticket.html", asset_id=asset_id, name=name, description=description, error=error)

	else:

		data = posts.find_one({'asset_id':asset_id})

		asset_id = asset_id

		tx_id = data['tx_id']

		utxo = tx_id + ":1"

		r = requests.get('http://testnet.api.coloredcoins.org:80/v2/assetmetadata/' + asset_id + '/' + utxo)

		response = r.json()

		asset_id = response['assetId']
		name = response['metadataOfIssuence']['name']
		description = response['metadataOfIssuence']['description']

		return render_template("ticket.html", asset_id=asset_id, name=name, description=description, error=error)




if __name__ == '__main__':
	#port = int(os.environ.get('PORT', 5000))
	#app.run(host='0.0.0.0', port=port)
	app.run(debug=True)


