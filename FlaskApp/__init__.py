from flask import Flask, render_template, redirect, url_for, request, jsonify, make_response, session, flash
import pymongo
from pymongo import MongoClient
from functools import *
import json
import requests
from time import gmtime, strftime
import os
import string
import random
from bitcoin import *
from passlib.hash import sha256_crypt
import pdb

def connect():
	connection = MongoClient('ds047772.mongolab.com', 47772)
	handle = connection["dbtwo"]
	handle.authenticate('matthewroesener','toshihawaii')
	return handle

app = Flask(__name__)
app.secret_key = "temp secret"

handle = connect()

tokens = handle.tokens
posts = handle.posts
accounts = handle.accounts
unsigned_tx = handle.unsigned_tx


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
		brainwallet_password = request.form['brainwallet_password']

		'''

		if accounts.find_one({'username':username}) == None:

			error = 'Invalid Credentials. Please try again.'

		else:
			session['logged_in'] = True
			session['username'] = username

			return redirect(url_for('explore'))

		'''

		if accounts.find_one({'username':username}) == None:

			error = 'Invalid Credentials. Please try again.'

		else:

			if sha256_crypt.verify(str(brainwallet_password), str(accounts.find_one({'username':username})['password'])) == False:

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
		brainwallet_password = request.form['brainwallet_password']
		confirm_brainwallet_password = request.form['confirm_brainwallet_password']

		if brainwallet_password != confirm_brainwallet_password:

			error = 'Invalid Password. Please try again.'

		else:

			priv, addr, password_on_server  = create_account(brainwallet_password)

			handle.accounts.insert({'username':username, 'priv':priv, 'my_address':addr, 'password': password_on_server})

			session['logged_in'] = True
			session['username'] = username

		return redirect(url_for('explore'))

	'''

	if account_password == confirm_password:

		my_address = create_account(brainwallet_password)

		handle.accounts.insert({'username':username, 'acccount_password':account_password, 'my_address':my_address})

		session['logged_in'] = True
		session['username'] = username

		return redirect(url_for('explore'))

	'''

	return render_template('signup.html', error=error)

def create_account(brainwallet_password):
	password_on_server = sha256_crypt.encrypt(brainwallet_password)
	priv = sha256(password_on_server)
	pub = privtopub(priv)
	addr = pubtoaddr(pub, 111)

	return priv, addr, password_on_server

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

	return render_template("cover2.html", auth_url=auth_url)


@app.route('/explore', methods=['GET', 'POST'])
@login_required
def explore():

	error = None

	username = session['username']

	session_user = accounts.find_one({'username':username})

	my_address = session_user['my_address']

	buyer_private_key = session_user['priv']

	posts = handle.posts.find()

	meta_data = []

	for post in posts:
		bitcoin_address = post['bitcoin_address']
		asset_id = post['asset_id']
		tx_id = post['tx_id']

		for index in range(0,10):

			utxo = tx_id + ':' + str(index)

			endpoint = 'http://testnet.api.coloredcoins.org:80/v2/assetmetadata/' + asset_id + '/' + utxo

			r = requests.get(endpoint)

			if (r.status_code) != 200:
				pass

			else:

				response = r.json()

				asset_id = response['assetId']
				name = response['metadataOfIssuence']['data']['userData']['meta'][1]['Name']
				description = response['metadataOfIssuence']['data']['userData']['meta'][2]['Description']
				price = response['metadataOfIssuence']['data']['userData']['meta'][3]['Price']
				image = response['metadataOfIssuence']['data']['userData']['meta'][4]['Image']

				data = {'bitcoin_address':bitcoin_address, 'asset_id':asset_id, 'name':name, 'description':description, 'price':price, 'image':image}

				meta_data.append(data)

	if request.method == 'POST':

		error = None
		asset_tx_id = None
		btc_tx_id = None

		from_address = str(request.form['bitcoin_address'])

		asset_id = str(request.form['asset_id'])

		ticket_price = str(request.form['ticket_price'])

		transfer_amount = int(request.form['transfer_amount'])

		issuer = accounts.find_one({'my_address':from_address})

		issuer_private_key = issuer['priv']

		asset_tx_id, btc_tx_id, error = swap(my_address=my_address, ticket_price=ticket_price, from_address=from_address, asset_id=asset_id, transfer_amount=transfer_amount, issuer_private_key=issuer_private_key, buyer_private_key=buyer_private_key)

		if asset_tx_id == True and btc_tx_id == True:

			return render_template("buy.html", asset_tx_id=asset_tx_id, btc_tx_id=btc_tx_id, error=error)


	return render_template("explore.html", posts=posts, meta_data=meta_data, error=error)


def swap(my_address, ticket_price, from_address, asset_id, transfer_amount, issuer_private_key, buyer_private_key):

	error = None
	asset_tx_id = None
	btc_tx_id = None

	try:

		price_url = "http://api.coindesk.com/v1/bpi/currentprice.json"
		r = requests.get(price_url)

		response = r.json()

		btc_usd_rate = response['bpi']['USD']['rate']

		input_amt = ticket_price
		ticket_price_satoshis = float(input_amt) / float(btc_usd_rate) * 100000000

		ticket_price_satoshis = 1000

		my_address_satoshis = get_address_balance(my_address)

		from_address_satoshis = get_address_balance(from_address)

		if my_address_satoshis > ticket_price_satoshis and from_address_satoshis > 1000:

			asset_tx_id, error = transfer_asset(from_address=from_address, to_address=my_address, transfer_amount=transfer_amount, asset_id=asset_id, tx_key=issuer_private_key)

			btc_tx_id, error = send_btc(send_to=from_address, ticket_price_satoshis=ticket_price_satoshis, send_from=my_address, tx_key=buyer_private_key)

		else:

			error = "Not enough funds"

	except:

		error = "Not enough funds"

	return asset_tx_id, btc_tx_id, error

def transfer_asset(from_address, to_address, transfer_amount, asset_id, tx_key):

	error = None
	tx_id = None

	payload = {'fee': 1000, 'from': from_address, 'to':[{'address':to_address,'amount': transfer_amount, 'assetId' : asset_id}]}

	r = requests.post('http://testnet.api.coloredcoins.org:80/v2/sendasset', data=json.dumps(payload), headers={'Content-Type':'application/json'})

	response = r.json()

	if r.status_code == 200:

		try:

			tx_hex = response['txHex']

			signed_tx = sign_tx(tx_hex, tx_key)

			tx_id = broadcast_tx(signed_tx)

		except:

			error = "Error transferring asset"

	return tx_id, error

def send_btc(send_to, ticket_price_satoshis, send_from, tx_key):

	pdb.set_trace()

	error = None
	tx_id = None

	h = history(send_from)

	outs = [{'value':ticket_price_satoshis, 'address':send_to}]

	tx_hex = mktx(h, outs)

	try:

		signed_tx = sign_tx(tx_hex, tx_key)

		tx_id = broadcast_tx(signed_tx)

	except:

		error = "Error transferring Bitcoin"

	return tx_id, error


def get_address_balance(address):
	'''

	r = requests.get("https://blockchain.info/address/"+address+"?format=json")

	response = r.json()

	print (response)

	balance = response["final_balance"]

	return balance

	'''
	return 500000000

@app.route('/transfer', methods=['GET', 'POST'])
@login_required
def transfer():

	error = None

	if request.method == 'POST':

		from_address = str(request.form['from_bitcoin_address'])

		asset_id = str(request.form['asset_id'])

		transfer_amount = int(request.form['transfer_amount'])

		to_address = str(request.form['to_bitcoin_address'])

		private_key = str(request.form['private_key'])

		payload = {'fee': 1000, 'from': from_address, 'to':[{'address':to_address,'amount': transfer_amount, 'assetId' : asset_id}]}

		r = requests.post('http://testnet.api.coloredcoins.org:80/v2/sendasset', data=json.dumps(payload), headers={'Content-Type':'application/json'})

		response = r.json()

		if r.status_code == 200:

			tx_hex = response['txHex']

			tx_key = private_key

			signed_tx = sign_tx(tx_hex, tx_key)

			tx_id = broadcast_tx(signed_tx)

			return render_template("transfer_asset.html", tx_id=tx_id)

		else:
			error = "Error transferring asset"

			return render_template("transfer_asset.html", from_address=from_address, asset_id=asset_id, transfer_amount=transfer_amount, to_address=to_address, error=error)

	return render_template("transfer.html", posts=posts)

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

	return render_template("profile.html", my_address=my_address, utxos=utxos)

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

		r = requests.post('http://testnet.api.coloredcoins.org:80/v2/issue', data=json.dumps(payload), headers={'Content-Type':'application/json'})

		response = r.json()

		tx_key = request.form['private_key']

		if str(r) == '<Response [200]>':

			tx_hex = response['txHex']

			asset_id = response['assetId']

			signed_tx = sign_tx(tx_hex, tx_key)

			tx_id = broadcast_tx(signed_tx)

			posts.insert({'bitcoin_address':my_address, 'asset_id':asset_id, 'tx_id':tx_id})

			return render_template("issuance.html", name=name, image=image, ticket_price=ticket_price, description=description, issued_amount=issued_amount)

		else:
			error = "Error issuing ticket, not enough funds to cover issue."


	return render_template("issue.html", error=error)


def sign_tx(tx_hex, tx_key):

	tx_structure = deserialize(tx_hex)

	for i in range(0, len(tx_structure['ins'])):

		tx_hex = sign(tx_hex, i, tx_key)

	signed_tx = tx_hex

	return signed_tx

def broadcast_tx(signed_tx):

	#pdb.set_trace()

	payload = { 'txHex':signed_tx }

	r = requests.post('http://testnet.api.coloredcoins.org:80/v2/broadcast', data=json.dumps(payload), headers={'Content-Type':'application/json'})

	response = r.json()

	tx_id = response['txid']

	return tx_id


# Check coin balance
@app.route('/check_ticket_issuer', methods=['GET', 'POST'])
@login_required
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
@login_required
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


@app.route('/ticket_id/<asset_id>')
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


