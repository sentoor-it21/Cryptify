from flask_session import Session  # Install flask_session package using pip
from flask import Flask, render_template, abort,request, session, redirect, url_for, jsonify,send_file
from flask import jsonify

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from tinyec import registry, ec
import tinyec
import os
import secrets
import requests


from scripts.ecc import derive_symmetric_key, encrypt_message, decrypt_message,curve
from scripts.image_ecc import derive_symmetric_key, encrypt_image, decrypt_image,curve
from scripts.video_ecc import ecc_point_to_256_bit_key,derive_symmetric_key, encrypt_video, decrypt_video,curve
from google_auth_oauthlib.flow import Flow
from scripts.file_ecc import encrypt_file, decrypt_file
from scripts.audio import encrypt_audio, decrypt_audio
import pathlib

from pymongo import MongoClient


MONGO_URI = "mongodb://localhost:27017/yourdatabase"

client = MongoClient(MONGO_URI)


db = client['yourdatabase']


app = Flask(__name__)
app.secret_key = "Flask Login APP"

cert_path = 'ssl/cert.pem'
key_path = 'ssl/key.pem'

if not os.path.exists(cert_path) or not os.path.exists(key_path):
    # Generate a self-signed certificate if not already generated
    from OpenSSL import crypto
    from datetime import datetime, timedelta

    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, 2048)

    cert = crypto.X509()
    cert.get_subject().CN = "localhost"
    cert.set_serial_number(1000)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(10 * 365 * 24 * 60 * 60)  # 10 years validity
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(k)
    cert.sign(k, "sha256")

    with open(cert_path, "wt") as cert_file:
        cert_file.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode("utf-8"))
    with open(key_path, "wt") as key_file:
        key_file.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k).decode("utf-8"))

# Use the SSL certificate and key
context = (cert_path, key_path)

os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"
GOOGLE_CLIENT_ID = "823245832428-ipn9jnlq69hvv1v8s7sbd7ur85j94qh9.apps.googleusercontent.com"
client_secrets_file = os.path.join(pathlib.Path(__file__).parent, "client_secret.json")

flow = Flow.from_client_secrets_file(
    client_secrets_file=client_secrets_file,
    scopes=["https://www.googleapis.com/auth/userinfo.profile","https://www.googleapis.com/auth/userinfo.email","openid"],
    redirect_uri="https://127.0.0.1:5000/home"
    )

def login_is_required(function):
    def wrapper(*args, **kwargs):
        if "google_id" not in session:
            return abort(401)
        else:
            return function()
    return wrapper

app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

@app.route("/login")
def login():
    authorization_url, state = flow.authorization_url()
    session["state"] = state
    session["google_id"] = "ajsdl"
    return redirect(authorization_url)


@app.route('/get_users', methods=['GET'])
def get_users():
    users_data = db.users.find({}, {'_id': 0, 'username': 1})
    users = [user['username'] for user in users_data]
    return jsonify(users)

@app.route('/get_public_keys', methods=['GET'])
def get_public_keys():
    try:
        username = request.args.get('username')

        user_keys = db.keys.find_one({'username': username}, {'_id': 0, 'public_key_x': 1, 'public_key_y': 1})

        if user_keys:
            print(user_keys)
            return jsonify(user_keys)
        else:
            return jsonify({'error': 'User not found'})
    except Exception as e:
        print(f"Error fetching public keys: {e}")
        return jsonify({"error": "An error occurred while fetching public keys"}), 500

@app.route("/home")
def callback():
    # Validate state parameter to prevent CSRF attacks
    if not session.get("state") == request.args.get("state"):
        abort(400)  # Invalid state parameter, handle accordingly

    # Fetch user profile information from Google API
    flow.fetch_token(authorization_response=request.url)
    credentials = flow.credentials

    user_info_response = requests.get(
        "https://www.googleapis.com/oauth2/v1/userinfo",
        headers={"Authorization": f"Bearer {credentials.token}"}
    )

    if user_info_response.status_code == 200:
        user_info = user_info_response.json()
        google_id = user_info.get("id")

        # Check if user already exists in the database
        existing_user = db.users.find_one({"google_id": google_id})

        if existing_user:
            username = existing_user.get("username")
            profile_picture_url = user_info.get("picture")
            session['username'] = username
            session['profile_picture_url'] = profile_picture_url
        else:
            username = user_info.get("name", "User")
            profile_picture_url = user_info.get("picture")

            # Save user information to MongoDB
            session['username'] = username
            session['profile_picture_url'] = profile_picture_url
            user_data = {
                "username": username,
                "profile_picture_url": profile_picture_url,
                "google_id": google_id
            }
            db.users.insert_one(user_data)

        return render_template('profile.html', username=session.get('username'), profile_picture_url=session.get('profile_picture_url'))
    else:
        return "Failed to fetch user information"

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

@app.route("/protected_area")
@login_is_required
def protected_area():
    return "Protected! <a href='/logout'><button>Logout</button></a>" 

@app.route('/')
def index():
    public_key_x = session.get('public_key_x')
    public_key_y = session.get('public_key_y')
    return render_template('index.html', public_key_x=public_key_x, public_key_y=public_key_y)

@app.route('/generate_key_pair', methods=['GET', 'POST'])
def generate_key_pair():
    curve = registry.get_curve('brainpoolP256r1')
    username = session.get('username')
    existing_user = db.keys.find_one({'username': username})

    if not existing_user:
        private_key = secrets.randbelow(curve.field.n)
        public_key = private_key * curve.g
        pub_key_x = str(public_key.x)  # Convert to string
        pub_key_y = str(public_key.y)  # Convert to string
        private_key_str = str(private_key)  # Convert to string

        key_data = {
            'public_key_x': pub_key_x,
            'public_key_y': pub_key_y,
            'private_key': private_key_str,
            'username': username
        }

        db.keys.insert_one(key_data)

        session['public_key_x'] = pub_key_x
        session['public_key_y'] = pub_key_y
        session['private_key'] = private_key_str

    return render_template('profile.html', username=username, profile_picture_url=session.get('profile_picture_url'))

@app.route('/audio_page', methods=['GET', 'POST'])
def audio_page():
    return render_template('audio_page.html')

@app.route('/image_page1', methods=['GET', 'POST'])
def image_page1():
    return render_template('image_page.html')

@app.route('/video_page1', methods=['GET', 'POST'])
def video_page1():
    return render_template('video_page.html')

@app.route('/file_page', methods=['GET', 'POST'])
def file_page():
    return render_template('file_page.html')

@app.route('/text_page1', methods=['GET', 'POST'])
def text_page1():
    return render_template('text_page.html')

@app.route('/get_private_key', methods=['GET'])
def get_private_key():
    username = session.get('username')

    user_private_key = db.keys.find_one({'username': username}, {'_id': 0, 'private_key': 1})

    if user_private_key:
        return jsonify(user_private_key)
    else:
        return jsonify({'error': 'User not found'})

@app.route('/text_page', methods=['GET', 'POST'])
def text_page():
    result = None
    if request.method == 'POST':

        # Retrieve form data
        choice = int(request.form['choice'])
        message = request.form['input_text']
        pub_key_x = int(request.form['pub_keyX'])
        pub_key_y = int(request.form['pub_keyY'])
        
        username = session.get('username')

        user_private_key_data = db.keys.find_one({'username': username}, {'_id': 0, 'private_key': 1})

        if user_private_key_data:
            user_private_key = int(user_private_key_data['private_key'])
        else:
            user_private_key = None  # Handle the case when user_private_key is not found

        prvt_key = user_private_key
        
        # Call your Python script functions
        public_key = ec.Point(curve, pub_key_x, pub_key_y)
        private_key = prvt_key
        symmetric_key = derive_symmetric_key(public_key, private_key)

        if choice == 1:  # Encrypt
            ciphertext = encrypt_message(symmetric_key, message)
            result = f"Ciphertext: {ciphertext.hex()}"
        elif choice == 2:  # Decrypt
            try:
                ciphertext = bytes.fromhex(message)
                decrypted_message = decrypt_message(symmetric_key, ciphertext)
                result = f"Decrypted Message: {decrypted_message}"
            except:
                result = "Invalid hex format or key."

        return render_template('text_page.html', result=result)  # Return the result as plain text response

    return render_template('text_page.html', result=result)

@app.route('/image_page', methods=['GET', 'POST'])
def image_page():

    if request.method == 'POST':
        choice = int(request.form['choice'])
        pub_key_x = int(request.form['pub_keyX'])
        pub_key_y = int(request.form['pub_keyY'])
        
        username = session.get('username')

        user_private_key_data = db.keys.find_one({'username': username}, {'_id': 0, 'private_key': 1})

        if user_private_key_data:
            user_private_key = int(user_private_key_data['private_key'])
        else:
            user_private_key = None  # Handle the case when user_private_key is not found

        private_key = user_private_key

        public_key = ec.Point(curve, pub_key_x, pub_key_y)
        symmetric_key = derive_symmetric_key(public_key, private_key)
        input_image = request.files['input_image']

        if choice == 1:  # Encrypt
            
            if input_image:
                image_data = input_image.read()
                encrypted_image = encrypt_image(symmetric_key, image_data)
                output_path = 'static/encrypted_image' + os.path.splitext(input_image.filename)[1]
                with open(output_path, 'wb') as file:
                    file.write(encrypted_image)
                response = send_file(output_path, as_attachment=True)
                response.headers['Content-Length'] = os.path.getsize(output_path)
                return response        

        elif choice == 2:  # Decrypt
            encrypted_image = request.files['input_image'].read()
            if encrypted_image:

                decrypted_image_data = decrypt_image(symmetric_key, encrypted_image)

                output_path = 'static/decrypted_image' + os.path.splitext(input_image.filename)[1]
                with open(output_path, 'wb') as file:
                    file.write(decrypted_image_data)

                output_path = 'static/decrypted_image' + os.path.splitext(input_image.filename)[1]
                response = send_file(output_path, as_attachment=True)
                response.headers['Content-Length'] = os.path.getsize(output_path)
                return response

    return render_template('image_page.html', message=None)

@app.route('/video_page', methods=['GET', 'POST'])
def video_page():

    if request.method == 'POST':
        choice = int(request.form['choice'])
        pub_key_x = int(request.form['pub_keyX'])
        pub_key_y = int(request.form['pub_keyY'])
        
        username = session.get('username')

        user_private_key_data = db.keys.find_one({'username': username}, {'_id': 0, 'private_key': 1})

        if user_private_key_data:
            user_private_key = int(user_private_key_data['private_key'])
        else:
            user_private_key = None  # Handle the case when user_private_key is not found

        private_key = user_private_key

        public_key = ec.Point(curve, pub_key_x, pub_key_y)
        symmetric_key = derive_symmetric_key(public_key, private_key)
        input_image = request.files['input_video']

        if choice == 1:  # Encrypt
            
            if input_image:
                image_data = input_image.read()
                encrypted_image = encrypt_video(symmetric_key, image_data)
                output_path = 'static/encrypted_video' + os.path.splitext(input_image.filename)[1]
                with open(output_path, 'wb') as file:
                    file.write(encrypted_image)
                response = send_file(output_path, as_attachment=True)
                response.headers['Content-Length'] = os.path.getsize(output_path)
                return response        

        elif choice == 2:  # Decrypt
            encrypted_image = request.files['input_video'].read()
            if encrypted_image:

                decrypted_image_data = decrypt_video(symmetric_key, encrypted_image)

                output_path = 'static/decrypted_video' + os.path.splitext(input_image.filename)[1]
                with open(output_path, 'wb') as file:
                    file.write(decrypted_image_data)

                output_path = 'static/decrypted_video' + os.path.splitext(input_image.filename)[1]
                response = send_file(output_path, as_attachment=True)
                response.headers['Content-Length'] = os.path.getsize(output_path)
                return response

    return render_template('video_page.html', message=None)

@app.route('/file_page1', methods=['GET', 'POST'])
def file_page1():
    if request.method == 'POST':
        choice = int(request.form['choice'])
        pub_key_x = int(request.form['pub_keyX'])
        pub_key_y = int(request.form['pub_keyY'])
        
        username = session.get('username')

        user_private_key_data = db.keys.find_one({'username': username}, {'_id': 0, 'private_key': 1})

        if user_private_key_data:
            user_private_key = int(user_private_key_data['private_key'])
        else:
            user_private_key = None  # Handle the case when user_private_key is not found

        private_key = user_private_key

        public_key = ec.Point(curve, pub_key_x, pub_key_y)
        symmetric_key = derive_symmetric_key(public_key, private_key)
        input_file = request.files['input_file']

        if choice == 1:  # Encrypt
            if input_file:
                file_data = input_file.read()
                encrypted_file = encrypt_file(symmetric_key, file_data)
                output_path = 'static/encrypted_file' + os.path.splitext(input_file.filename)[1]
                with open(output_path, 'wb') as file:
                    file.write(encrypted_file)
                response = send_file(output_path, as_attachment=True)
                response.headers['Content-Length'] = os.path.getsize(output_path)
                return response        

        elif choice == 2:  # Decrypt
            decrypted_file = request.files['input_file'].read()
            if decrypted_file:
                decrypted_file_data = decrypt_file(symmetric_key, decrypted_file)
                output_path = 'static/decrypted_file' + os.path.splitext(input_file.filename)[1]
                with open(output_path, 'wb') as file:
                    file.write(decrypted_file_data)

                output_path = 'static/decrypted_file' + os.path.splitext(input_file.filename)[1]
                response = send_file(output_path, as_attachment=True)
                response.headers['Content-Length'] = os.path.getsize(output_path)
                return response

    return render_template('file_page.html')

@app.route('/audio_page1', methods=['GET', 'POST'])
def audio_page1():
    if request.method == 'POST':
        choice = int(request.form['choice'])
        pub_key_x = int(request.form['pub_keyX'])
        pub_key_y = int(request.form['pub_keyY'])
        
        username = session.get('username')

        user_private_key_data = db.keys.find_one({'username': username}, {'_id': 0, 'private_key': 1})

        if user_private_key_data:
            user_private_key = int(user_private_key_data['private_key'])
        else:
            user_private_key = None  # Handle the case when user_private_key is not found

        private_key = user_private_key

        public_key = ec.Point(curve, pub_key_x, pub_key_y)
        symmetric_key = derive_symmetric_key(public_key, private_key)
        input_image = request.files['input_audio']

        if choice == 1:  # Encrypt
            
            if input_image:
                image_data = input_image.read()
                encrypted_image = encrypt_audio(symmetric_key, image_data)
                output_path = 'static/encrypted_audio' + os.path.splitext(input_image.filename)[1]
                with open(output_path, 'wb') as file:
                    file.write(encrypted_image)
                response = send_file(output_path, as_attachment=True)
                response.headers['Content-Length'] = os.path.getsize(output_path)
                return response        

        elif choice == 2:  # Decrypt
            encrypted_image = request.files['input_audio'].read()
            if encrypted_image:

                decrypted_image_data = decrypt_audio(symmetric_key, encrypted_image)

                output_path = 'static/decrypted_audio' + os.path.splitext(input_image.filename)[1]
                with open(output_path, 'wb') as file:
                    file.write(decrypted_image_data)

                output_path = 'static/decrypted_audio' + os.path.splitext(input_image.filename)[1]
                response = send_file(output_path, as_attachment=True)
                response.headers['Content-Length'] = os.path.getsize(output_path)
                return response

    return render_template('audio_page.html')


if __name__ == '__main__':
    app.run(debug=True, ssl_context=context)