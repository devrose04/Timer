# password_reset.py

import secrets
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from flask import jsonify
from datetime import datetime, timedelta
import random

# Assuming you have a database connection
# from your_database_module import db
reset_codes = {}

def generate_reset_code(email):
    code = random.randint(1000, 9999)
    reset_codes[email] = code
    return code

def send_reset_email(email, reset_code):
    sender_email = "bffnutley@gmail.com"
    sender_password = "drge nljs fown hsdj"

    message = MIMEMultipart("alternative")
    message["Subject"] = "Password Reset for BFF Timer"
    message["From"] = sender_email
    message["To"] = email

    text = f"""
    Hello,

    You have requested to reset your password for BFF Timer.
    Your password reset code is: {reset_code}

    If you did not request this reset, please ignore this email.

    Best regards,
    BFF Timer Team
    """

    html = f"""
    <html>
      <body>
        <p>Hello,</p>
        <p>You have requested to reset your password for BFF Timer.</p>
        <p>Your password reset code is: <strong>{reset_code}</strong></p>
        <p>If you did not request this reset, please ignore this email.</p>
        <p>Best regards,<br>BFF Timer Team</p>
      </body>
    </html>
    """

    part1 = MIMEText(text, "plain")
    part2 = MIMEText(html, "html")

    message.attach(part1)
    message.attach(part2)

    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, email, message.as_string())

def handle_password_reset_request(email):
    # Check if the email exists in your database
    # user = db.users.find_one({"email": email})
    # if not user:
    #     return jsonify({"success": False, "message": "Email not found"}), 404

    reset_code = generate_reset_code(email)
    expiration_time = datetime.utcnow() + timedelta(hours=1)

    # Store the reset code and expiration time in your database
    # db.reset_codes.insert_one({
    #     "email": email,
    #     "reset_code": reset_code,
    #     "expiration_time": expiration_time
    # })

    try:
        send_reset_email(email, reset_code)
        return jsonify({"success": True, "message": "Password reset code sent"}), 200
    except Exception as e:
        print(f"Error sending email: {e}")
        return jsonify({"success": False, "message": "Error sending email"}), 500

# Flask route to handle the password reset request
# from flask import request
# 
# @app.route('/reset_password', methods=['POST'])
# def reset_password():
#     email = request.json.get('email')
#     if not email:
#         return jsonify({"success": False, "message": "Email is required"}), 400
#     return handle_password_reset_request(email)