import random, hashlib
from django.core.mail import send_mail
from datetime import timedelta
from django.utils import timezone
from django.utils.timezone import now

def generate_otp():
    return str(random.randint(100000, 999999))

def hash_otp(otp):
    return hashlib.sha256(otp.encode()).hexdigest()

def send_otp_email(email, otp):
    send_mail(
        "Your OTP Code",
        f"Your OTP is {otp}. It is valid for 10 minutes.",
        "noreply@example.com",
        [email],
    )