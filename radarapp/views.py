from django.shortcuts import render
from django.conf import settings
from rest_framework import status
from rest_framework.decorators import api_view
from rest_framework.response import Response
from .models import UserTicket, UserProfile, UserWallet, Users, VerificationToken, Transaction, Driver, RadarTicket, Notification
from .serializers import UserSerializer, DriverSerializer
from django.contrib.auth import authenticate
from django.contrib.auth.models import update_last_login
from django.db import transaction
from django.views.decorators.csrf import csrf_exempt
from django.core.mail import send_mail
from django.utils.crypto import get_random_string
from django.http import HttpRequest, JsonResponse
from django.contrib.auth.hashers import check_password, make_password
import paystack
import requests
import json
import random
import string
from datetime import datetime
from django.utils import timezone
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
import io
import qrcode
from django.http import HttpResponse
from concurrent.futures import ThreadPoolExecutor
import logging
from decimal import Decimal
import os
from django.core.files import File
from django.shortcuts import get_object_or_404
from django.core.exceptions import ValidationError
import face_recognition
import numpy as np
from PIL import Image
import io
from django.db import transaction as db_transaction
import uuid


paystack_secret_key = 'sk_test_c70a285be29337a0697e19864e3665adb79cfc37'
paystack.api_key = paystack_secret_key

logger = logging.getLogger(__name__)
# Create your views here.


def index(request):
    return HttpResponse("<h1>hello world</h1>", request)


executor = ThreadPoolExecutor(max_workers=10)


def get_random_avatar(avatars_dir):
    avatars = os.listdir(avatars_dir)
    if avatars:
        selected_avatar = random.choice(avatars)
        return os.path.join(avatars_dir, selected_avatar)
    return None


def generate_unique_reference_number():
    # Generate a unique reference number using UUID and take a substring
    reference_number = str(uuid.uuid4().hex[:20].upper())  # 20 characters from UUID
    # Ensure the reference number is unique in the Transaction model
    while Transaction.objects.filter(reference_number=reference_number).exists():
        reference_number = str(uuid.uuid4().hex[:20].upper())
    return reference_number


def create_user(data):
    serializer = UserSerializer(data=data)
    if serializer.is_valid():
        user = serializer.save()
        return {'status': 'success', 'user': user}
    else:
        return {'status': 'error', 'errors': serializer.errors}

def create_driver(data):
    serializer = DriverSerializer(data=data)
    if serializer.is_valid():
        driver = serializer.save()
        return {'status': 'success', 'driver': driver}
    else:
        return {'status': 'error', 'errors': serializer.errors}

@api_view(['POST'])
def signup(request):
    user_type = request.data.get('user_type')
    email = request.data.get('email')

    if user_type == "user":
            # Generate a random 6-digit token
        token = ''.join(random.choices('0123456789', k=6))
    
        # Create or update the verification token for the user
        verification_token, created = VerificationToken.objects.update_or_create(
            user_email=email,
            defaults={'token': token, 'created_at': timezone.now()}
        )

        sender_email = 'habeebmuftau05@gmail.com'
        receiver_email = email
        password = 'jvbe whjo lnwe pwxu'
        subject = 'Verify Email'
        message = f'''Hi,

        Your Verification Token Is: {token}
        
        Please use it to verify your account'''

        msg = MIMEMultipart()
        msg['From'] = sender_email
        msg['To'] = receiver_email
        msg['Subject'] = subject
        msg.attach(MIMEText(message, 'plain'))

        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(sender_email, password)

        server.sendmail(sender_email, receiver_email, msg.as_string())

        server.quit()
        return Response({"status": "success", "message": "Verification token sent to email"}, status=status.HTTP_200_OK)

        
        # future = executor.submit(create_user, data)
    elif user_type == "driver":
        # future = executor.submit(create_driver, data)
        pass
    else:
        return Response({'status': 'error', 'message': 'Invalid user type'}, status=status.HTTP_400_BAD_REQUEST)


def create_user_wallet(user):
    user_wallet = UserWallet.objects.create(user=user)
    user_wallet.save()
    return "Wallet created successfully"


@api_view(['POST'])
def verify_token(request):
    email = request.data.get('email')
    token = request.data.get('token')
    
    try:
        verification_token = VerificationToken.objects.get(user_email=email)
        
        if verification_token.token == token and verification_token.is_valid():
            data = request.data.copy()
            if 'password' in data:
                data['password'] = make_password(data['password'])
            
            serializer = UserSerializer(data=data)
            if serializer.is_valid():
                result = create_user(data)
                if result['status'] == 'success':
                    user = result['user']
                    
                    create_user_wallet(user=user)
                    
                    # Select a random profile picture
                    avatar_folder = os.path.join(settings.MEDIA_ROOT, 'avatars')
                    avatar_files = os.listdir(avatar_folder)
                    random_avatar = random.choice(avatar_files)

                    # Create UserProfile with the selected avatar
                    UserProfile.objects.create(user=user, profile_picture=f'avatars/{random_avatar}')

                    verification_token.delete()

                    return Response({'status': 'success', 'message': 'User created successfully'}, status=status.HTTP_201_CREATED)
                else:
                    return Response({'status': 'error', 'message': result['errors']}, status=status.HTTP_400_BAD_REQUEST)
            else:
                return Response({"status": "error", "message": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response({"status": "error", "message": "Invalid or expired token"}, status=status.HTTP_400_BAD_REQUEST)
    
    except VerificationToken.DoesNotExist:
        return Response({"status": "error", "message": "Token does not exist"}, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
def login(request):
    username_or_email = request.data.get('username_or_email')
    password = request.data.get('password')

    # Authenticate user with either username or email
    user = authenticate(request, username=username_or_email, password=password)
    
    if user is not None:
        # User is authenticated, return success response
        update_last_login(None, user)
        return Response({
                    "status": "success", 
                    "message": "Login successful",
                    "user_id": user.user_id,
                    "email": user.email
                }, status=status.HTTP_200_OK)    
    else:
        # Authentication failed, return error response
        return Response({"status": "error", 'message': 'Invalid username/email or password'}, status=status.HTTP_401_UNAUTHORIZED)


@api_view(['POST'])
def forgot_password(request):
    email = request.data.get('email')
    
    if not email:
        return Response({"error": "Email is required"}, status=status.HTTP_400_BAD_REQUEST)
    
    # Generate a random 6-digit token
    token = ''.join(random.choices('0123456789', k=6))
    
    # Create or update the verification token for the user
    verification_token, created = VerificationToken.objects.update_or_create(
        user_email=email,
        defaults={'token': token, 'created_at': timezone.now()}
    )
    
    # Send email with the token
    sender_email = 'habeebmuftau05@gmail.com'
    receiver_email = email
    password = 'jvbe whjo lnwe pwxu'  # Use environment variables for sensitive information
    subject = 'Verify Email'
    message = f'''Hi,

    Your Verification Token Is: {token}
    
    Please use it to verify your account'''

    # try:
    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = receiver_email
    msg['Subject'] = subject
    msg.attach(MIMEText(message, 'plain'))

    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.starttls()
    server.login(sender_email, password)
    server.sendmail(sender_email, receiver_email, msg.as_string())
    server.quit()
    # except Exception as e:
    #     logger.error(f"Failed to send email to {email}: {str(e)}")
    #     return Response({"error": "Failed to send verification email"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    return Response({"status": "success", "message": "Password reset token sent to email"}, status=status.HTTP_200_OK)


@api_view(['POST'])
def verify_forgot_password_token(request):
    email = request.data.get('email')
    token = request.data.get('token')
    
    if not email or not token:
        return Response({"status": "error", "message": "Email and token are required"}, status=status.HTTP_400_BAD_REQUEST)
    
    try:
        verification_token = VerificationToken.objects.get(user_email=email)
        
        # Check if the token is valid
        if verification_token.token == token and verification_token.is_valid():
            # Token is valid, delete the verification token
            verification_token.delete()

            return Response({"status": "success", "message": "Token Valid"}, status=status.HTTP_202_ACCEPTED)
        else:
            return Response({"status": "error", "message": "Invalid or expired token"}, status=status.HTTP_400_BAD_REQUEST)
    
    except VerificationToken.DoesNotExist:
        return Response({"status": "error", "message": "Token does not exist"}, status=status.HTTP_400_BAD_REQUEST)
    # except Exception as e:
    #     logger.error(f"Error during token verification for {email}: {str(e)}")
    #     return Response({"error": "An error occurred during verification"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
def change_password_fp(request):
    email = request.data.get('email')
    new_password = request.data.get('new_password')
    
    if not email or not new_password:
        return Response({"status": "error", "message": "Email and new password are required"}, status=status.HTTP_400_BAD_REQUEST)
    
    try:
        user = Users.objects.get(email=email)
        user.password = make_password(new_password)
        user.save()
        
        return Response({"status": "success", "message": "Password changed successfully"}, status=status.HTTP_200_OK)
    
    except Users.DoesNotExist:
        return Response({"status": "error", "message": "User does not exist"}, status=status.HTTP_400_BAD_REQUEST)
    except Exception as e:
        logger.error(f"Failed to change password for {email}: {str(e)}")
        return Response({"status":"error", "message": "An error occurred while changing the password"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
def change_fullname(request):
    user_id = request.data.get('user_id')
    new_fullname = request.data.get('new_fullname')

    if not user_id or not new_fullname:
        return Response({'status': 'error', 'message': 'User ID and new full name are required'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        with transaction.atomic():
            user = Users.objects.select_for_update().get(user_id=user_id)
            user.full_name = new_fullname
            user.save()
        return Response({'status': 'success', 'message': 'Full name changed successfully'}, status=status.HTTP_200_OK)
    except Users.DoesNotExist:
        return Response({'status': 'error', 'message': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({'status': 'error', 'message': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
def change_username(request):
    user_id = request.data.get('user_id')
    new_username = request.data.get('new_username')

    if not user_id or not new_username:
        return Response({'status': "error", "message": "User ID and new username are required"}, status=status.HTTP_400_BAD_REQUEST)

    try:
        # Check if the new username is already in use
        if Users.objects.filter(username=new_username).exists():
            return Response({"status": "error", "message": "Username already in use"}, status=status.HTTP_400_BAD_REQUEST)

        with transaction.atomic():
            user = Users.objects.select_for_update().get(user_id=user_id)
            user.username = new_username
            user.save()

        return Response({'status': 'success', 'message': 'Username changed successfully'}, status=status.HTTP_200_OK)
    except Users.DoesNotExist:
        return Response({"status": "error", "message": "User not found"}, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({"status": "error", "message": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
def change_email(request):
    user_id = request.data.get('user_id')
    new_email = request.data.get('new_email')

    if not user_id or not new_email:
        return Response({"status": "error", "message": "User ID and new email are required"}, status=status.HTTP_400_BAD_REQUEST)

    if Users.objects.filter(email=new_email).exists():
        return Response({"status": "error", "message": "Email already in use"}, status=status.HTTP_400_BAD_REQUEST)

    token = ''.join(random.choices('0123456789', k=6))

    verification_token, created = VerificationToken.objects.update_or_create(
        user_email=new_email,
        defaults={'token': token, 'created_at': timezone.now()}
    )

    sender_email = 'habeebmuftau05@gmail.com'
    receiver_email = new_email
    password = 'jvbe whjo lnwe pwxu'
    subject = 'Verify Email'
    message = f'''Hi,

Your Verification Token Is: {token}

Please use it to verify your account'''

    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = receiver_email
    msg['Subject'] = subject
    msg.attach(MIMEText(message, 'plain'))

    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.starttls()
    server.login(sender_email, password)
    server.sendmail(sender_email, receiver_email, msg.as_string())
    server.quit()

    return Response({"status": "success", "message": "Verification token sent to email"}, status=status.HTTP_200_OK)


@api_view(['POST'])
def verify_new_email(request):
    user_id = request.data.get('user_id')
    new_email = request.data.get('new_email')
    token = request.data.get('token')

    if not user_id or not new_email or not token:
        return Response({"status": "error", "message": "User ID, new email, and token are required"}, status=status.HTTP_400_BAD_REQUEST)

    try:
        verification_token = VerificationToken.objects.get(user_email=new_email)
        
        if verification_token.token == token and verification_token.is_valid():
            with transaction.atomic():
                user = Users.objects.select_for_update().get(user_id=user_id)
                user.email = new_email
                user.save()
                verification_token.delete()

            return Response({"status": "success", "message": "Email changed successfully"}, status=status.HTTP_200_OK)
        else:
            return Response({"status": "error", "message": "Invalid or expired token"}, status=status.HTTP_400_BAD_REQUEST)
    except VerificationToken.DoesNotExist:
        return Response({"status": "error", "message": "Token does not exist"}, status=status.HTTP_400_BAD_REQUEST)
    except Users.DoesNotExist:
        return Response({"status": "error", "message": "User not found"}, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({"status": "error", "message": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


def convert_date_format(date_str):
    try:
        # Parse the input string to a datetime object
        input_date = datetime.strptime(date_str, "%d-%m-%Y")
        # Format the datetime object to the desired output string
        output_date = input_date.strftime("%Y-%m-%d")
        return output_date
    except ValueError:
        return "Invalid date format. Please use dd-mm-yyyy."


def get_ticket_price(from_loc, to_loc, trip_type):
    prices = {
        ("mushin", "costain"): 100,
        ("mushin", "ilupeju"): 150,
        ("mushin", "oshodi"): 200,
        ("mushin", "yaba"): 250,
        ("costain", "mushin"): 100,
        ("costain", "ilupeju"): 150,
        ("costain", "oshodi"): 200,
        ("costain", "yaba"): 250,
        ("ilupeju", "mushin"): 150,
        ("ilupeju", "costain"): 200,
        ("ilupeju", "oshodi"): 250,
        ("ilupeju", "yaba"): 300,
        ("oshodi", "mushin"): 200,
        ("oshodi", "costain"): 250,
        ("oshodi", "ilupeju"): 300,
        ("oshodi", "yaba"): 350,
        ("yaba", "mushin"): 250,
        ("yaba", "costain"): 300,
        ("yaba", "ilupeju"): 350,
        ("yaba", "oshodi"): 400,
    }

    if (from_loc.lower(), to_loc.lower()) in prices:
        price = prices[(from_loc.lower(), to_loc.lower())]
        if trip_type == "one_way":
            return price
        elif trip_type == "round_trip":
            price = price * 2
            price = price - (price * 0.15)
            return price
    else:
        raise ValueError("Invalid locations")


def validate_wallet_pin(user, pin):
    try:
        wallet = UserWallet.objects.get(user=user)
        return wallet.wallet_pin == pin
    except UserWallet.DoesNotExist:
        return False
    

def deduct_from_wallet(user, amount):
    if user.userwallet.balance >= amount:
        user.userwallet.balance -= amount
        user.userwallet.save()
        return True
    return False


def generate_unique_ticket_code():
    # Generate a unique ticket code using UUID and take a substring
    ticket_code = str(uuid.uuid4().hex[:8].upper())  # 8 characters from UUID
    # Ensure the ticket code is unique in the UserTicket model
    while UserTicket.objects.filter(ticket_code=ticket_code).exists():
        ticket_code = str(uuid.uuid4().hex[:8].upper())
    return ticket_code


@api_view(['POST'])
def book_ticket(request):
    trip_type = request.data.get('trip_type')
    ticket_type = request.data.get('ticket_type')
    user_id = request.data.get('user_id')
    radar_ticket_id = request.data.get('radar_ticket_id', "None")
    date_booked = request.data.get('date_booked')
    time_booked = request.data.get('time_booked')
    buy_for_self = request.data.get('buy_for_self', False)
    mp_ticket_list = request.data.get('mp_ticket_list', [])
    wallet_pin = request.data.get('wallet_pin')

    if not all([trip_type, ticket_type, user_id, radar_ticket_id, date_booked, time_booked, wallet_pin]):
        return Response({"status": "error", "message": "Missing required fields"}, status=status.HTTP_400_BAD_REQUEST)

    try:
        user = Users.objects.get(user_id=user_id)

        if not validate_wallet_pin(user, wallet_pin):
            return Response({"status": "error", "message": "Invalid wallet pin"}, status=status.HTTP_401_UNAUTHORIZED)
        
        total_amount = 0

        with db_transaction.atomic():
            def create_ticket(user, radar_ticket, trip_type, date_booked, time_booked, ticket_type, num_of_tickets_bought=None, bought_by=None):
                return UserTicket.objects.create(
                    user=user,
                    radar_ticket=radar_ticket,
                    trip_type=trip_type,
                    date_booked=date_booked,
                    time_booked=time_booked,
                    ticket_type=ticket_type,
                    num_of_tickets_bought=num_of_tickets_bought,
                    bought_by=bought_by,
                    ticket_code=generate_unique_ticket_code()
                )

            def create_transaction(user, amount, transaction_type, sender=None, receiver=None):
                Transaction.objects.create(
                    user=user,
                    amount=amount,
                    transaction_type=transaction_type,
                    sender=sender,
                    receiver=receiver,
                    reference=generate_unique_reference_number()
                )

            if trip_type == "one_way":
                radar_ticket = RadarTicket.objects.get(radar_ticket_id=radar_ticket_id)

                if ticket_type == "sp":
                    create_ticket(user, radar_ticket, trip_type, date_booked, time_booked, ticket_type)
                    total_amount += radar_ticket.price
                    create_transaction(user, radar_ticket.price, 'booking')
                elif ticket_type == "mp":
                    if buy_for_self:
                        num_of_tickets_bought = len(mp_ticket_list)
                        create_ticket(user, radar_ticket, trip_type, date_booked, time_booked, ticket_type, num_of_tickets_bought=num_of_tickets_bought)
                        total_amount += radar_ticket.price * num_of_tickets_bought
                        create_transaction(user, radar_ticket.price * num_of_tickets_bought, 'booking')
                    
                    for mp_ticket in mp_ticket_list:
                        radar_ticket = RadarTicket.objects.get(radar_ticket_id=mp_ticket['radar_ticket_id'])
                        create_ticket(
                            Users.objects.get(user_id=mp_ticket['user_id']),
                            radar_ticket,
                            trip_type,
                            mp_ticket['date_booked'],
                            mp_ticket['time_booked'],
                            ticket_type,
                            bought_by=user
                        )
                        create_transaction(
                            Users.objects.get(user_id=mp_ticket['user_id']),
                            radar_ticket.price,
                            'booking',
                            sender=user,
                            receiver=Users.objects.get(user_id=mp_ticket['user_id'])
                        )
                        total_amount += radar_ticket.price

            elif trip_type == "round_trip":
                radar_ticket1 = RadarTicket.objects.get(radar_ticket_id=request.data.get('radar_ticket1_id'))
                radar_ticket2 = RadarTicket.objects.get(radar_ticket_id=request.data.get('radar_ticket2_id'))

                if ticket_type == 'sp':
                    create_ticket(user, radar_ticket1, trip_type, date_booked, time_booked, ticket_type)
                    create_ticket(user, radar_ticket2, trip_type, date_booked, time_booked, ticket_type)
                    total_amount += radar_ticket1.price + radar_ticket2.price
                    create_transaction(user, radar_ticket1.price + radar_ticket2.price, 'booking')
                
                elif ticket_type == 'mp':
                    if buy_for_self:
                        num_of_tickets_bought = len(mp_ticket_list)
                        create_ticket(user, radar_ticket1, trip_type, date_booked, time_booked, ticket_type, num_of_tickets_bought=num_of_tickets_bought)
                        create_ticket(user, radar_ticket2, trip_type, date_booked, time_booked, ticket_type, num_of_tickets_bought=num_of_tickets_bought)
                        total_amount += (radar_ticket1.price + radar_ticket2.price) * num_of_tickets_bought
                        create_transaction(user, (radar_ticket1.price + radar_ticket2.price) * num_of_tickets_bought, 'booking')
                    
                    for mp_ticket in mp_ticket_list:
                        radar_ticket1 = RadarTicket.objects.get(radar_ticket_id=mp_ticket['radar_ticket1_id'])
                        radar_ticket2 = RadarTicket.objects.get(radar_ticket_id=mp_ticket['radar_ticket2_id'])
                        create_ticket(
                            Users.objects.get(user_id=mp_ticket['user_id']),
                            radar_ticket1,
                            trip_type,
                            mp_ticket['date_booked'],
                            mp_ticket['time_booked'],
                            ticket_type,
                            bought_by=user
                        )
                        create_ticket(
                            Users.objects.get(user_id=mp_ticket['user_id']),
                            radar_ticket2,
                            trip_type,
                            mp_ticket['date_booked'],
                            mp_ticket['time_booked'],
                            ticket_type,
                            bought_by=user
                        )
                        create_transaction(
                            Users.objects.get(user_id=mp_ticket['user_id']),
                            radar_ticket1.price + radar_ticket2.price,
                            'booking',
                            sender=user,
                            receiver=Users.objects.get(user_id=mp_ticket['user_id'])
                        )
                        total_amount += radar_ticket1.price + radar_ticket2.price

            # Deduct the total amount from the user's wallet
            if deduct_from_wallet(user, total_amount):
                return Response({"status": "success", "message": "Tickets booked and transactions created successfully"}, status=status.HTTP_201_CREATED)
            else:
                return Response({"status": "error", "message": "Insufficient balance"}, status=status.HTTP_402_PAYMENT_REQUIRED)
    
    except Users.DoesNotExist:
        return Response({"status": "error", "message": "User not found"}, status=status.HTTP_404_NOT_FOUND)
    except RadarTicket.DoesNotExist:
        return Response({"status": "error", "message": "RadarTicket not found"}, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({"status": "error", "message": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(["POST"])
def get_username(request):
    user_id = request.data.get("user_id")
    
    if not user_id:
        return Response({"status": "error", "message": "user_id is required"}, status=status.HTTP_400_BAD_REQUEST)

    try:
        user = Users.objects.get(user_id=user_id)
        username = user.username
        return Response({"status": "success", "message": username}, status=status.HTTP_200_OK)
    except Users.DoesNotExist:
        return Response({"status": "error", "message": "User not found"}, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({"status": "error", "message": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
def get_wallet_balance(request):
    user_id = request.data.get('user_id')
    
    if not user_id:
        return Response({"status": "error", "message": "user_id is required"}, status=status.HTTP_400_BAD_REQUEST)

    try:
        user = Users.objects.get(user_id=user_id)
    except Users.DoesNotExist:
        return Response({"status": "error", "message": "User not found"}, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({"status": "error", "message": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    try:
        wallet = UserWallet.objects.get(user=user)
        wallet_balance = wallet.wallet_balance
        return Response({"status": "success", "message": str(wallet_balance)}, status=status.HTTP_200_OK)
    except UserWallet.DoesNotExist:
        return Response({"status": "error", "message": "Wallet not found for user"}, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({"status": "error", "message": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET'])
def get_locations(request):
    locations = ['Mushin', 'Costain', 'Ilupeju', 'Yaba', 'Oshodi', 'Ikeja']
    return Response({'status': 'success', 'message': locations}, status=status.HTTP_200_OK)


@api_view(['POST'])
def get_all_transactions(request):
    user_id = request.data.get('user_id')

    if not user_id:
        return Response({"status": "error", "message": "user_id is required"}, status=status.HTTP_400_BAD_REQUEST)

    try:
        user = Users.objects.get(user_id=user_id)
    except Users.DoesNotExist:
        return Response({"status": "error", "message": "User not found"}, status=status.HTTP_404_NOT_FOUND)

    transactions = Transaction.objects.filter(user=user)

    if not transactions.exists():
        return Response({"status": "success", "message": "No transactions found"}, status=status.HTTP_200_OK)

    transactions_list = []

    for transaction in transactions:
        transaction_data = {
            'amount': str(transaction.amount),
            'transaction_date': str(transaction.transaction_date),
            'transaction_type': transaction.transaction_type,
            'status': transaction.status,
            'reference': transaction.reference
        }

        if transaction.transaction_type == 'transfer':
            if transaction.receiver:
                transaction_data.update({
                    'receiver_name': transaction.receiver.username,
                })
            transaction_data.update({
                'payment_method': transaction.payment_method,
            })
        elif transaction.transaction_type == 'deposit':
            if transaction.sender:
                transaction_data.update({
                    'sender_name': transaction.sender.username,
                })
            transaction_data.update({
                'credited_to': transaction.credited_to,
            })

        transactions_list.append(transaction_data)

    return Response({"status": "success", "transactions": transactions_list}, status=status.HTTP_200_OK)


@api_view(['POST'])
def send_money(request):
    sender_id = request.data.get('sender_id')
    receiver_username = request.data.get('receiver_username')
    amount = request.data.get('amount')
    wallet_pin = request.data.get('wallet_pin')

    if not sender_id or not receiver_username or not amount or not wallet_pin:
        return Response({"status": "error", "message": "sender_id, receiver_username, amount, and wallet_pin are required"}, status=status.HTTP_400_BAD_REQUEST)

    try:
        amount = Decimal(amount)
        if amount <= 0:
            return Response({"status": "error", "message": "Amount must be greater than zero"}, status=status.HTTP_400_BAD_REQUEST)
    except:
        return Response({"status": "error", "message": "Invalid amount"}, status=status.HTTP_400_BAD_REQUEST)

    try:
        sender = Users.objects.get(user_id=sender_id)
    except Users.DoesNotExist:
        return Response({"status": "error", "message": "Sender not found"}, status=status.HTTP_404_NOT_FOUND)

    try:
        receiver = Users.objects.get(username=receiver_username)
    except Users.DoesNotExist:
        return Response({"status": "error", "message": "Receiver not found"}, status=status.HTTP_404_NOT_FOUND)

    try:
        sender_wallet = UserWallet.objects.get(user=sender)
    except UserWallet.DoesNotExist:
        return Response({"status": "error", "message": "Sender's wallet not found"}, status=status.HTTP_404_NOT_FOUND)

    try:
        receiver_wallet = UserWallet.objects.get(user=receiver)
    except UserWallet.DoesNotExist:
        return Response({"status": "error", "message": "Receiver's wallet not found"}, status=status.HTTP_404_NOT_FOUND)

    if sender_wallet.wallet_pin != wallet_pin:
        return Response({"status": "error", "message": "Invalid wallet PIN"}, status=status.HTTP_400_BAD_REQUEST)

    if sender_wallet.wallet_balance < amount:
        return Response({"status": "error", "message": "Insufficient balance"}, status=status.HTTP_400_BAD_REQUEST)

    with db_transaction.atomic():
        # Deduct the amount from sender's wallet
        sender_wallet.wallet_balance -= amount
        sender_wallet.save()

        # Add the amount to receiver's wallet
        receiver_wallet.wallet_balance += amount
        receiver_wallet.save()

        # Generate a reference number
        reference = f'TXN-{sender.user_id}-{receiver.user_id}-{int(amount*100)}-{datetime.now().timestamp()}'

        # Record the transaction for sender
        sender_transaction = Transaction.objects.create(
            user=sender,
            amount=amount,
            transaction_type='transfer',
            status='completed',
            sender=sender,
            receiver=receiver,
            reference=reference,
            payment_method='Wallet Balance',
            credited_to='Wallet Balance'
        )

        # Record the transaction for receiver
        receiver_transaction = Transaction.objects.create(
            user=receiver,
            amount=amount,
            transaction_type='deposit',
            status='completed',
            sender=sender,
            receiver=receiver,
            reference=reference,
            payment_method='Wallet Balance',
            credited_to='Wallet Balance'
        )

    response_data = {
        "status": "success",
        "message": "Money sent successfully",
        # "transaction_details": {
        #     "sender_transaction": {
        #         "amount": str(sender_transaction.amount),
        #         "transaction_date": str(sender_transaction.transaction_date),
        #         "transaction_type": sender_transaction.transaction_type,
        #         "status": sender_transaction.status,
        #         "reference": sender_transaction.reference,
        #         "receiver_name": receiver.username,
        #         "payment_method": sender_transaction.payment_method
        #     },
        #     "receiver_transaction": {
        #         "amount": str(receiver_transaction.amount),
        #         "transaction_date": str(receiver_transaction.transaction_date),
        #         "transaction_type": receiver_transaction.transaction_type,
        #         "status": receiver_transaction.status,
        #         "reference": receiver_transaction.reference,
        #         "sender_name": sender.username,
        #         "credited_to": receiver_transaction.credited_to
        #     }
        # }
    }

    return Response(response_data, status=status.HTTP_200_OK)


@api_view(['POST'])
def change_password_logged_in(request):
    user_id = request.data.get('user_id')
    old_password = request.data.get('old_password')
    new_password = request.data.get('new_password')

    if not user_id or not old_password or not new_password:
        return Response({"status": "error", "message": "user_id, old_password, and new_password are required"}, status=status.HTTP_400_BAD_REQUEST)

    try:
        user = Users.objects.get(user_id=user_id)
    except Users.DoesNotExist:
        return Response({"status": "error", "message": "User not found"}, status=status.HTTP_404_NOT_FOUND)

    if not check_password(old_password, user.password):
        return Response({"status": "error", "message": "Old password is incorrect"}, status=status.HTTP_400_BAD_REQUEST)

    if old_password == new_password:
        return Response({"status": "error", "message": "New password cannot be the same as the old password"}, status=status.HTTP_400_BAD_REQUEST)

    user.set_password(new_password)
    user.save()
    
    update_last_login(None, user)

    return Response({"status": "success", "message": "Password changed successfully"}, status=status.HTTP_200_OK)


@api_view(['POST'])
def validate_username(request):
    username = request.data.get('username')

    if not username:
        return Response({'status': 'error', 'message': 'Username is required'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        user = Users.objects.get(username=username)
        return Response({'status': 'success', 'message': 'User exists', 'user_id': user.user_id}, status=status.HTTP_200_OK)
    except Users.DoesNotExist:
        return Response({'status': 'error', 'message': 'User does not exist'}, status=status.HTTP_404_NOT_FOUND)
    

@api_view(['POST'])
def driver_signup(request):
    try:
        # Retrieve data from the request
        fullname = request.data.get('fullname')
        username = request.data.get('username')
        email = request.data.get('email')
        password = request.data.get('password')
        profile_picture = request.FILES.get('profile_picture')

        # Check if all required fields are provided
        if not all([fullname, username, email, password]):
            return Response({'status': 'error', 'message': 'All fields except profile_picture are required.'}, status=status.HTTP_400_BAD_REQUEST)

        # Check for existing username or email
        if Driver.objects.filter(username=username).exists():
            return Response({'status': 'error', 'message': 'Username already taken.'}, status=status.HTTP_400_BAD_REQUEST)

        if Driver.objects.filter(email=email).exists():
            return Response({'status': 'error', 'message': 'Email already registered.'}, status=status.HTTP_400_BAD_REQUEST)

        # Hash the password
        hashed_password = make_password(password)

        # Create and save the new driver
        driver = Driver(
            fullname=fullname,
            username=username,
            email=email,
            password=hashed_password,
            profile_picture=profile_picture
        )
        driver.save()

        return Response({'status': 'success', 'message': 'Driver signed up successfully'}, status=status.HTTP_201_CREATED)
    
    except Exception as e:
        return Response({'status': 'error', 'message': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    

@api_view(['POST'])
def create_ticket(request):
    try:
        driver_id = request.data.get('driver_id')
        from_loc = request.data.get('from_loc')
        to_loc = request.data.get('to_loc')
        transport_date = request.data.get('transport_date')
        transport_time = request.data.get('transport_time')
        num_of_buyers = request.data.get('num_of_buyers', 12)  # Default to 12 if not provided
        ticket_status = request.data.get('status', 'upcoming')  # Default to 'upcoming' if not provided

        if not all([driver_id, from_loc, to_loc, transport_date, transport_time]):
            return Response({'status': 'error', 'message': 'All fields except num_of_buyers and status are required.'}, status=status.HTTP_400_BAD_REQUEST)

        # Check if driver exists
        driver = Driver.objects.get(driver_id=driver_id)

        # Calculate the ticket price using the helper function
        try:
            price = get_ticket_price(from_loc, to_loc, request.data.get('trip_type'))
        except ValueError as e:
            return Response({'status': 'error', 'message': str(e)}, status=status.HTTP_400_BAD_REQUEST)

        # Create RadarTicket instance
        radar_ticket = RadarTicket(
            driver_id=driver,
            from_loc=from_loc,
            to_loc=to_loc,
            transport_date=transport_date,
            transport_time=transport_time,
            num_of_buyers=num_of_buyers,
            status=ticket_status,
            price=price  # Save the calculated price in the radar ticket
        )
        radar_ticket.save()

        return Response({'status': 'success', 'message': 'Ticket created successfully', 'price': price}, status=status.HTTP_201_CREATED)
    except Driver.DoesNotExist:
        return Response({'status': 'error', 'message': 'Driver not found.'}, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({'status': 'error', 'message': str(e)}, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
def get_user_profile_pic(request):
    try:
        user_id = request.data.get('user_id')
        
        if not user_id:
            return Response({'status': 'error', 'message': 'user_id is required.'}, status=status.HTTP_400_BAD_REQUEST)

        user = get_object_or_404(Users, pk=user_id)
        user_profile = get_object_or_404(UserProfile, user=user)

        if user_profile.profile_picture:
            profile_picture_url = request.build_absolute_uri(user_profile.profile_picture.url)
        else:
            profile_picture_url = None
        
        return Response({'status': 'success', 'profile_picture_url': profile_picture_url}, status=status.HTTP_200_OK)
    except Exception as e:
        return Response({'status': 'error', 'message': str(e)}, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
def user_get_three_recent_booked_ticket(request):
    try:
        user_id = request.data.get('user_id')

        if not user_id:
            return Response({'status': 'error', 'message': 'user_id is required.'}, status=400)

        user = get_object_or_404(Users, pk=user_id)

        # Fetch the three most recent booked tickets
        recent_tickets = UserTicket.objects.filter(user_id=user).order_by('-date_booked', '-time_booked')[:3]

        # Prepare the response data
        tickets_data = []
        for ticket in recent_tickets:
            tickets_data.append({
                'ticket_id': ticket.ticket_id,
                'radar_ticket_id': ticket.radar_ticket_id_id,
                'trip_type': ticket.trip_type,
                'date_booked': ticket.date_booked,
                'time_booked': ticket.time_booked,
                'ticket_type': ticket.ticket_type,
                'bought_by': ticket.bought_by_id if ticket.bought_by else None,
                'num_of_tickets_bought': ticket.num_of_tickets_bought,
                'status': ticket.status,
                'expiration_date': ticket.expiration_date,
                'expiration_time': ticket.expiration_time
            })

        return Response({'status': 'success', 'tickets': tickets_data}, status=200)
    except Exception as e:
        return Response({'status': 'error', 'message': str(e)}, status=400)
    

@api_view(['POST'])
def check_pin_availability(request):
    user_id = request.data.get('user_id')
    
    try:
        user = Users.objects.get(user_id=user_id)
        user_wallet = UserWallet.objects.get(user=user)
        
        if user_wallet.wallet_pin:
            return Response({
                "status": "success",
                "message": "Pin is available"
            }, status=status.HTTP_200_OK)
        else:
            return Response({
                "status": "success",
                "message": "Pin not set"
            }, status=status.HTTP_200_OK)
    except Users.DoesNotExist:
        return Response({
            "status": "error",
            "message": "User does not exist"
        }, status=status.HTTP_404_NOT_FOUND)
    except UserWallet.DoesNotExist:
        return Response({
            "status": "error",
            "message": "User wallet does not exist"
        }, status=status.HTTP_404_NOT_FOUND)
    

@api_view(['POST'])
def create_wallet_pin(request):
    user_id = request.data.get('user_id')
    wallet_pin = request.data.get('wallet_pin')

    try:
        user = Users.objects.get(user_id=user_id)
        user_wallet, created = UserWallet.objects.get_or_create(user=user)

        if user_wallet.wallet_pin:
            return Response({
                "status": "error",
                "message": "Pin already exists"
            }, status=status.HTTP_400_BAD_REQUEST)

        user_wallet.wallet_pin = wallet_pin
        user_wallet.full_clean()  # Validates the model instance
        user_wallet.save()

        return Response({
            "status": "success",
            "message": "Pin created successfully"
        }, status=status.HTTP_201_CREATED)

    except Users.DoesNotExist:
        return Response({
            "status": "error",
            "message": "User does not exist"
        }, status=status.HTTP_404_NOT_FOUND)
    except ValidationError as e:
        return Response({
            "status": "error",
            "message": "Invalid pin: " + ', '.join(e.messages)
        }, status=status.HTTP_400_BAD_REQUEST)
    except Exception as e:
        return Response({
            "status": "error",
            "message": str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    

@api_view(['POST'])
def change_wallet_pin(request):
    user_id = request.data.get('user_id')
    old_pin = request.data.get('old_pin')
    new_pin = request.data.get('new_pin')

    try:
        user = Users.objects.get(user_id=user_id)
        user_wallet = UserWallet.objects.get(user=user)

        if user_wallet.wallet_pin != old_pin:
            return Response({
                "status": "error",
                "message": "Old pin is incorrect"
            }, status=status.HTTP_400_BAD_REQUEST)

        user_wallet.wallet_pin = new_pin
        user_wallet.full_clean()  # Validates the model instance
        user_wallet.save()

        return Response({
            "status": "success",
            "message": "Pin changed successfully"
        }, status=status.HTTP_200_OK)

    except Users.DoesNotExist:
        return Response({
            "status": "error",
            "message": "User does not exist"
        }, status=status.HTTP_404_NOT_FOUND)
    except UserWallet.DoesNotExist:
        return Response({
            "status": "error",
            "message": "Wallet does not exist for the user"
        }, status=status.HTTP_404_NOT_FOUND)
    except ValidationError as e:
        return Response({
            "status": "error",
            "message": "Invalid new pin: " + ', '.join(e.messages)
        }, status=status.HTTP_400_BAD_REQUEST)
    except Exception as e:
        return Response({
            "status": "error",
            "message": str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    

@api_view(['POST'])
def driver_login_with_password(request):
    driver_username = request.data.get('driver_username')
    driver_password = request.data.get('driver_password')

    try:
        driver = Driver.objects.get(username=driver_username)

        if check_password(driver_password, driver.password):
            return Response({
                "status": "success",
                "message": "Login successful"
            }, status=status.HTTP_200_OK)
        else:
            return Response({
                "status": "error",
                "message": "Incorrect password"
            }, status=status.HTTP_400_BAD_REQUEST)

    except Driver.DoesNotExist:
        return Response({
            "status": "error",
            "message": "Driver not found"
        }, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({
            "status": "error",
            "message": str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    

def get_known_face_encodings_and_names():
    # Retrieve face encodings and names from the database
    known_face_encodings = []
    known_face_names = []
    drivers = Driver.objects.all()
    
    for driver in drivers:
        if driver.profile_picture:
            image = face_recognition.load_image_file(driver.profile_picture.path)
            encoding = face_recognition.face_encodings(image)
            if encoding:
                known_face_encodings.append(encoding[0])
                known_face_names.append(driver.username)
    
    return known_face_encodings, known_face_names

@api_view(['POST'])
def driver_login_with_face_id(request):
    try:
        uploaded_file = request.FILES.get('image')
        
        if not uploaded_file:
            return Response({'status': 'error', 'message': 'No image file provided.'}, status=status.HTTP_400_BAD_REQUEST)
        
        image = Image.open(uploaded_file)
        image = np.array(image)
        
        known_face_encodings, known_face_names = get_known_face_encodings_and_names()
        
        uploaded_face_encodings = face_recognition.face_encodings(image)
        
        if not uploaded_face_encodings:
            return Response({'status': 'error', 'message': 'No faces found in the image'}, status=status.HTTP_400_BAD_REQUEST)
        
        for uploaded_face_encoding in uploaded_face_encodings:
            matches = face_recognition.compare_faces(known_face_encodings, uploaded_face_encoding)
            if True in matches:
                matched_index = matches.index(True)
                matched_name = known_face_names[matched_index]
                
                driver = Driver.objects.filter(username=matched_name).first()
                if driver:
                    return Response({'status': 'success', 'message': 'Login successful', 'driver': {'username': driver.username}}, status=status.HTTP_200_OK)
        
        return Response({'status': 'error', 'message': 'No match found'}, status=status.HTTP_404_NOT_FOUND)
    
    except Exception as e:
        return Response({'status': 'error', 'message': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    

@api_view(['POST'])
def check_user_existence_with_username(request):
    username = request.data.get('username')

    if not username:
        return Response({'status': 'error', 'message': 'Username is required'}, status=status.HTTP_400_BAD_REQUEST)

    user_exists = Users.objects.filter(username=username).exists()

    if user_exists:
        return Response({'status': 'success', 'message': 'User exists'}, status=status.HTTP_200_OK)
    else:
        return Response({'status': 'error', 'message': 'User does not exist'}, status=status.HTTP_404_NOT_FOUND)
    

@api_view(['POST'])
def get_all_booked_ticket_with_user_id(request):
    user_id = request.data.get('user_id')

    if not user_id:
        return Response({'status': 'error', 'message': 'user_id is required.'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        # Fetch all tickets associated with the provided user_id
        tickets = UserTicket.objects.filter(user_id=user_id)

        if not tickets.exists():
            return Response({'status': 'error', 'message': 'No tickets found for the given user_id.'}, status=status.HTTP_404_NOT_FOUND)

        # Serialize the ticket data
        ticket_data = []
        for ticket in tickets:
            radar_ticket = RadarTicket.objects.get(radar_ticket_id=ticket.radar_ticket_id)
            ticket_data.append({
                'ticket_id': ticket.id,
                'radar_ticket_id': ticket.radar_ticket_id,
                'trip_type': ticket.trip_type,
                'date_booked': ticket.date_booked,
                'time_booked': ticket.time_booked,
                'ticket_type': ticket.ticket_type,
                'num_of_tickets_bought': ticket.num_of_tickets_bought,
                'bought_by': ticket.bought_by,
                'ticket_code': ticket.ticket_code,
                'radar_ticket_price': radar_ticket.price
            })

        return Response({'status': 'success', 'tickets': ticket_data}, status=status.HTTP_200_OK)

    except RadarTicket.DoesNotExist:
        return Response({'status': 'error', 'message': 'RadarTicket not found for one or more tickets.'}, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({'status': 'error', 'message': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
def get_all_created_tickets_with_driver_id(request):
    driver_id = request.data.get('driver_id')

    if not driver_id:
        return Response({'status': 'error', 'message': 'driver_id is required.'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        # Fetch all tickets associated with the provided driver_id
        tickets = RadarTicket.objects.filter(driver_id=driver_id)

        if not tickets.exists():
            return Response({'status': 'error', 'message': 'No tickets found for the given driver_id.'}, status=status.HTTP_404_NOT_FOUND)

        # Serialize the ticket data
        ticket_data = [{
            'radar_ticket_id': ticket.radar_ticket_id,
            'from_loc': ticket.from_loc,
            'to_loc': ticket.to_loc,
            'price': ticket.price,
            'transport_date': ticket.transport_date,
            'transport_time': ticket.transport_time,
            'num_of_buyers': ticket.num_of_buyers,
            'status': ticket.status,
        } for ticket in tickets]

        return Response({'status': 'success', 'tickets': ticket_data}, status=status.HTTP_200_OK)

    except Exception as e:
        return Response({'status': 'error', 'message': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    

@api_view(['POST'])
def find_ride(request):
    try:
        # Retrieve data from the request
        from_loc = request.data.get('from_loc')
        to_loc = request.data.get('to_loc')
        transport_date = request.data.get('transport_date')

        # Validate required fields
        if not all([from_loc, to_loc, transport_date]):
            return Response({'status': 'error', 'message': 'All fields are required.'}, status=status.HTTP_400_BAD_REQUEST)
        
        # Validate date format
        try:
            transport_date = datetime.strptime(transport_date, '%Y-%m-%d').date()
        except ValueError:
            return Response({'status': 'error', 'message': 'Invalid date format. Use YYYY-MM-DD.'}, status=status.HTTP_400_BAD_REQUEST)
        
        # Query the RadarTicket model for matching rides
        matching_rides = RadarTicket.objects.filter(
            from_loc=from_loc,
            to_loc=to_loc,
            transport_date=transport_date
        )

        # If no rides found
        if not matching_rides.exists():
            return Response({'status': 'error', 'message': 'No rides found.'}, status=status.HTTP_404_NOT_FOUND)

        # Serialize the results
        rides_data = [{
            'driver_id': ride.driver_id.driver_id,
            'from_loc': ride.from_loc,
            'to_loc': ride.to_loc,
            'transport_date': ride.transport_date,
            'transport_time': ride.transport_time,
            'available_seats': ride.available_seats,
            'num_of_buyers': ride.num_of_buyers,
            'status': ride.status
        } for ride in matching_rides]

        return Response({'status': 'success', 'rides': rides_data}, status=status.HTTP_200_OK)
    
    except Exception as e:
        return Response({'status': 'error', 'message': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    

@api_view(['POST'])
def confirm_ticket_code(request):
    try:
        # Retrieve data from the request
        driver_id = request.data.get('driver_id')
        radar_ticket_id = request.data.get('radar_ticket_id')
        ticket_code = request.data.get('ticket_code')

        # Validate required fields
        if not all([driver_id, radar_ticket_id, ticket_code]):
            return Response({'status': 'error', 'message': 'All fields are required.'}, status=status.HTTP_400_BAD_REQUEST)

        # Verify that the ticket exists and matches the provided details
        try:
            ticket = UserTicket.objects.get(
                ticket_code=ticket_code,
                radar_ticket_id=radar_ticket_id,
                radar_ticket_id__driver_id=driver_id  # Ensure the ticket is for the given driver
            )
        except UserTicket.DoesNotExist:
            return Response({'status': 'error', 'message': 'Invalid ticket code or mismatch with radar ticket or driver.'}, status=status.HTTP_404_NOT_FOUND)

        # Check if the ticket is already confirmed
        if ticket.status == 'Confirmed':
            return Response({'status': 'error', 'message': 'Ticket is already confirmed.'}, status=status.HTTP_400_BAD_REQUEST)

        # Update ticket status to 'Confirmed'
        ticket.status = 'Confirmed'
        ticket.save()

        return Response({'status': 'success', 'message': 'Ticket confirmed successfully'}, status=status.HTTP_200_OK)
    
    except Exception as e:
        return Response({'status': 'error', 'message': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    

@api_view(['POST'])
def get_all_user_notifications(request):
    user_id = request.data.get('user_id')

    try:
        user = Users.objects.get(user_id=user_id)
        notifications = Notification.objects.filter(user=user).order_by('-created_at')
        notifications_data = [
            {
                'title': notification.title,
                'message': notification.message,
                'created_at': notification.created_at,
                'is_read': notification.is_read,
                'notif_type': notification.notif_type
            } for notification in notifications
        ]
        return Response({"status": "success", "notifications": notifications_data}, status=status.HTTP_200_OK)
    except Users.DoesNotExist:
        return Response({"status": "error", "message": "User not found"}, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({"status": "error", "message": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    

@api_view(['POST'])
def get_username_and_prof_pic_of_users_i_sent_money_to(request):
    try:
        user_id = request.data.get('user_id')
        
        if not user_id:
            return Response({'status': 'error', 'message': 'user_id is required.'}, status=status.HTTP_400_BAD_REQUEST)

        user = get_object_or_404(Users, pk=user_id)

        sent_transfers = Transaction.objects.filter(sender=user).select_related('receiver')

        users_info = []
        unique_receivers = set()

        for transfer in sent_transfers:
            receiver = transfer.receiver
            if receiver and receiver.username not in unique_receivers:
                unique_receivers.add(receiver.username)
                user_profile = UserProfile.objects.filter(user=receiver).first()
                profile_picture_url = request.build_absolute_uri(user_profile.profile_picture.url) if user_profile and user_profile.profile_picture else None
                users_info.append({
                    'username': receiver.username,
                    'profile_picture_url': profile_picture_url
                })

        return Response({'status': 'success', 'users_info': users_info}, status=status.HTTP_200_OK)
    except Exception as e:
        return Response({'status': 'error', 'message': str(e)}, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
def driver_confirm_user_ticket_code(request):
    radar_ticket_id = request.data.get('radar_ticket_id')
    ticket_code = request.data.get('ticket_code')

    if not all([radar_ticket_id, ticket_code]):
        return Response({"status": "error", "message": "All fields are required"}, status=status.HTTP_400_BAD_REQUEST)

    try:
        radar_ticket = RadarTicket.objects.get(radar_ticket_id=radar_ticket_id)
    except RadarTicket.DoesNotExist:
        return Response({"status": "error", "message": "Radar ticket not found"}, status=status.HTTP_404_NOT_FOUND)

    try:
        user_ticket = UserTicket.objects.get(
            radar_ticket=radar_ticket,
            ticket_code=ticket_code
        )
    except UserTicket.DoesNotExist:
        return Response({"status": "error", "message": "Ticket code not found for this radar ticket"}, status=status.HTTP_404_NOT_FOUND)

    if user_ticket.status != 'Pending':
        return Response({"status": "error", "message": "Ticket has already been used or is invalid"}, status=status.HTTP_400_BAD_REQUEST)

    # Optionally, you can update the ticket status to 'Used' or any other appropriate status
    user_ticket.status = 'Used'
    user_ticket.save()

    return Response({"status": "success", "message": "Ticket code confirmed successfully"}, status=status.HTTP_200_OK)


@api_view(['POST'])
def topup_wallet(request):
    amount = request.data.get("amount")
    user_id = request.data.get("user_id")

    if not amount or not user_id:
        return Response({"error": "Amount and user_id are required"}, status=status.HTTP_400_BAD_REQUEST)

    amount_in_kobo = int(float(amount) * 100)

    try:
        user = Users.objects.get(user_id=user_id)
        email = user.email
    except Users.DoesNotExist:
        return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)

    url = "https://api.paystack.co/transaction/initialize"
    payload = json.dumps({
        "email": email,
        "amount": amount_in_kobo,
    })
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer sk_test_c70a285be29337a0697e19864e3665adb79cfc37'
    }

    response = requests.post(url, headers=headers, data=payload)
    response_data = response.json()

    if response.status_code == 200 and response_data['status']:
        data = response_data['data']
        reference = data['reference']
        access_code = data['access_code']
        authorization_url = data['authorization_url']

        Transaction.objects.create(
            user=user,
            reference=reference,
            transaction_type='deposit',
            status='pending',
            access_code=access_code,
            email=email,
            amount=Decimal(amount),
        )

        return Response({"status": "success", "authorization_url": authorization_url, "access_code": access_code, "reference": reference, "amount": amount}, status=status.HTTP_200_OK)
    else:
        return Response({"status": "error", "message": response_data.get('message', 'Error initializing transaction')}, status=response.status_code)


@api_view(['POST'])
def verify_payment(request):
    reference = request.data.get('reference')
    amount = request.data.get('amount')

    if not reference or not amount:
        return Response({'error': 'Reference and amount are required.'}, status=status.HTTP_400_BAD_REQUEST)

    url = f"https://api.paystack.co/transaction/verify/{reference}"
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer sk_test_c70a285be29337a0697e19864e3665adb79cfc37'
    }

    response = requests.get(url, headers=headers)
    response_data = response.json()

    if response.status_code == 200:
        if response_data['status'] and response_data['data']['amount'] == int(amount) * 100:
            try:
                with transaction.atomic():
                    transaction = Transaction.objects.select_for_update().get(reference=reference)

                    if transaction.status == 'success':
                        return Response({'message': 'Payment already verified.'}, status=status.HTTP_200_OK)

                    transaction.status = 'success'
                    transaction.save()

                    user = transaction.user
                    wallet = UserWallet.objects.select_for_update().get(user=user)
                    wallet.wallet_balance += Decimal(amount)
                    wallet.save()

                return Response({'message': 'Payment verified successfully.'}, status=status.HTTP_200_OK)
            except Transaction.DoesNotExist:
                return Response({'error': 'Transaction not found'}, status=status.HTTP_404_NOT_FOUND)
            except UserWallet.DoesNotExist:
                return Response({'error': 'Wallet not found'}, status=status.HTTP_404_NOT_FOUND)
            except Exception as e:
                return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            return Response({'error': 'Payment verification failed.'}, status=status.HTTP_400_BAD_REQUEST)
    else:
        return Response({'error': 'Failed to verify payment.'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)