from django.shortcuts import render
from django.conf import settings
from rest_framework import status
from rest_framework.decorators import api_view
from rest_framework.response import Response
from .models import Ticket, UserProfile, UserWallet, Users, VerificationToken, Transaction
from .serializers import UserSerializer, DriverSerializer
from django.contrib.auth import authenticate
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

logger = logging.getLogger(__name__)
# Create your views here.


def index(request):
    return HttpResponse("<h1>hello world</h1>", request)


executor = ThreadPoolExecutor(max_workers=10)

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
        
        # Check if the token is valid
        if verification_token.token == token and verification_token.is_valid():
            # Token is valid, create user and user profile
            data = request.data.copy()
            if 'password' in data:
                data['password'] = make_password(data['password'])
            
            serializer = UserSerializer(data=data)
            if serializer.is_valid():
                result = create_user(data)
                if result['status'] == 'success':
                    user = result['user']

                    UserProfile.objects.create(user=user)

                    # Create User wallet
                    create_user_wallet(user=user)

                    # Delete the used token
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
        return Response({"status": "success", 'message': 'Login successful'}, status=status.HTTP_200_OK)
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


# @api_view(['POST'])
# def book_ticket(request):
#     user_id = request.data.get('user_id')
#     trip_type = request.data.get('trip_type')
#     from_loc = request.data.get('from_loc')
#     to_loc = request.data.get('to_loc')
#     transport_date = request.data.get('transport_date')
#     price = request.data.get('price')

#     if None in [user_id, trip_type, from_loc, to_loc, transport_date, price]:
#         return Response({"status": 'error', "message": 'Missing required fields'}, status=status.HTTP_400_BAD_REQUEST)

#     try:
#         user = Users.objects.get(user_id=user_id)
#     except Users.DoesNotExist:
#         return Response({"status": 'error', 'message': 'User does not exist'}, status=status.HTTP_404_NOT_FOUND)

#     if trip_type == 'one_way':
#         with transaction.atomic():
#             try:
#                 wallet = UserWallet.objects.select_for_update().get(user_id=user_id)
#                 if wallet.wallet_balance < price:
#                     return Response({'status': 'error', 'message': 'Insufficient funds'}, status=status.HTTP_400_BAD_REQUEST)

#                 wallet.wallet_balance = float(wallet.wallet_balance) - price
#                 wallet.save()

#                 Ticket.objects.create(
#                     user_id=user,
#                     trip_type=trip_type,
#                     from_loc=from_loc,
#                     to_loc=to_loc,
#                     transport_date=convert_date_format(transport_date),
#                     price=price
#                 )

#                 # booked_ticket = {
#                 #     "user_id": user_id,
#                 #     "trip_type": trip_type,
#                 #     "from_loc": from_loc,
#                 #     "to_loc": to_loc,
#                 #     "transport_date": transport_date,
#                 #     "price":price
#                 # }

#                 return Response({'status': 'success', "message": "Booking Successful"}, status=status.HTTP_200_OK)
#             except UserWallet.DoesNotExist:
#                 return Response({'status': 'error', 'message': 'Wallet does not exist'}, status=status.HTTP_404_NOT_FOUND)
#     elif trip_type == 'round_trip':
#         with transaction.atomic():
#             try:
#                 wallet = UserWallet.objects.select_for_update().get(user_id=user_id)
#                 if wallet.wallet_balance < price:
#                     return Response({'status': 'error', 'message': 'Insufficient funds'}, status=status.HTTP_400_BAD_REQUEST)

#                 wallet.wallet_balance = float(wallet.wallet_balance) - price
#                 wallet.save()

#                 Ticket.objects.create(
#                     user_id=user,
#                     trip_type=trip_type,
#                     from_loc=from_loc,
#                     to_loc=to_loc,
#                     transport_date=convert_date_format(transport_date),
#                     price=price
#                 )

#                 # booked_ticket = {
#                 #     "user_id": user_id,
#                 #     "trip_type": trip_type,
#                 #     "from_loc": from_loc,
#                 #     "to_loc": to_loc,
#                 #     "transport_date": transport_date,
#                 #     "price":price
#                 # }
#                 return Response({'status': 'success', "message": "Booking Successful"}, status=status.HTTP_200_OK)
#             except UserWallet.DoesNotExist:
#                 return Response({'status': 'error', 'message': 'Wallet does not exist'}, status=status.HTTP_404_NOT_FOUND)
#     else:
#         return Response({'status': 'error', 'message': 'Invalid trip type'}, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
def get_ticket_price(request):
    from_loc = request.data.get('from_loc')
    to_loc = request.data.get('to_loc')
    trip_type = request.data.get('trip_type')

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
        # print(price)
        if trip_type == "one_way":
            return Response({'status': 'success', 'price': price}, status=status.HTTP_200_OK)
        elif trip_type == "round_trip":
            price = price * 2

            price = price - (price * 0.15)
            return Response({'status': 'success', 'price': price}, status=status.HTTP_200_OK)
    else:
        return Response({'status': 'error', 'message': 'Invalid locations'})



@api_view(['POST'])
def book_ticket(request):
    trip_type = request.data.get('trip_type')
    ticket_type = request.data.get('ticket_type')
    user_id = request.data.get('user_id')
    radar_ticket_id = request.data.get('radar_ticket_id')
    date_booked = request.data.get('date_booked')
    time_booked = request.data.get('time_booked')
    buy_for_self = request.data.get('buy_for_self')
    mp_ticket_list = request.data.get('mp_ticket_list')
    
    if not all([trip_type, ticket_type, user_id, radar_ticket_id, date_booked, time_booked]):
        return Response({"status": "error", "message": "Missing required fields"}, status=status.HTTP_400_BAD_REQUEST)
    
    def create_ticket(user_id, radar_ticket_id, trip_type, date_booked, time_booked, ticket_type, num_of_tickets_bought=None, bought_by=None):
        return Ticket.objects.create(
            user_id=user_id,
            radar_ticket_id=radar_ticket_id,
            trip_type=trip_type,
            date_booked=date_booked,
            time_booked=time_booked,
            ticket_type=ticket_type,
            num_of_tickets_bought=num_of_tickets_bought,
            bought_by=bought_by
        )

    try:
        if trip_type == "one_way":
            if ticket_type == "sp":
                create_ticket(user_id, radar_ticket_id, trip_type, date_booked, time_booked, ticket_type)
            elif ticket_type == "mp":
                if buy_for_self:
                    num_of_tickets_bought = len(mp_ticket_list)
                    create_ticket(user_id, radar_ticket_id, trip_type, date_booked, time_booked, ticket_type, num_of_tickets_bought=num_of_tickets_bought)
                
                for mp_ticket in mp_ticket_list:
                    create_ticket(mp_ticket['user_id'], mp_ticket['radar_ticket_id'], trip_type, mp_ticket['date_booked'], mp_ticket['time_booked'], ticket_type, bought_by=user_id)
        
        elif trip_type == "round_trip":
            radar_ticket1_id = request.data.get('radar_ticket1_id')
            radar_ticket2_id = request.data.get('radar_ticket2_id')

            if not all([radar_ticket1_id, radar_ticket2_id]):
                return Response({"status": "error", "message": "Missing radar ticket IDs for round trip"}, status=status.HTTP_400_BAD_REQUEST)

            if ticket_type == 'sp':
                create_ticket(user_id, radar_ticket1_id, trip_type, date_booked, time_booked, ticket_type)
                create_ticket(user_id, radar_ticket2_id, trip_type, date_booked, time_booked, ticket_type)
            
            elif ticket_type == 'mp':
                if buy_for_self:
                    num_of_tickets_bought = len(mp_ticket_list)
                    create_ticket(user_id, radar_ticket1_id, trip_type, date_booked, time_booked, ticket_type, num_of_tickets_bought=num_of_tickets_bought)
                    create_ticket(user_id, radar_ticket2_id, trip_type, date_booked, time_booked, ticket_type, num_of_tickets_bought=num_of_tickets_bought)
                
                for mp_ticket in mp_ticket_list:
                    create_ticket(mp_ticket['user_id'], mp_ticket['radar_ticket1_id'], trip_type, mp_ticket['date_booked'], mp_ticket['time_booked'], ticket_type, bought_by=user_id)
                    create_ticket(mp_ticket['user_id'], mp_ticket['radar_ticket2_id'], trip_type, mp_ticket['date_booked'], mp_ticket['time_booked'], ticket_type, bought_by=user_id)
        
        return Response({"status": "success", "message": "Tickets booked successfully"}, status=status.HTTP_201_CREATED)
    
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
    locations = ['mushin', 'costain', 'ilupeju', 'yaba', 'oshodi', 'ikeja']
    return Response({'status': 'success', 'message': locations}, status=status.HTTP_200_OK)


@api_view(['POST'])
def get_first_three_transactions(request):
    user_id = request.data.get('user_id')

    if not user_id:
        return Response({"status": "error", "message": "user_id is required"}, status=status.HTTP_400_BAD_REQUEST)

    try:
        user = Users.objects.get(user_id=user_id)
    except Users.DoesNotExist:
        return Response({"status": "error", "message": "User not found"}, status=status.HTTP_404_NOT_FOUND)

    transactions = Transaction.objects.filter(user=user)[:3]

    if not transactions:
        return Response({"status": "success", "message": "No transactions found"}, status=status.HTTP_200_OK)

    transactions_list = []

    for transaction in transactions:
        my_transc_dict = {
            'amount': str(transaction.amount),
            'transaction_date': str(transaction.transaction_date),
            'transaction_type': transaction.transaction_type,
            'status': transaction.status,
        }
        transactions_list.append(my_transc_dict)

    return Response({"status": "success", "transactions": transactions_list}, status=status.HTTP_200_OK)


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
        my_transc_dict = {
            'amount': str(transaction.amount),
            'transaction_date': str(transaction.transaction_date),
            'transaction_type': transaction.transaction_type,
            'status': transaction.status,
        }
        transactions_list.append(my_transc_dict)

    return Response({"status": "success", "transactions": transactions_list}, status=status.HTTP_200_OK)