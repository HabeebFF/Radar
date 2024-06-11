from django.shortcuts import render
from django.conf import settings
from rest_framework import status
from rest_framework.decorators import api_view
from rest_framework.response import Response
from .models import Users
from .serializers import UserSerializer, DriverSerializer
from django.contrib.auth import authenticate
from django.db import transaction
from django.views.decorators.csrf import csrf_exempt
from django.core.mail import send_mail
from django.utils.crypto import get_random_string
from django.http import HttpRequest, JsonResponse
from django.contrib.auth.hashers import check_password
import paystack
import requests
import json
import random
import string
from datetime import datetime
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
import io
import qrcode
from django.http import HttpResponse
from concurrent.futures import ThreadPoolExecutor
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
    data = request.data

    if user_type == "user":
        future = executor.submit(create_user, data)
    elif user_type == "driver":
        future = executor.submit(create_driver, data)
    else:
        return Response({'status': 'error', 'message': 'Invalid user type'}, status=status.HTTP_400_BAD_REQUEST)

    result = future.result()
    
    if result['status'] == 'success':
        return Response({'status': 'success', 'message': 'User created successfully'}, status=status.HTTP_201_CREATED)
    else:
        return Response({'status': 'error', 'errors': result['errors']}, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
def login(request):
    email = request.data.get("email")
    password = request.data.get("password")

    if not email or not password:
        return Response({"error": "Email and password are required."}, status=status.HTTP_400_BAD_REQUEST)

    # Assuming you're using email as the username field
    try:
        user = Users.objects.get(email=email)

        if user.is_verified == False:
            return Response({"error": "User is unverified."}, status=status.HTTP_400_BAD_REQUEST)

    except Users.DoesNotExist:
        return Response({"error": "Invalid email or password."}, status=status.HTTP_400_BAD_REQUEST)

    # user = authenticate(username=user.username, password=password)

    if user.isverified and password == user.password:
        # token, created = Token.objects.get_or_create(user=user)
        return Response({"successful": "Login Successful"}, status=status.HTTP_200_OK)
    else:
        return Response({"error": "Invalid email or password."}, status=status.HTTP_400_BAD_REQUEST)



@api_view(['POST'])
@transaction.atomic  # Ensuring atomicity for the select_for_update block
def verify_user(request):
    email = request.data.get("email")

    if not email:
        return Response({"error": "Email is required."}, status=status.HTTP_400_BAD_REQUEST)

    try:
        user = Users.objects.select_for_update().get(email=email)
        user.is_verified = True
        user.save()
        return Response({"success": "User Verified Successfully"}, status=status.HTTP_200_OK)
    except User.DoesNotExist:
        return Response({"error": "User with this email does not exist."}, status=status.HTTP_404_NOT_FOUND)
