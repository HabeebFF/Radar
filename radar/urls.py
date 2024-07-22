"""
URL configuration for radar project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from radarapp.views import *
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path("admin/", admin.site.urls),
    path("signup/", signup, name="signup"),
    path("login/", login, name="login"),
    path("verify-token/", verify_token, name="verify_token"),
    path("change-fullname/", change_fullname, name="change_fullname"),
    path("change-username/", change_username, name="change_username"),
    path("change-email/", change_email, name="change_email"),
    path("verify-new-email/", verify_new_email, name="verify_new-email"),
    path("forgot-password/send-token/", forgot_password, name="forgot_password"),
    path("forgot-password/verify-token/", verify_forgot_password_token, name="verify_forgot_password_token"),
    path("forgot-password/change-password/", change_password_fp, name="change_password_fp"),
    path('get-ticket-price/', get_ticket_price, name="get_ticket_price"),
    path('book-ticket/', book_ticket, name='book_ticket'),
    path('get-username/', get_username, name='get_username'),
    path('get-wallet-balance/', get_wallet_balance, name='get_wallet_balance'),
    path('get-locations/', get_locations, name='get_locations'),
    path('get-first-three-transactions/', get_first_three_transactions, name='get_first_three_transactions'),
    path('get-all-transactions/', get_all_transactions, name="get_all_transactions"),
    path('send-money/', send_money, name='send_money'),
    path('change-password-logged-in/', change_password_logged_in, name='change_password_logged_in'),
    path('driver-signup/', driver_signup, name='driver_signup'),
    path('create-ticket/', create_ticket, name='create_ticket'),
    path('get-user-profile-pic/', get_user_profile_pic, name='get_user_profile_pic'),
    path('user-get-three-recent-booked-ticket', user_get_three_recent_booked_ticket, name='user_get_three_recent_booked_ticket'),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)