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

urlpatterns = [
    path("admin/", admin.site.urls),
    path("signup/", signup, name="signup"),
    path("login/", login, name="login"),
    path("verify-token/", verify_token, name="verify_token"),
    path("change-fullname/", change_fullname, name="change_fullname"),
    path("change-username/", change_username, name="change_username"),
    path("change-email/", change_email, name="change_email"),
    path("verify-new-email/", verify_new_email, name="verify_new-email")
]
