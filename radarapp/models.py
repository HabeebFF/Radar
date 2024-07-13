from django.db import models
from django.contrib.auth.models import AbstractUser
from django.core.exceptions import ValidationError
import datetime

class Users(AbstractUser):
    user_id = models.AutoField(primary_key=True)
    full_name = models.CharField(max_length=148)
    username = models.CharField(max_length=128, unique=True, db_index=True)
    email = models.EmailField(unique=True, db_index=True)
    password = models.CharField(max_length=256)
    user_type = models.CharField(max_length=10, default='user')

    USERNAME_FIELD = 'email'  # Use email for authentication
    REQUIRED_FIELDS = ['username', 'full_name']  # Required fields for creating a superuser

    def __str__(self):
        return self.email


class UserProfile(models.Model):
    profile_id = models.AutoField(primary_key=True)
    user = models.ForeignKey(Users, on_delete=models.CASCADE)
    profile_picture = models.ImageField(upload_to='profile_pictures/', null=True, blank=True)
    date_of_birth = models.DateField(null=True)

    def clean(self):
        if self.profile_picture:
            if self.profile_picture.size > 5 * 1024 * 1024:  # limit file size to 5MB
                raise ValidationError("Profile picture file size should not exceed 5MB")


class UserWallet(models.Model):
    user_wallet_id = models.AutoField(primary_key=True)
    user = models.ForeignKey(Users, on_delete=models.CASCADE)
    wallet_balance = models.DecimalField(default=5000, null=False, decimal_places=2, max_digits=10)
    wallet_pin = models.CharField(max_length=128)

    def clean(self):
        if not self.wallet_pin.isdigit():
            raise ValidationError("Wallet PIN must be numeric")


class VerificationToken(models.Model):
    user_email = models.EmailField(unique=True, db_index=True)
    token = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)

    def is_valid(self):
        now = datetime.datetime.now(datetime.timezone.utc)
        return now - self.created_at < datetime.timedelta(minutes=10)


class Ticket(models.Model):
    ticket_id = models.AutoField(primary_key=True)
    user_id = models.ForeignKey(Users, on_delete=models.CASCADE)
    trip_type = models.CharField(max_length=10)
    from_loc = models.CharField(max_length=15)
    to_loc = models.CharField(max_length=15)
    transport_date = models.DateField()
    transport_time = models.TimeField()
    date_booked = models.DateField()
    time_booked = models.TimeField()


class Transaction(models.Model):
    transactions_id = models.AutoField(primary_key=True)
    