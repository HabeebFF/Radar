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
    wallet_pin = models.CharField(max_length=4)

    def clean(self):
        if not self.wallet_pin.isdigit():
            raise ValidationError("Wallet PIN must be numeric")
        if len(self.wallet_pin) != 4:
            raise ValidationError("Wallet PIN must be exactly 4 digits")


class VerificationToken(models.Model):
    user_email = models.EmailField(unique=True, db_index=True)
    token = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)

    def is_valid(self):
        now = datetime.datetime.now(datetime.timezone.utc)
        return now - self.created_at < datetime.timedelta(minutes=10)
    

class Notification(models.Model):
    user = models.ForeignKey(Users, on_delete=models.CASCADE)
    title = models.CharField(max_length=30)
    message = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    is_read = models.BooleanField(default=False)
    notif_type = models.CharField(max_length=7)


class Driver(models.Model):
    driver_id = models.AutoField(primary_key=True)
    fullname = models.CharField(max_length=124)
    username = models.CharField(unique=True, max_length=124)
    email = models.EmailField(unique=True)
    password = models.CharField(max_length=124)
    profile_picture = models.ImageField(upload_to='profile_pictures/', blank=True, null=True)

    def __str__(self):
        return self.fullname

    def clean(self):
        if self.profile_picture and self.profile_picture.size > 5 * 1024 * 1024:  # limit file size to 5MB
            raise ValidationError("Profile picture file size should not exceed 5MB")


class RadarTicket(models.Model):
    radar_ticket_id = models.AutoField(primary_key=True)
    driver_id = models.ForeignKey(Driver, on_delete=models.CASCADE)
    from_loc = models.CharField(max_length=15)
    to_loc = models.CharField(max_length=15)
    price = models.DecimalField(max_digits=10, decimal_places=2)
    transport_date = models.DateField()
    transport_time = models.TimeField()
    num_of_buyers = models.IntegerField(default=12)
    status = models.CharField(max_length=20, default='upcoming')


class UserTicket(models.Model):
    ticket_id = models.AutoField(primary_key=True)
    user = models.ForeignKey(Users, on_delete=models.CASCADE, related_name='tickets')
    radar_ticket_id = models.ForeignKey(RadarTicket, on_delete=models.CASCADE)
    trip_type = models.CharField(max_length=10)
    date_booked = models.DateField()
    time_booked = models.TimeField()
    ticket_type = models.CharField(max_length=10, default='sp')
    bought_by = models.ForeignKey(Users, on_delete=models.CASCADE, null=True, related_name='bought_tickets')
    num_of_tickets_bought = models.IntegerField(null=True)
    ticket_code = models.CharField(max_length=8, unique=True)  # Ensure ticket codes are unique
    status = models.CharField(max_length=20, default='Pending')
    expiration_date = models.DateField()
    expiration_time = models.TimeField()

    def clean(self):
        # Ensure the expiration date and time are valid
        if self.expiration_date < datetime.now().date():
            raise ValidationError("Expiration date cannot be in the past.")
        if self.expiration_date == datetime.now().date() and self.expiration_time < datetime.now().time():
            raise ValidationError("Expiration time cannot be in the past on the expiration date.")
        # Ensure num_of_tickets_bought is a positive integer
        if self.num_of_tickets_bought and self.num_of_tickets_bought <= 0:
            raise ValidationError("Number of tickets bought must be greater than zero.")

    def __str__(self):
        return f"Ticket {self.ticket_code} - {self.user_id.email} - {self.radar_ticket_id.from_loc} to {self.radar_ticket_id.to_loc}"



class Transaction(models.Model):
    transaction_id = models.AutoField(primary_key=True)
    user = models.ForeignKey(Users, on_delete=models.CASCADE)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    transaction_date = models.DateTimeField(auto_now_add=True)
    transaction_type = models.CharField(max_length=10)  # Example values: 'deposit', 'withdrawal', etc.
    status = models.CharField(max_length=10, default='Pending')

    def __str__(self):
        return f"{self.user.email} - {self.amount} - {self.transaction_type}"
    

