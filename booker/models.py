from datetime import datetime, timezone
from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager
from django.core.exceptions import ValidationError
import random
import time
import stripe
from django.conf import settings
from django.contrib.auth import get_user_model

stripe.api_key = settings.STRIPE_SECRET_KEY


# Custom user manager
class UserManager(BaseUserManager):
    def create_user(self, phone, password=None, **extra_fields):
        if not phone:
            raise ValueError("Phone number is required")
        user = self.model(phone=phone, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, phone, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        return self.create_user(phone, password, **extra_fields)



class Plan(models.Model):
    name = models.CharField(max_length=50)
    stripe_plan_id = models.CharField(max_length=50, unique=True)
    price = models.DecimalField(max_digits=7, decimal_places=2)
    
    def __str__(self):
        return self.name

# User model
class User(AbstractBaseUser):
    ROLES = (
        ('Owner', 'Owner'),
        ('Manager', 'Manager'),
        ('Therapist', 'Therapist'),
    )
    
    username = models.CharField(max_length=30)
    phone = models.CharField(max_length=15, unique=True)
    email = models.EmailField(null=True, blank=True, unique=True)  # Ensure this works with unique but optional
    role = models.CharField(max_length=10, choices=ROLES, default='Owner')
    
    is_staff = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    
    exp = models.IntegerField(null=True, blank=True)  # In years
    specialty = models.CharField(max_length=255, blank=True, null=True)  
    is_verified = models.BooleanField(default=False)
    description = models.TextField(null=True, blank=True)  
    image = models.ImageField(upload_to='user_images/', null=True, blank=True)  
    
     # Stripe related fields
    stripe_customer_id = models.CharField(max_length=255, blank=True, null=True)
    current_plan = models.ForeignKey(Plan, on_delete=models.SET_NULL, null=True, blank=True)

    # Subscription status and timestamps
    is_subscription_active = models.BooleanField(default=False)
    subscription_start_date = models.DateTimeField(null=True, blank=True)
    subscription_end_date = models.DateTimeField(null=True, blank=True)
    
    USERNAME_FIELD = 'phone'
    REQUIRED_FIELDS = ['username']

    objects = UserManager()

    def __str__(self):
        return self.username if self.username else self.phone

    def clean(self):
        if not self.phone:
            raise ValidationError("Phone number is required")

    def get_store_details(self):
        if self.role != 'Owner':
            return None
        stores = self.owned_stores.prefetch_related('managers', 'therapists').all()
        store_details = []
        for store in stores:
            store_info = {
                'store_name': store.name,
                'managers': store.get_managers_with_therapists(),
                'therapists': store.get_therapists(),
            }
            store_details.append(store_info)
        return store_details
    
    def activate_subscription(self, plan):
        """Activate a user's subscription with a given plan."""
        self.current_plan = plan
        self.is_subscription_active = True
        self.subscription_start_date = timezone.now()
        # Set subscription_end_date based on plan duration or handle via webhook
        self.save()

    def deactivate_subscription(self):
        """Deactivate a user's subscription."""
        self.is_subscription_active = False
        self.subscription_end_date = timezone.now()
        self.save()




class Subscription(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='subscriptions')
    stripe_subscription_id = models.CharField(max_length=50, unique=True)
    plan = models.ForeignKey(Plan, on_delete=models.SET_NULL, null=True)
    status = models.CharField(max_length=50)
    current_period_end = models.DateTimeField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f'{self.user.username} - {self.plan.name}'

    def cancel(self):
        
        stripe_subscription = stripe.Subscription.retrieve(self.stripe_subscription_id)
        stripe_subscription.cancel_at_period_end = True
        self.status = "canceled"
        self.save()
    
    
class PaymentIntent(models.Model):
    payment_intent_id = models.CharField(max_length=255, unique=True)
    user = models.ForeignKey(get_user_model(), on_delete=models.CASCADE)
    amount = models.IntegerField()
    currency = models.CharField(max_length=10)
    status = models.CharField(max_length=50)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.payment_intent_id

  
class StripeEvents(models.Model):
    event_id = models.CharField(max_length=255, unique=True)
    event_type = models.CharField(max_length=50)
    event_data = models.JSONField()
    subscription = models.ForeignKey(Subscription, on_delete=models.SET_NULL, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f'Event: {self.event_type} - {self.event_id}'

    
    # Store model
class Store(models.Model):
    name = models.CharField(max_length=255)
    address = models.CharField(max_length=255)
    owner = models.ForeignKey(User, on_delete=models.CASCADE, related_name="owned_stores")
    managers = models.ManyToManyField(User, related_name="managed_stores", limit_choices_to={'role': 'Manager'})
    therapists = models.ManyToManyField(User, related_name="therapist_stores", limit_choices_to={'role': 'Therapist'})
    phone = models.CharField(max_length=15)
    email = models.EmailField(null=True, blank=True)
    opening_days = models.JSONField()  # Ensure proper validation of format
    start_time = models.TimeField()
    end_time = models.TimeField()
    lunch_start_time = models.TimeField(null=True, blank=True)
    lunch_end_time = models.TimeField(null=True, blank=True)
    subscribe = models.BooleanField(default=False)

    class Meta:
        unique_together = ['name', 'address']
        indexes = [
            models.Index(fields=['name', 'address']),  # For better performance
        ]

    def __str__(self):
        return self.name

    def get_therapists(self):
        return [{'therapist_name': therapist.username} for therapist in self.therapists.all()]

    def get_managers_with_therapists(self):
        managers_with_therapists = []
        for manager in self.managers.all():
            manager_info = {
                'manager_name': manager.username,
                'assigned_therapists': [therapist.username for therapist in manager.therapist_stores.filter(id=self.id)]
            }
            managers_with_therapists.append(manager_info)
        return managers_with_therapists

    def get_manager_and_therapist_names(self):
        manager_names = [manager.username for manager in self.managers.all()]
        therapist_names = [therapist.username for therapist in self.therapists.all()]
        return {
            'managers': manager_names,
            'therapists': therapist_names
        }

# Therapist schedule model book appointment
class TherapistSchedule(models.Model):
    STATUS_CHOICES = (
        ('Pending', 'Pending'),
        ('Confirmed', 'Confirmed'),
        ('Cancelled', 'Cancelled'),
    )
    therapist = models.ForeignKey(User, on_delete=models.CASCADE, limit_choices_to={'role': 'Therapist'})
    store = models.ForeignKey(Store, on_delete=models.CASCADE)
    date = models.DateField()
    start_time = models.TimeField()
    end_time = models.TimeField()
    previous_start_time = models.DateTimeField(null=True, blank=True)  # Track previous start time
    previous_end_time = models.DateTimeField(null=True, blank=True)    # Track previous end time
    is_day_off = models.BooleanField(default=False)
    status = models.CharField(max_length=25, choices=STATUS_CHOICES, default='Pending')
    title = models.CharField(max_length=255, null=True, blank=True)
    color = models.CharField(max_length=7, null=True, blank=True)
    
    # New field for customer confirmation status
    customer_confirmation_status = models.CharField(
        max_length=20,
        choices=[
            ('Pending', 'Pending'),
            ('Confirmed', 'Confirmed'),
            ('Declined', 'Declined')
        ],
        default='Pending'
    )

    # Customer-related fields
    customer_name = models.CharField(max_length=255, default="Unknown Customer")
    customer_phone = models.CharField(max_length=15, default="Unknown Phone")
    customer_email = models.EmailField(null=True, blank=True)

    class Meta:
        unique_together = ['therapist', 'store', 'date', 'start_time', 'end_time']
        indexes = [
            models.Index(fields=['therapist', 'store', 'date']),
        ]

    def __str__(self):
        return f'{self.customer_name} - {self.date} - {self.start_time} to {self.end_time} - {self.status}'

    def get_duration(self):
        return (datetime.combine(self.date, self.end_time) - datetime.combine(self.date, self.start_time)).total_seconds() / 60  # Duration in minutes


# Manager schedule model
class ManagerSchedule(models.Model):
    manager = models.ForeignKey(User, on_delete=models.CASCADE, limit_choices_to={'role': 'Manager'})
    store = models.ForeignKey(Store, on_delete=models.CASCADE)
    date = models.DateField()
    start_time = models.TimeField()
    end_time = models.TimeField()
    is_day_off = models.BooleanField(default=False)

    class Meta:
        unique_together = ['manager', 'store', 'date', 'start_time', 'end_time']
        indexes = [
            models.Index(fields=['manager', 'store', 'date']),  # For performance
        ]

    def __str__(self):
        return f'{self.manager.phone} - {self.date} - {self.start_time} to {self.end_time}'


class OTP(models.Model):
    phone = models.CharField(max_length=15, unique=True)
    otp = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)

    def is_expired(self):
        return (time.time() - self.created_at.timestamp()) > 300  



