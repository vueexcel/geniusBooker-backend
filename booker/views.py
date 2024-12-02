from datetime import datetime
import json
from django.shortcuts import get_object_or_404
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken
from django.core.exceptions import ValidationError
from django.db import transaction
from .models import ManagerSchedule, StripeEvents, User, Store, TherapistSchedule
from rest_framework import generics
from rest_framework.authentication import TokenAuthentication
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.permissions import BasePermission,AllowAny
from twilio.rest import Client
from django.views.decorators.csrf import csrf_exempt
from django.http import HttpResponseRedirect, JsonResponse
from django.shortcuts import render
import phonenumbers
from django.core.cache import cache
from phonenumbers import NumberParseException
from twilio.base.exceptions import TwilioRestException
from phonenumbers import parse, is_valid_number, format_number, PhoneNumberFormat
from django.conf import settings
import logging
import stripe
from datetime import timedelta
from .models import OTP,Plan, Subscription 
from django.utils import timezone
import requests
from random import randint
import phonenumbers
from twilio.rest import Client
from django.utils.crypto import get_random_string
from django.contrib.auth.hashers import make_password
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from rest_framework.throttling import UserRateThrottle
import base64
from django.utils.http import urlsafe_base64_decode
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from .serializers import (
    PaymentIntentSerializer, RegisterSerializer, StaffSerializer, TherapistSerializer, UserSerializer, StoreSerializer,
    TherapistScheduleSerializer,AppointmentSerializer, PlanSerializer, SubscriptionSerializer,AddStaffToStoreSerializer,StoreDetailSerializer,ManagerSchedule,ManageTherapistScheduleSerializer
)

logger = logging.getLogger(__name__)

twilio_client = Client("TWILIO_ACCOUNT_SID", "TWILIO_AUTH_TOKEN")
# Utility to create user and add them to store roles
@transaction.atomic
def create_user_and_assign_role(staff_member, store=None):
    # Extract the staff details
    role = staff_member.get('role', 'Therapist')
    phone = staff_member.get('phone')
    password = staff_member.get('password')
    email = staff_member.get('email')
    exp = staff_member.get('exp', None)
    specialty = staff_member.get('specialty', None)
    username = staff_member.get('staff_name')

    if not phone or not password:
        raise ValidationError("Phone number and password are required to create a staff member.")
    
    user = User.objects.filter(phone=phone).first()

    # If user doesn't exist, create a new one
    if not user:
        user = User.objects.create_user(
            phone=phone,
            password=password,
            email=email,
            role=role,
            exp=exp,
            specialty=specialty,
            username=username
        )
    else:
        # Update existing user with exp and specialty if provided
        user.exp = exp if exp is not None else user.exp
        user.specialty = specialty if specialty is not None else user.specialty
        user.username = username if username else user.username  
        user.save()
    
    if store:
        if role == 'Manager':
            if store.managers.filter(id=user.id).exists():
                raise ValidationError("This Manager is already assigned to the store.")
            store.managers.add(user)
        elif role == 'Therapist':
            if store.therapists.filter(id=user.id).exists():
                raise ValidationError("This Therapist is already assigned to the store.")
            store.therapists.add(user)

    return user

def get_store_data(user, stores):
    store_data = []
    for store in stores:
        # Manager schedules
        manager_data = []
        for manager in store.managers.all():
            manager_info = UserSerializer(manager).data
            manager_schedule = ManagerSchedule.objects.filter(manager=manager, store=store).values('date', 'start_time', 'end_time', 'is_day_off')
            manager_info['schedule'] = list(manager_schedule)
            manager_data.append(manager_info)
        
        # Therapist schedules
        therapist_data = []
        for therapist in store.therapists.all():
            therapist_schedule = TherapistSchedule.objects.filter(therapist=therapist, store=store).values('date', 'start_time', 'end_time', 'is_day_off')
            therapist_info = UserSerializer(therapist).data
            therapist_info['schedule'] = list(therapist_schedule)
            therapist_data.append(therapist_info)

        store_data.append({
            "store_id": store.id,
            "store_name": store.name,
            "store_address": store.address,
            "store_phone": store.phone,
            "store_email": store.email,
            "store_schedule": {
                "opening_days": store.opening_days,
                "start_time": store.start_time,
                "end_time": store.end_time,
                "lunch_start_time": store.lunch_start_time,
                "lunch_end_time": store.lunch_end_time
            },
            "managers": manager_data,
            "therapists": therapist_data
        })
    return store_data


class StoreListView(APIView):
    permission_classes = [AllowAny]
    def get(self, request):
        stores = Store.objects.all().prefetch_related('therapists')
        serializer = StoreDetailSerializer(stores, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

logger = logging.getLogger(__name__)
def verify_recaptcha(recaptcha_response):
    """
    Verifies the Cloudflare Turnstile CAPTCHA response from the user.
    """
    secret_key = settings.TURNSTILE_SECRET_KEY
    if not secret_key:
        logger.error("TURNSTILE_SECRET_KEY is not set in environment variables.")
        return False

    url = 'https://challenges.cloudflare.com/turnstile/v0/siteverify'
    data = {
        'secret': secret_key,  # Your Cloudflare Turnstile secret key
        'response': recaptcha_response  # The token received from the frontend
    }

    try:
        response = requests.post(url, data=data)
        result = response.json()
        logger.debug(f"CAPTCHA verification result: {result}")  
        if not result.get('success', False):
            logger.error(f"CAPTCHA failed with error codes: {result.get('error-codes')}")
            return False
        return True
    
    except requests.exceptions.RequestException as e:
        logger.error(f"Error during CAPTCHA verification: {str(e)}")
        return False


def format_phone_number(phone, country_code="US"):
    try:
        # Clean up the phone number (remove spaces, dashes, etc.)
        phone = ''.join([c for c in phone if c.isdigit() or c == '+'])
        
        # If the phone number starts with a '+', parse it as an international number
        if phone.startswith('+'):
            parsed_number = phonenumbers.parse(phone, None)  # No need to provide a region
        else:
            # Parse the number with the provided country code
            parsed_number = phonenumbers.parse(phone, country_code)

        # Check if the phone number is valid
        if phonenumbers.is_valid_number(parsed_number):
            # Return the formatted phone number in E.164 format
            return phonenumbers.format_number(parsed_number, phonenumbers.PhoneNumberFormat.E164)
        else:
            raise ValueError("Invalid phone number format")
    
    except phonenumbers.phonenumberutil.NumberParseException as e:
        raise ValueError(f"Error formatting phone number: {str(e)}")

class RegisterAPI(APIView):
    def post(self, request):
        try:
            recaptcha_response = request.data.get('recaptcha')
            if not verify_recaptcha(recaptcha_response):
                return Response({"error": "Invalid CAPTCHA."}, status=status.HTTP_400_BAD_REQUEST)

            # Extract phone number from request data
            phone = request.data.get('phone')
            if not phone:
                return Response({"error": "Phone number is required"}, status=status.HTTP_400_BAD_REQUEST)

            # Format the phone number to ensure international format
            try:
                phone_number = phonenumbers.parse(phone, None)
                formatted_phone = phonenumbers.format_number(phone_number, phonenumbers.PhoneNumberFormat.E164)
            except NumberParseException:
                return Response({"error": "Invalid phone number format"}, status=status.HTTP_400_BAD_REQUEST)

            # Check if an OTP has already been sent and is still valid
            if cache.get(f"otp_{formatted_phone}"):
                return Response({"error": "OTP has already been sent. Please wait before retrying."}, status=status.HTTP_400_BAD_REQUEST)

            # Generate OTP and store it temporarily in the cache
            otp_code = str(randint(100000, 999999))
            cache.set(f"otp_{formatted_phone}", otp_code, timeout=300)  # Set OTP with a 5-minute expiration

            # Send OTP via SMS using Twilio
            client = Client(settings.TWILIO_ACCOUNT_SID, settings.TWILIO_AUTH_TOKEN)
            twilio_whatsapp_number = settings.TWILIO_PHONE_NUMBER
            try:
                client.messages.create(
                    body=f"Your OTP for account verification is: {otp_code}",
                    from_=f'whatsapp:{twilio_whatsapp_number}',  # Use WhatsApp number
                    to=f'whatsapp:{formatted_phone}' 
                )
            except TwilioRestException as e:
                logger.error(f"Twilio error: {str(e)}")
                return Response({"error": "Failed to send OTP. Please try again."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

            return Response({"message": "OTP sent successfully. Please verify your phone to complete registration."}, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error(f"Error during OTP send: {str(e)}")
            return Response({"error": "An error occurred"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class CompleteRegistrationAPI(APIView):
    def post(self, request):
        try:
            otp = request.data.get('otp')
            phone = request.data.get('phone')

            # Format the phone number to ensure international format
            try:
                phone_number = phonenumbers.parse(phone, None)
                formatted_phone = phonenumbers.format_number(phone_number, phonenumbers.PhoneNumberFormat.E164)
            except NumberParseException:
                return Response({"error": "Invalid phone number format"}, status=status.HTTP_400_BAD_REQUEST)

            # Validate OTP from the cache
            cached_otp = cache.get(f"otp_{formatted_phone}")
            if cached_otp != otp:
                return Response({"error": "Invalid or expired OTP"}, status=status.HTTP_400_BAD_REQUEST)

            # OTP is valid, proceed with registration
            password = request.data.get('password')
            password2 = request.data.get('password2')

            if password != password2:
                return Response({"error": "Passwords do not match"}, status=status.HTTP_400_BAD_REQUEST)

            serializer = RegisterSerializer(data=request.data)
            if serializer.is_valid():
                with transaction.atomic():  # Start a transaction
                    user = serializer.save(phone=formatted_phone, role='Owner', is_verified=True)
                    user.is_active = True
                    user.save()

                    # Delete OTP from cache after successful registration
                    cache.delete(f"otp_{formatted_phone}")

                return Response({"message": "User registered successfully!"}, status=status.HTTP_201_CREATED)

            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            logger.error(f"Error during registration: {str(e)}")
            return Response({"error": "An error occurred"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

token_generator = PasswordResetTokenGenerator()

class PasswordResetRequestView(APIView):
    def post(self, request):
        phone = request.data.get('phone')

        try:
            user = User.objects.get(phone=phone)
        except User.DoesNotExist:
            return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)

        # Generate password reset token and user ID
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = token_generator.make_token(user)

        # Create the password reset URL
        reset_url = f"{settings.FRONTEND_URL}/#/reset-password/?{uid}/{token}/"

        # Send the reset URL to the user's phone via SMS using Twilio
        client = Client(settings.TWILIO_ACCOUNT_SID, settings.TWILIO_AUTH_TOKEN)
        
        try:
            message = client.messages.create(
                body=f"Hi {user.username},\nUse the link to reset your password: {reset_url}",
                from_=f'whatsapp:{settings.TWILIO_PHONE_NUMBER}',
                to=f'whatsapp:{user.phone}'
            )
        except Exception as e:
            return Response({"error": "Failed to send SMS"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        return Response({"message": "Password reset link sent to your phone."}, status=status.HTTP_200_OK)

class PasswordResetConfirmView(APIView):
    def post(self, request, uidb64, token):
        # Decode the user ID from the URL
        try:
            uid = urlsafe_base64_decode(uidb64).decode()
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            return Response({"error": "Invalid user"}, status=status.HTTP_400_BAD_REQUEST)

        # Check if the token is valid
        token_generator = PasswordResetTokenGenerator()
        if not token_generator.check_token(user, token):
            return Response({"error": "Invalid or expired token"}, status=status.HTTP_400_BAD_REQUEST)

        # Validate the passwords
        password = request.data.get('new_password')
        password2 = request.data.get('confirm_password')

        if password != password2:
            return Response({"error": "Passwords do not match"}, status=status.HTTP_400_BAD_REQUEST)

        # Set the new password and clear reset token
        try:
            validate_password(password)
        except ValidationError as e:
            return Response({"error": e.messages}, status=status.HTTP_400_BAD_REQUEST)

        user.set_password(password)
        user.save()

        return Response({"message": "Password reset successfully"}, status=status.HTTP_200_OK)

# Login API
class OwnerLoginView(APIView):
        def post(self, request):
            phone = request.data.get('phone')
            password = request.data.get('password')
            user = authenticate(phone=phone, password=password)

            if user and user.role == 'Owner':
                # Fetch the stores owned by the owner
                stores = Store.objects.filter(owner=user).prefetch_related('managers', 'therapists')
                refresh = RefreshToken.for_user(user)
                
                store_data =  get_store_data(user, stores)

                
                data = {
                    "access": str(refresh.access_token),
                    "refresh": str(refresh),
                    "owner": {
                        "role": user.role,
                        "owner_id": user.id,
                        "name": user.username,
                        "email": user.email,
                        "phone": user.phone
                    },
                    "stores": store_data
                }

                return Response(data, status=status.HTTP_200_OK)

            return Response({"error": "Login with owner credentials"}, status=status.HTTP_403_FORBIDDEN)
    
class ManagerLoginView(APIView):
    def post(self, request):
        phone = request.data.get('phone')
        password = request.data.get('password')
        user = authenticate(phone=phone, password=password)

        if user and user.role == 'Manager':
            # stores managed by the manager
            stores = Store.objects.filter(managers=user)
            refresh = RefreshToken.for_user(user)

            
            store_data = get_store_data(user, stores)

            # manager's own schedule
            manager_schedule = ManagerSchedule.objects.filter(manager=user).values('date', 'start_time', 'end_time', 'is_day_off')

            # Prepare response data
            data = {
                "access": str(refresh.access_token),
                "refresh": str(refresh),
                "manager": {
                    "role": user.role,
                    "manager_id": user.id,
                    "name": user.username,
                    "email": user.email,
                    "phone": user.phone,
                    "exp": str(user.exp),
                    "schedule": list(manager_schedule)
                },
                "stores": store_data
            }

            return Response(data, status=status.HTTP_200_OK)

        return Response({"error": "Login with manager credentials"}, status=status.HTTP_403_FORBIDDEN)

class TherapistLoginView(APIView):
    def post(self, request):
        phone = request.data.get('phone')
        password = request.data.get('password')
        user = authenticate(phone=phone, password=password)

        if user and user.role == 'Therapist':
            refresh = RefreshToken.for_user(user)

            #stores associated with the therapist
            stores = Store.objects.filter(therapists=user)

            # store data
            store_data = get_store_data(user, stores)

            # therapist's own schedule
            therapist_schedule = TherapistSchedule.objects.filter(therapist=user).values('date', 'start_time', 'end_time', 'is_day_off')

            # response data
            data = {
                "access": str(refresh.access_token),
                "refresh": str(refresh),
                "therapist": {
                    "role": user.role,
                    "therapist_id": user.id,
                    "name": user.username,
                    "email": user.email,
                    "phone": user.phone,
                    "exp": str(user.exp),
                    "specialty": user.specialty,
                    "schedule": list(therapist_schedule)
                },
                "stores": store_data
            }

            return Response(data, status=status.HTTP_200_OK)

        return Response({"error": "Login with therapist credentials"}, status=status.HTTP_403_FORBIDDEN)


class IsOwner(BasePermission):
    def has_permission(self, request, view):
        return request.user and request.user.role == 'Owner'

# Owner - Create Store with multiple staff API
class CreateStoreWithStaffAPI(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated, IsOwner]

    @transaction.atomic 
    def post(self, request):
        # Ensure the authenticated user is an Owner
        if request.user.role != 'Owner':
            return Response({"detail": "Only owners can create a store."}, status=status.HTTP_403_FORBIDDEN)

        store_data = request.data.get('store')
        staff_data = request.data.get('staff', [])

        store_serializer = StoreSerializer(data=store_data)
        if store_serializer.is_valid():
            store = store_serializer.save(owner=request.user)

            # Add multiple staff
            created_staff = []
            for staff_member in staff_data:
                role = staff_member.get('role')
                if role not in ['Manager', 'Therapist']:
                    # Roll back the transaction if an invalid role is provided
                    transaction.set_rollback(True)
                    return Response({"error": "Staff role must be either 'Manager' or 'Therapist'."}, status=status.HTTP_400_BAD_REQUEST)

                # Create staff member (either Manager or Therapist)
                staff_serializer = StaffSerializer(data=staff_member)
                if staff_serializer.is_valid():
                    staff = staff_serializer.save()

                    # Assign staff to the store based on role
                    if role == 'Manager':
                        store.managers.add(staff)
                    elif role == 'Therapist':
                        store.therapists.add(staff)

                    created_staff.append({
                        "staff_id": staff.id,
                        "staff_role": staff.role,
                        "staff_name": staff.username
                    })
                else:
                    # Rollback if any staff creation fails
                    transaction.set_rollback(True)
                    return Response(staff_serializer.errors, status=status.HTTP_400_BAD_REQUEST)

            return Response({
                "message": "Store and staff created successfully.",
                "store_id": store.id,
                "store_name": store.name,
                "created_staff": created_staff
            }, status=status.HTTP_201_CREATED)
        else:
            return Response(store_serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class DeleteStoreAPI(APIView):
    authentication_classes = [JWTAuthentication]  
    permission_classes = [IsAuthenticated, IsOwner]  # Only owners can delete the store

    def delete(self, request, store_id):
        store = get_object_or_404(Store, id=store_id)

        # Check if the user is the owner of the store
        if store.owner != request.user:
            return Response({"detail": "You do not have permission to delete this store."}, status=status.HTTP_403_FORBIDDEN)

        # the deletion
        store.delete()
        return Response({"detail": "Store deleted successfully."}, status=status.HTTP_204_NO_CONTENT)

# Add Staff to existing store API
class AddStaffAPI(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, store_id):
        store = get_object_or_404(Store, id=store_id)
        
        # Owner or Manager permission checks
        if not (request.user.role == 'Owner' and request.user == store.owner or
                request.user.role == 'Manager' and request.user in store.managers.all()):
            return Response({"error": "Unauthorized"}, status=status.HTTP_403_FORBIDDEN)
        
        staff_data = request.data.get('staff', [])
        added_staff = []
        for staff_member in staff_data:
            user = create_user_and_assign_role(staff_member, store)
            added_staff.append({
                "staff_id": user.id,
                "staff_role": user.role,
                "staff_name": user.username
            })
        
        return Response({
            "message": "Staff added successfully.",
            "store_id": store.id,
            "added_staff": added_staff
        }, status=status.HTTP_201_CREATED)


class AddStaffToStoreView(APIView):
    def post(self, request):
        serializer = AddStaffToStoreSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            staff = serializer.create_staff(serializer.validated_data)
            return Response({"message": f"Staff {staff.role} added to store successfully."}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# Add, Update, and Delete Staff API (Owner and Manager)
class ManageStaffAPI(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, store_id):
        store = get_object_or_404(Store, id=store_id)
        
        # Owner or Manager permission checks
        if not (request.user.role == 'Owner' or request.user in store.managers.all() or request.user.store == store):
            return Response({"error": "Unauthorized"}, status=status.HTTP_403_FORBIDDEN)
        
        added_staff = []
        staff_data = request.data.get('staff', [])
        for staff_member in staff_data:
            user = create_user_and_assign_role(staff_member, store)
            added_staff.append({
                "staff_id": user.id,
                "staff_role": user.role,
                "staff_name": user.username
            })
        return Response({
            "message": "Staff added successfully.",
            "store_id": store.id,
            "added_staff": added_staff
        }, status=status.HTTP_201_CREATED)

    def put(self, request, store_id, staff_id):
        store = get_object_or_404(Store, id=store_id)
        staff_member = get_object_or_404(User, id=staff_id)
        
        # Owner or Manager permission check
        if request.user.role == 'Owner' and request.user.store == store:
            pass  # Owner can modify all
        elif request.user.role == 'Manager' and request.user in store.managers.all() and staff_member.role == 'Therapist':
            pass  # Manager can modify Therapists only
        elif request.user.role == 'Therapist' and request.user == staff_member:
            pass  # Therapists can only modify their own schedules
        else:
            return Response({"error": "Unauthorized"}, status=status.HTTP_403_FORBIDDEN)

        # Check if there is schedule data in the request
        schedule_data = request.data.get('schedule', None)
        if schedule_data:
            # Update the therapist's schedule
            self.update_schedule(staff_member, store, schedule_data)

        # Update staff member details (if there are any other updates)
        serializer = StaffSerializer(staff_member, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({
                "message": "Staff updated successfully.",
                "staff_id": staff_member.id,
                "store_id": store.id
            }, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, store_id, staff_id):
        store = get_object_or_404(Store, id=store_id)
        staff_member = get_object_or_404(User, id=staff_id)

        # Owner or Manager permission check
        if request.user.role == 'Owner' and request.user.store == store:
            pass  # Owner can delete all
        elif request.user.role == 'Manager' and request.user in store.managers.all() and staff_member.role == 'Therapist':
            pass  # Manager can delete Therapists only
        elif request.user.role == 'Therapist' and request.user == staff_member:
            pass  # Therapists can only delete their own schedules
        else:
            return Response({"error": "Unauthorized"}, status=status.HTTP_403_FORBIDDEN)
        
        store.managers.remove(staff_member) if staff_member.role == 'Manager' else store.therapists.remove(staff_member)
        return Response({
            "message": "Staff deleted successfully.",
            "staff_id": staff_member.id,
            "store_id": store.id
        }, status=status.HTTP_200_OK)

    def update_schedule(self, therapist, store, schedule_data):
        for schedule_item in schedule_data:
            TherapistSchedule.objects.update_or_create(
                therapist=therapist,
                store=store,
                start_time=schedule_item.get('start'),
                defaults={
                    'title': schedule_item.get('title'),
                    'end_time': schedule_item.get('end'),
                    'background_color': schedule_item.get('backgroundColor')
                }
            )

# Manage Therapist Schedules and Appointments API
class ManageTherapistScheduleAPI(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, therapist_id):
        therapist = get_object_or_404(User, id=therapist_id, role='Therapist')

        if not (request.user.role == 'Owner' or request.user.role == 'Manager' or request.user == therapist):
            return Response({"error": "Unauthorized"}, status=status.HTTP_403_FORBIDDEN)

        schedule_data = request.data

        try:
            start_datetime = datetime.fromisoformat(schedule_data['start'])
            end_datetime = datetime.fromisoformat(schedule_data['end'])
            schedule_data['date'] = start_datetime.date()
            schedule_data['start_time'] = start_datetime.time() 
            schedule_data['end_time'] = end_datetime.time()      
        except (ValueError, KeyError):
            return Response({"error": "Invalid 'start' or 'end' datetime format. Expected format: 'YYYY-MM-DDTHH:MM:SS'"},
                            status=status.HTTP_400_BAD_REQUEST)

        serializer = ManageTherapistScheduleSerializer(data=schedule_data, context={'request': request})
        if serializer.is_valid():
            serializer.save(therapist=therapist)
            return Response({
                "message": "Schedule created successfully.",
                "schedule": serializer.data
            }, status=status.HTTP_201_CREATED)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def put(self, request, schedule_id):
        schedule = get_object_or_404(TherapistSchedule, id=schedule_id)
        therapist = schedule.therapist

        if not (request.user.role == 'Owner' or request.user.role == 'Manager' or request.user == therapist):
            return Response({"error": "Unauthorized"}, status=status.HTTP_403_FORBIDDEN)

        schedule_data = request.data
        if not schedule_data:
            return Response({"error": "No schedule data provided."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            start_datetime = datetime.fromisoformat(schedule_data['start'])
            end_datetime = datetime.fromisoformat(schedule_data['end'])
            schedule_data['date'] = start_datetime.date()
            schedule_data['start_time'] = start_datetime.time()
            schedule_data['end_time'] = end_datetime.time()
        except (ValueError, KeyError):
            return Response({"error": "Invalid 'start' or 'end' datetime format. Expected format: 'YYYY-MM-DDTHH:MM:SS'"},
                            status=status.HTTP_400_BAD_REQUEST)

        serializer = ManageTherapistScheduleSerializer(schedule, data=schedule_data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Schedule updated successfully.", "schedule": serializer.data}, status=status.HTTP_200_OK)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
    def delete(self, request, schedule_id):
        schedule = get_object_or_404(TherapistSchedule, id=schedule_id)
        therapist = schedule.therapist

        # Owners, Managers, and the therapist themselves can delete the schedule
        if not (request.user.role == 'Owner' or request.user.role == 'Manager' or request.user == therapist):
            return Response({"error": "Unauthorized"}, status=status.HTTP_403_FORBIDDEN)

        therapist_id = schedule.therapist.id
        schedule.delete()
        return Response({
            "message": "Schedule deleted successfully",
            "schedule_id": schedule_id,
            "therapist_id": therapist_id
        }, status=status.HTTP_200_OK)

# Appointment Booking API
class BookAppointmentAPI(APIView):
    permission_classes = []  # Allow anyone to book an appointment

    def post(self, request):
        # Extract data from the request
        name = request.data.get('name')
        phone = request.data.get('phone')
        email = request.data.get('email', None)
        therapist_id = request.data.get('therapist_id')  
        store_id = request.data.get('store_id')
        start_time = request.data.get('start_time')  
        end_time = request.data.get('end_time')      

        print(f"received data : {request.data}")
        print(f"start_time : {start_time}, end_time : {end_time}")
        
        # Ensure mandatory fields are provided
        if not name or not phone or not therapist_id or not start_time or not end_time:
            return Response({"error": "Missing required fields"}, status=status.HTTP_400_BAD_REQUEST)

        # Fetch therapist and store
        therapist = get_object_or_404(User, id=therapist_id, role='Therapist')
        store = get_object_or_404(Store, id=store_id)

        # Check therapist association with store
        if therapist not in store.therapists.all():
            return Response({"error": "Selected therapist is not assigned to this store"}, status=status.HTTP_400_BAD_REQUEST)

        # Parse start and end datetime
        try:
            start_datetime = timezone.datetime.fromisoformat(start_time)  # expects 'YYYY-MM-DDTHH:MM:SS'
            end_datetime = timezone.datetime.fromisoformat(end_time)      
        except ValueError:
            return Response({"error": "Invalid start or end datetime format. Ensure you are using the correct format."}, status=status.HTTP_400_BAD_REQUEST)

        # Validate start and end times
        if start_datetime >= end_datetime:
            return Response({"error": "Start time must be earlier than end time."}, status=status.HTTP_400_BAD_REQUEST)

        # Extract the date, start, and end times
        date = start_datetime.date()
        start_time_parsed = start_datetime.time()
        end_time_parsed = end_datetime.time()

        # Check for overlapping confirmed bookings
        existing_confirmed_bookings = TherapistSchedule.objects.filter(
            therapist=therapist, store=store, date=date,
            start_time__lt=end_time_parsed, end_time__gt=start_time_parsed,
            status='Confirmed'
        )

        if existing_confirmed_bookings.exists():
            return Response({"error": "Therapist is already booked during this time slot"}, status=status.HTTP_400_BAD_REQUEST)

        # Create the appointment as 'Pending'
        schedule_data = {
            "therapist": therapist.id,
            "store": store.id,
            "customer_name": name,
            "customer_phone": phone,
            "customer_email": email,
            "date": date,
            "start_time": start_time_parsed,  
            "end_time": end_time_parsed,      
            "status": "Pending",
            "is_day_off": False,
            "title": f"Appointment with {therapist.username}",
            "color": "#00FF00"
        }

        # Validate and save the appointment
        serializer = TherapistScheduleSerializer(data=schedule_data, context={'request': request})
        if serializer.is_valid():
            appointment = serializer.save()

            # Send SMS to the user confirming the booking as 'Pending'
            message_body = (
                f"Dear {name}, your appointment at {store.name} with {therapist.username} is pending for {date} "
                f"from {start_time_parsed} to {end_time_parsed}. It will be confirmed shortly."
            )
            self.send_sms(phone, message_body)

            # Notify the therapist and manager
            self.notify_therapist_and_manager(therapist, store, date, start_time_parsed, end_time_parsed, name)

            return Response({
                "message": "Appointment booked successfully",
                "appointment_id": appointment.id,
                "therapist_id": therapist.id,
                "store_id": store.id,
                "customer_name": name
            }, status=status.HTTP_201_CREATED)
            
        print(serializer.errors)  # Debugging output
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    def send_sms_confirmation(self, name, phone, store, therapist, date, start_time, end_time):
        # Logic to send SMS to the user confirming the booking as 'Pending'
        message_body = (
            f"Dear {name}, your appointment at {store.name} with {therapist.username} is pending for {date} "
            f"from {start_time} to {end_time}. It will be confirmed shortly."
        )
        self.send_sms(phone, message_body)

    def send_sms(self, to, message_body):
        account_sid = settings.TWILIO_ACCOUNT_SID
        auth_token = settings.TWILIO_AUTH_TOKEN
        twilio_phone_number = settings.TWILIO_PHONE_NUMBER

        client = Client(account_sid, auth_token)
        try:
            message = client.messages.create(
                from_=f'whatsapp:{twilio_phone_number}',
                body=message_body,
                to=f'whatsapp:{to}'
            )
            print(f"SMS sent: {message.sid}")
        except Exception as e:
            print(f"Failed to send SMS: {str(e)}")

    def notify_therapist_and_manager(self, therapist, store, date, start_time, end_time, username):
        phone_number_therapist = therapist.phone
        phone_number_manager = store.manager.phone if hasattr(store, 'manager') else None

        # Message to the therapist
        message_body_therapist = (
            f"Dear {therapist.username}, you have a new appointment at {store.name} "
            f"on {date} from {start_time} to {end_time}. "
            f"Booked by: {username}."
        )
        self.send_sms(phone_number_therapist, message_body_therapist)
        
        # Message to the manager if available
        if phone_number_manager:
            message_body_manager = (
                f"Dear {store.manager.username}, a new appointment has been booked for {therapist.username} "
                f"at {store.name} on {date} from {start_time} to {end_time}. "
                f"Booked by: {username}."
            )
            self.send_sms(phone_number_manager, message_body_manager)


class UpdateAppointmentStatusAPI(APIView):
    permission_classes = [IsAuthenticated]  # Only authenticated users should access

    def patch(self, request, appointment_id):
        status_action = request.data.get('status', None)
        new_start_datetime = request.data.get('new_start', None)
        new_end_datetime = request.data.get('new_end', None)
    
        if status_action not in ['Confirmed', 'Cancelled', 'Rescheduled']:
            return Response({"error": "Invalid status action"}, status=status.HTTP_400_BAD_REQUEST)
    
        # Fetch the appointment
        try:
            appointment = TherapistSchedule.objects.get(id=appointment_id)
        except TherapistSchedule.DoesNotExist:
            return Response({"error": "Appointment not found"}, status=status.HTTP_404_NOT_FOUND)
    
        # Ensure the user is authorized to modify the appointment
        if not self.is_authorized_user(request.user, appointment):
            return Response({"error": "You are not authorized to modify this appointment"}, status=status.HTTP_403_FORBIDDEN)
    
        previous_status = appointment.status  # For logging purposes
    
        # Handle Reschedule case: update datetime and notify customer
        
        if status_action == 'Rescheduled':
            if not new_start_datetime or not new_end_datetime:
                return Response({"error": "New start and end datetime must be provided for rescheduling"}, status=status.HTTP_400_BAD_REQUEST)

            try:
                new_start_datetime = datetime.strptime(new_start_datetime, "%Y-%m-%d %H:%M")
                new_end_datetime = datetime.strptime(new_end_datetime, "%Y-%m-%d %H:%M")
            except ValueError:
                return Response({"error": "Invalid datetime format. Use YYYY-MM-DD HH:MM."}, status=status.HTTP_400_BAD_REQUEST)

             # Combine date with new start and end time and ensure timezone awareness
            new_start_datetime = timezone.make_aware(timezone.datetime.combine(appointment.date, new_start_datetime.time()))
            new_end_datetime = timezone.make_aware(timezone.datetime.combine(appointment.date, new_end_datetime.time()))

            # Check if the new time slot overlaps with another confirmed appointment on the same date
            if TherapistSchedule.objects.filter(
                therapist=appointment.therapist,
                date=appointment.date,
                start_time__lt=new_end_datetime.time(),
                end_time__gt=new_start_datetime.time(),
                status='Confirmed'
            ).exists():
                return Response({"error": "The new time slot overlaps with another appointment on this date"}, status=status.HTTP_400_BAD_REQUEST)

            # Store the previous appointment times for notification
            previous_start = appointment.start_time
            previous_end = appointment.end_time

            # Update the appointment with new time and status
            appointment.start_time = new_start_datetime.time()  
            appointment.end_time = new_end_datetime.time()      
            appointment.status = 'Rescheduled'
            appointment.save()

            # Notify the customer about the rescheduled appointment
            self.send_reschedule_sms(appointment, previous_start, previous_end)

            # Include the previous and new times in the response
            response_data = {
                "message": "Appointment rescheduled successfully",
                "previous_start": previous_start.strftime('%Y-%m-%d %H:%M'),
                "previous_end": previous_end.strftime('%Y-%m-%d %H:%M'),
                "new_start": new_start_datetime.strftime('%Y-%m-%d %H:%M'),
                "new_end": new_end_datetime.strftime('%Y-%m-%d %H:%M'),
                "store_name": appointment.store.name,
                "therapist_name": appointment.therapist.username,
                "customer_name": appointment.customer_name
            }
            return Response(response_data, status=status.HTTP_200_OK)

        # Handle Confirm and Cancel cases
        elif status_action in ['Confirmed', 'Cancelled']:
            if appointment.status == 'Confirmed' and status_action == 'Confirmed':
                return Response({"error": "This appointment is already confirmed"}, status=status.HTTP_400_BAD_REQUEST)
    
            appointment.status = status_action
            appointment.save()

            # If the appointment is canceled, include a promo code in the message
            if status_action == 'Cancelled':
                promo_code = self.generate_promo_code()  # Generate a promo code
                message_body = (
                    f"Dear {appointment.customer_name}, we are sorry for the inconvenience. "
                    f"Your appointment at {appointment.store.name} with {appointment.therapist.username} has been canceled. "
                    f"As a gesture of goodwill, please use the promo code '{promo_code}' for a discount on your next booking. "
                    f"The appointment was originally scheduled from {appointment.start_time.strftime('%Y-%m-%d %H:%M')} "
                    f"to {appointment.end_time.strftime('%Y-%m-%d %H:%M')}."
                )
            else:
                message_body = (
                    f"Dear {appointment.customer_name}, your appointment at {appointment.store.name} "
                    f"with {appointment.therapist.username} has been confirmed "
                    f"for {appointment.date.strftime('%Y-%m-%d')} from {appointment.start_time.strftime('%H:%M')} "
                    f"to {appointment.end_time.strftime('%H:%M')}."
                )

    
            self.send_sms(appointment.customer_phone, message_body)
    
        # Log the status change
        print(f"Appointment {appointment_id} status changed from {previous_status} to {status_action} by {request.user.username}")
    
        return Response({"message": f"Appointment {status_action.lower()} successfully"}, status=status.HTTP_200_OK)

    def is_authorized_user(self, user, appointment):
        if user.role == 'Owner' and appointment.store.owner == user:
            return True
        elif user.role == 'Manager' and user in appointment.store.managers.all():
            return True
        elif user.role == 'Therapist' and appointment.therapist == user:
            return True
        return False

    def generate_promo_code(self):
        # For now,use a predefined promo code or generate one
        import random
        import string
        return ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))

    def send_sms(self, to, message_body):
        account_sid = settings.TWILIO_ACCOUNT_SID
        auth_token = settings.TWILIO_AUTH_TOKEN
        twilio_phone_number = settings.TWILIO_PHONE_NUMBER

        client = Client(account_sid, auth_token)
        try:
            message = client.messages.create(
                from_=f'whatsapp:{twilio_phone_number}',
                body=message_body,
                to=f'whatsapp:{to}'
            )
            print(f"SMS sent: {message.sid}")
        except Exception as e:
            print(f"Failed to send SMS: {str(e)}")

    def send_reschedule_sms(self, appointment, previous_start, previous_end):
        confirmation_link = f"{settings.FRONTEND_URL}/#/confirm-reschedule/?{appointment.id}"

        # Combine the appointment date with the previous start and end times
        previous_start_datetime = timezone.datetime.combine(appointment.date, previous_start)
        previous_end_datetime = timezone.datetime.combine(appointment.date, previous_end)

        # Format the previous and new start/end times for clear presentation
        previous_time_str = (
            f"from {previous_start_datetime.strftime('%Y-%m-%d')} {previous_start_datetime.strftime('%H:%M')} "
            f"to {previous_end_datetime.strftime('%Y-%m-%d')} {previous_end_datetime.strftime('%H:%M')}"
        )

        new_start_datetime = timezone.datetime.combine(appointment.date, appointment.start_time)
        new_end_datetime = timezone.datetime.combine(appointment.date, appointment.end_time)

        new_time_str = (
            f"from {new_start_datetime.strftime('%Y-%m-%d')} {new_start_datetime.strftime('%H:%M')} "
            f"to {new_end_datetime.strftime('%Y-%m-%d')} {new_end_datetime.strftime('%H:%M')}"
        )

        # Compose the SMS message
        message_body = (
            f"Dear {appointment.customer_name}, your appointment with {appointment.therapist.username} "
            f"at {appointment.store.name} has been rescheduled. The original appointment was {previous_time_str}, "
            f"and the new appointment time is {new_time_str}. "
            f"Please confirm the new time by clicking here: {confirmation_link}."
        )

        self.send_sms(appointment.customer_phone, message_body)

class ConfirmRescheduledAppointmentAPI(APIView):
    permission_classes = []  # No authentication required for customer confirmation

    def post(self, request, appointment_id):
        # Fetch the appointment
        try:
            appointment = TherapistSchedule.objects.get(id=appointment_id, status='Rescheduled')
        except TherapistSchedule.DoesNotExist:
            return Response({"error": "Appointment not found or not rescheduled"}, status=status.HTTP_404_NOT_FOUND)

        # Prevent confirmation of expired appointments
        if appointment.date < timezone.now().date() or (appointment.date == timezone.now().date() and appointment.end_time < timezone.now().time()):
            return Response({"error": "The appointment time has already passed"}, status=status.HTTP_400_BAD_REQUEST)

        # Get customer's confirmation response
        confirmation_status = request.data.get('confirmation_status', None)
        if confirmation_status not in ['Confirmed', 'Declined']:
            return Response({"error": "Invalid confirmation status"}, status=status.HTTP_400_BAD_REQUEST)

        # Update the appointment's status based on the customer's confirmation
        if confirmation_status == 'Confirmed':
            appointment.status = 'Confirmed'
        else:  # confirmation_status == 'Declined'
            appointment.status = 'Cancelled'

        appointment.customer_confirmation_status = confirmation_status
        appointment.save()

        # Notify therapist and store manager about the confirmation or decline
        self.notify_therapist_and_manager(appointment)

        return Response({"message": f"Appointment {confirmation_status.lower()} successfully"}, status=status.HTTP_200_OK)

    def notify_therapist_and_manager(self, appointment):
        message_body = f"The customer has {appointment.customer_confirmation_status.lower()} the appointment on {appointment.date}."

        # Notify the therapist
        if appointment.therapist.phone:
            self.send_sms(appointment.therapist.phone, message_body)

        # Notify the store manager if exists
        if appointment.store.manager and appointment.store.manager.phone:
            self.send_sms(appointment.store.manager.phone, message_body)

    def send_sms(self, to, message_body):
        account_sid = settings.TWILIO_ACCOUNT_SID
        auth_token = settings.TWILIO_AUTH_TOKEN
        twilio_phone_number = settings.TWILIO_PHONE_NUMBER

        client = Client(account_sid, auth_token)
        try:
            message = client.messages.create(
                from_=f'whatsapp:{twilio_phone_number}',
                body=message_body,
                to=f'whatsapp:{to}'
            )
            print(f"SMS sent: {message.sid}")
        except Exception as e:
            print(f"Failed to send SMS: {str(e)}")

class AppointmentDetailsAPI(APIView):
    
    def get(self, request, appointment_id):
        # Fetch the appointment by ID
        try:
            appointment = TherapistSchedule.objects.get(id=appointment_id)
        except TherapistSchedule.DoesNotExist:
            return Response({"error": "Appointment not found"}, status=status.HTTP_404_NOT_FOUND)

        # Prepare appointment data
        data = {
            "id": appointment.id,
            "therapist": appointment.therapist.username,
            "customer_name": appointment.customer_name,
            "customer_phone": appointment.customer_phone,
            "customer_email": appointment.customer_email,
            "store": appointment.store.name,
            "status": appointment.status,
            "current_start_time": timezone.datetime.combine(appointment.date, appointment.start_time).strftime('%Y-%m-%d %H:%M'),
            "current_end_time": timezone.datetime.combine(appointment.date, appointment.end_time).strftime('%Y-%m-%d %H:%M'),
        }

        # If the appointment was rescheduled, include previous times
        if appointment.status == 'Rescheduled':
            previous_start = appointment.previous_start_time
            previous_end = appointment.previous_end_time

            # Format previous times if they exist
            if previous_start and previous_end:
                data['previous_start_time'] = previous_start.strftime('%Y-%m-%d %H:%M')
                data['previous_end_time'] = previous_end.strftime('%Y-%m-%d %H:%M')

        return Response(data, status=status.HTTP_200_OK)


class AppointmentsByStoreAPI(APIView):
    permission_classes = []  

    def get(self, request, store_id):
        # Fetch confirmed and rescheduled appointments for the store
        appointments = TherapistSchedule.objects.filter(store_id=store_id, status__in=['Confirmed', 'Rescheduled'])

        if not appointments.exists():
            return Response({"error": "No appointments found for this store"}, status=status.HTTP_404_NOT_FOUND)

        # Prepare a response with additional fields for rescheduled appointments
        appointment_data = []
        for appointment in appointments:
            data = {
                "id": appointment.id,
                "therapist": appointment.therapist.username,
                "customer_name": appointment.customer_name,
                "customer_phone": appointment.customer_phone,
                "customer_email": appointment.customer_email,
                "store": appointment.store.name,
                "status": appointment.status,
                "start_time": appointment.start_time.strftime('%Y-%m-%d %H:%M'),
                "end_time": appointment.end_time.strftime('%Y-%m-%d %H:%M'),
            }

            # If the appointment was rescheduled, include previous times
            if appointment.status == 'Rescheduled':
                previous_start = appointment.previous_start_time
                previous_end = appointment.previous_end_time

                # Format previous times if they exist
                if previous_start and previous_end:
                    data['previous_start_time'] = previous_start.strftime('%Y-%m-%d %H:%M')
                    data['previous_end_time'] = previous_end.strftime('%Y-%m-%d %H:%M')

            appointment_data.append(data)

        return Response(appointment_data, status=status.HTTP_200_OK)
    

# Get Role Details API
class RoleDetailsAPI(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        serializer = UserSerializer(request.user)
        return Response(serializer.data)

# Update Manager Profile
class UpdateManagerProfileAPI(APIView):
    permission_classes = [IsAuthenticated]

    def put(self, request):
        user = request.user
        if user.role != 'Manager':
            return Response({"error": "Unauthorized"}, status=status.HTTP_403_FORBIDDEN)
        
        serializer = UserSerializer(user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            updated_user = User.objects.get(id=user.id)  # Fetch updated user data
            
            return Response({
                "message": "Profile updated successfully",
                "user_id": updated_user.id,
                "username": updated_user.username,
                "phone": updated_user.phone,
                "email": updated_user.email,
                "experience": updated_user.exp,  # Ensure that experience is correctly included
                "specialty": updated_user.specialty
            }, status=status.HTTP_200_OK)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# Update Therapist Profile
class UpdateTherapistProfileAPI(APIView):
    permission_classes = [IsAuthenticated]

    def put(self, request):
        user = request.user
        if user.role != 'Therapist':
            return Response({"error": "Unauthorized"}, status=status.HTTP_403_FORBIDDEN)
        
        serializer = TherapistSerializer(user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            updated_user = User.objects.get(id=user.id)  # Fetch updated user data
            return Response({
                "message": "Profile updated successfully",
                "user_id": updated_user.id,
                "username": updated_user.username,
                "phone": updated_user.phone,
                "email": updated_user.email,
                "experience": updated_user.exp,
                "specialty": updated_user.specialty
            }, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# Update Store Details API
class UpdateStoreDetailsAPI(APIView):
    permission_classes = [IsAuthenticated]

    def put(self, request, store_id):
        store = get_object_or_404(Store, id=store_id)
        if not (request.user.role == 'Owner' or request.user in store.managers.all()):
            return Response({"error": "Unauthorized"}, status=status.HTTP_403_FORBIDDEN)

        serializer = StoreSerializer(store, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({
                "message": "Store updated successfully",
                "store_id": store.id
            }, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# Store and Staff Details API
class StoreStaffDetailsAPI(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, store_id):
        store = get_object_or_404(Store, id=store_id)
        if not (request.user.role == 'Owner' or request.user in store.managers.all()):
            return Response({"error": "Unauthorized"}, status=status.HTTP_403_FORBIDDEN)

        store_serializer = StoreSerializer(store)

        # Staff details with experience and specialty for therapists
        therapist_data = []
        for therapist in store.therapists.all():
            therapist_data.append({
                "therapist_id": therapist.id,
                "therapist_name": therapist.username,
                "therapist_exp": therapist.exp,  
                "therapist_specialty": therapist.specialty  
            })

        # Manager details with only experience
        manager_data = []
        for manager in store.managers.all():
            manager_data.append({
                "manager_id": manager.id,
                "manager_name": manager.username,
                "manager_exp": manager.exp  
            })

        return Response({
            "store": store_serializer.data,
            "managers": manager_data,
            "therapists": therapist_data,
        }, status=status.HTTP_200_OK)
        
        
class AllSchedulesAPI(APIView):
    permission_classes = [AllowAny]

    def get(self, request, store_id):
        store = get_object_or_404(Store, id=store_id)

        # Store schedule
        store_schedule = {
            "opening_days": store.opening_days,
            "start_time": store.start_time,
            "end_time": store.end_time,
            "lunch_start_time": store.lunch_start_time,
            "lunch_end_time": store.lunch_end_time
        }

        # Manager schedules
        manager_schedules = []
        for manager in store.managers.all():
            manager_schedule = ManagerSchedule.objects.filter(manager=manager).values('date', 'start_time', 'end_time')
            manager_schedules.append({
                "manager_id": manager.id,
                "manager_name": manager.username,
                "schedule": list(manager_schedule)
            })

        # Therapist schedules
        therapist_schedules = []
        for therapist in store.therapists.all():
            therapist_schedule = TherapistSchedule.objects.filter(therapist=therapist).values('date', 'start_time', 'end_time', 'is_day_off')
            therapist_schedules.append({
                "therapist_id": therapist.id,
                "therapist_name": therapist.username,
                "schedule": list(therapist_schedule)
            })

        return Response({
            "store_schedule": store_schedule,
            "manager_schedules": manager_schedules,
            "therapist_schedules": therapist_schedules
        }, status=status.HTTP_200_OK)


class StoreScheduleAPI(APIView):
    permission_classes = [AllowAny]

    def get(self, request, store_id):
        store = get_object_or_404(Store, id=store_id)
        return Response({
            "store_id": store.id,
            "store_schedule": {
                "opening_days": store.opening_days,
                "start_time": store.start_time,
                "end_time": store.end_time,
                "lunch_start_time": store.lunch_start_time,
                "lunch_end_time": store.lunch_end_time
            }
        }, status=status.HTTP_200_OK)


class ManagerScheduleAPI(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, manager_id):
        manager = get_object_or_404(User, id=manager_id, role='Manager')
        schedule = ManagerSchedule.objects.filter(manager=manager).values('date', 'start_time', 'end_time')
        return Response({
            "manager_id": manager_id,
            "schedule": list(schedule)
    
            }, status=status.HTTP_200_OK)

class TherapistScheduleAPI(APIView):
    # permission_classes = [IsAuthenticated]

    def get(self, request, therapist_id):
        therapist = get_object_or_404(User, id=therapist_id, role='Therapist')

        # Get start and end date from query params (optional)
        start_date = request.query_params.get('start_date')
        end_date = request.query_params.get('end_date')

        # Fetch therapist's schedule (both own schedule and customer bookings)
        if start_date and end_date:
            therapist_schedule = TherapistSchedule.objects.filter(
                therapist=therapist,
                date__range=[start_date, end_date]
            )
        else:
            therapist_schedule = TherapistSchedule.objects.filter(therapist=therapist)

        # Separate own schedule from customer bookings
        own_schedule = []
        customer_bookings = []

        for slot in therapist_schedule:
            # Consider a schedule without customer info as therapist's own schedule
            if (slot.customer_name == "Unknown Customer" and slot.customer_phone == "Unknown Phone"):
                own_schedule.append(slot)
            else:
                customer_bookings.append(slot)

        # If no customer bookings or own schedules are found, return an empty response
        if not customer_bookings and not own_schedule:
            return Response({
                "therapist_id": therapist_id,
                "therapist_name": therapist.username,
                "schedules": [],
                "pendingBookings": [],
                "confirmedBookings": []
            }, status=status.HTTP_200_OK)

        # Split customer bookings into pending and confirmed
        pending_bookings = []
        confirmed_bookings = []

        for booking in customer_bookings:
            appointment_data = {
                "title": "booked",
                "appointment_id": booking.id,
                "name": booking.customer_name,
                "phone": booking.customer_phone,
                "email": booking.customer_email,  
                "start": f"{booking.date} {booking.start_time}",
                "end": f"{booking.date} {booking.end_time}",
                "date": str(booking.date)
            }

            if booking.status == "Pending":
                pending_bookings.append(appointment_data)
            elif booking.status == "Confirmed":
                confirmed_bookings.append(appointment_data)

        # Prepare own schedule data (non-customer bookings)
        own_schedule_data = [
            {
                "start": f"{slot.date} {slot.start_time}",
                "end": f"{slot.date} {slot.end_time}",
                "date": str(slot.date),
                "title": slot.title,  
                "color": slot.color  
            }
            for slot in own_schedule
        ]

        return Response({
            "therapist_id": therapist_id,
            "therapist_name": therapist.username,
            "schedules": own_schedule_data,
            "pendingBookings": pending_bookings,
            "confirmedBookings": confirmed_bookings
        }, status=status.HTTP_200_OK)

        
class ListAllBookingsAPI(generics.ListAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = TherapistScheduleSerializer

    def get_queryset(self):
        user = self.request.user
        if user.role == 'Owner':
            # Owner can view all appointments across all stores they own
            return TherapistSchedule.objects.filter(store__owner=user)
        elif user.role == 'Manager':
            # Manager can view all appointments for stores they manage
            return TherapistSchedule.objects.filter(store__managers=user)
        elif user.role == 'Therapist':
            # Therapist can only view their own appointments
            return TherapistSchedule.objects.filter(therapist=user)
        
        # Filter by status
        status_filter = self.request.query_params.get('status', None)
        if status_filter:
            queryset = queryset.filter(status=status_filter)

        return queryset

class StoreListAPI(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        if request.user.role == 'Owner':
            stores = Store.objects.filter(owner=request.user)
        elif request.user.role == 'Manager':
            stores = Store.objects.filter(managers=request.user)
        elif request.user.role == 'Therapist':
            stores = Store.objects.filter(therapists=request.user)
        else:
            return Response({"error": "Unauthorized"}, status=status.HTTP_403_FORBIDDEN)

        store_data = [{"id": store.id, "name": store.name} for store in stores]
        return Response(store_data, status=status.HTTP_200_OK)
    
    
stripe.api_key = settings.STRIPE_SECRET_KEY



# Constants for Plan Prices
PLAN_PRICE_MAP = {
    'starter': 'si_R4r3GLIO5C9kDg',
    'pro': 'si_R4r3RsYTWjMY3w',
    'business': 'si_R4r33UfFkCopUL'
}

# Helper function to create Stripe customer
def create_stripe_customer(user):
    """Creates a Stripe customer if not already created."""
    if not user.stripe_customer_id:
        try:
            customer = stripe.Customer.create(
                email=user.email,
                name=user.username,
                phone=user.phone
            )
            user.stripe_customer_id = customer.id
            user.save()
            logger.info(f"Stripe customer created for user: {user.email}")
        except Exception as e:
            logger.error(f"Error creating Stripe customer: {str(e)}")
            raise


class CreateCheckoutSessionView(APIView):
    """Create a checkout session for the selected plan."""
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user
        plan_name = request.data.get('plan')

        if plan_name not in PLAN_PRICE_MAP:
            return Response({"error": "Invalid plan"}, status=400)

        price_id = PLAN_PRICE_MAP[plan_name]

        try:
            # Create Stripe customer if not already created
            create_stripe_customer(user)

            # Create the checkout session
            checkout_session = stripe.checkout.Session.create(
                customer=user.stripe_customer_id,
                success_url="http://localhost:9000/#/successpayment?session_id={CHECKOUT_SESSION_ID}",
                cancel_url=f"{settings.FRONTEND_URL}/cancel",
                payment_method_types=['card'],
                line_items=[{'price': price_id, 'quantity': 1}],
                mode='subscription',
                metadata={'user': user.email}
            )

            logger.info(f"Checkout session created for user {user.email} with plan {plan_name}")
            return JsonResponse({
                'url': checkout_session.url,
                'stripe_public_key': settings.STRIPE_PUBLISHABLE_KEY,
            }, status=201)

        except Exception as e:
            logger.error(f"Error creating checkout session: {str(e)}")
            return Response({'error': str(e)}, status=400)

class SuccessView(APIView):
    """Handle the success URL from Stripe checkout."""
    permission_classes = [AllowAny]

    def get(self, request, *args, **kwargs):
        stripe.api_key = settings.STRIPE_SECRET_KEY
        session_id = request.query_params.get('session_id')

        if not session_id:
            logger.error("Session ID not provided")
            return Response({"error": "Session ID not provided"}, status=400)

        try:
            session = stripe.checkout.Session.retrieve(session_id)
            subscription_id = session.subscription
            subscription = stripe.Subscription.retrieve(subscription_id)
            user_email = session.metadata.get('user')

            user = get_object_or_404(User, email=user_email)
            latest_invoice = stripe.Invoice.retrieve(subscription.latest_invoice)
            payment_intent_id = latest_invoice.payment_intent

            if not payment_intent_id:
                logger.error("Payment Intent ID not found in invoice")
                return Response({"error": "Payment Intent ID not found"}, status=400)

            Subscription.objects.create(
                stripe_subscription_id=subscription.id,
                payment_intent_id=payment_intent_id,
                user=user,
                subscription_renewed=datetime.fromtimestamp(subscription.current_period_start).strftime('%Y-%m-%d'),
                subscription_expired=datetime.fromtimestamp(subscription.current_period_end).strftime('%Y-%m-%d'),
                status=subscription.status
            )

            return HttpResponseRedirect("http://localhost:9000/#/successpayment")

        except Exception as e:
            logger.error(f"Unexpected error: {str(e)}")
            return HttpResponseRedirect(f"{settings.FRONTEND_URL}/subscription/response?response=error&message={str(e)}")

# Stripe webhook to handle subscription events
@csrf_exempt
def stripe_webhook(request):
    stripe.api_key = settings.STRIPE_SECRET_KEY
    payload = request.body.decode('utf-8')
    sig_header = request.META.get('HTTP_STRIPE_SIGNATURE')

    try:
        event = stripe.Webhook.construct_event(payload, sig_header, settings.STRIPE_WEBHOOK_SECRET)
    except (ValueError, stripe.error.SignatureVerificationError):
        logger.warning("Invalid Stripe webhook signature or payload")
        return JsonResponse({'error': 'Invalid signature or payload'}, status=400)

    # Handle relevant events
    event_type = event['type']
    if event_type.startswith('customer.subscription.'):
        handle_subscription_events(event)
    elif event_type.startswith('payment_intent.'):
        handle_payment_intent_events(event)

    return JsonResponse({'status': 'success'}, status=200)

# Helper functions for handling Stripe subscription events
def handle_subscription_events(event):
    subscription = event['data']['object']
    user_email = subscription['metadata']['user']

    try:
        user = User.objects.get(email=user_email)

        if event['type'] == 'customer.subscription.created':
            latest_invoice = stripe.Invoice.retrieve(subscription['latest_invoice'])
            payment_intent_id = latest_invoice['payment_intent']
            Subscription.objects.create(
                stripe_subscription_id=subscription['id'],
                payment_intent_id=payment_intent_id,
                user=user,
                subscription_renewed=datetime.fromtimestamp(subscription['current_period_start']).strftime('%Y-%m-%d'),
                subscription_expired=datetime.fromtimestamp(subscription['current_period_end']).strftime('%Y-%m-%d'),
                status=subscription['status']
            )
        elif event['type'] == 'customer.subscription.updated':
            sub = Subscription.objects.get(stripe_subscription_id=subscription['id'])
            sub.status = subscription['status']
            sub.subscription_renewed = datetime.fromtimestamp(subscription['current_period_start']).strftime('%Y-%m-%d')
            sub.subscription_expired = datetime.fromtimestamp(subscription['current_period_end']).strftime('%Y-%m-%d')
            sub.save()
        elif event['type'] == 'customer.subscription.deleted':
            sub = Subscription.objects.get(stripe_subscription_id=subscription['id'])
            sub.status = subscription['status']
            sub.save()

        # Log the event in StripeEvents
        StripeEvents.objects.create(
            event_id=event['id'],
            event_type=event['type'],
            event_data=json.dumps(event['data']),
            subscription=sub if event['type'] != 'customer.subscription.deleted' else None
        )

    except User.DoesNotExist:
        logger.error(f"User with email {user_email} not found")
    except Exception as e:
        logger.error(f"Error handling subscription event: {str(e)}")

def handle_payment_intent_events(event):
    payment_intent = event['data']['object']
    user_email = payment_intent['metadata']['user']

    try:
        user = User.objects.get(email=user_email)
        stripe.PaymentIntent.objects.update_or_create(
            payment_intent_id=payment_intent['id'],
            defaults={
                'user': user,
                'amount': payment_intent['amount'],
                'currency': payment_intent['currency'],
                'status': payment_intent['status'],
            }
        )

        # Log the event in StripeEvents
        StripeEvents.objects.create(
            event_id=event['id'],
            event_type=event['type'],
            event_data=json.dumps(event['data'])
        )

    except Exception as e:
        logger.error(f"Error handling payment intent event: {str(e)}")

class AllSubscriptionsView(APIView):
    """Return all subscriptions and payment intents."""
    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):
        subscriptions = Subscription.objects.all()
        payment_intents = stripe.PaymentIntent.objects.all()

        subscription_serializer = SubscriptionSerializer(subscriptions, many=True)
        payment_intent_serializer = PaymentIntentSerializer(payment_intents, many=True)

        return Response({
            'subscriptions': subscription_serializer.data,
            'payment_intents': payment_intent_serializer.data
        }, status=200)

# Success and cancel views for Stripe checkout
def success(request):
    return render(request, 'success.html')

def cancel(request):
    return render(request, 'cancel.html')
