from rest_framework import serializers
from .models import User, Store, TherapistSchedule
from datetime import datetime

# User Serializer
from .models import User, Store, TherapistSchedule, ManagerSchedule,Plan, Subscription,PaymentIntent

class UserSerializer(serializers.ModelSerializer):
    experience = serializers.SerializerMethodField()
    schedule = serializers.SerializerMethodField()
    
    class Meta:
        model = User
        fields = [
            'id','username', 'role', 'experience', 'phone', 'email', 
            'image', 'description', 'is_active', 'schedule'
        ]

    def update(self, instance, validated_data):
        # Update fields if they are provided in the request
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        
        instance.save()
        return instance
    
    def get_experience(self, instance):
        return f'{instance.exp} years' if instance.role in ['Therapist', 'Manager'] and instance.exp else 'N/A'
    
    def get_schedule(self, instance):
        if instance.role == 'Therapist':
            schedules = TherapistSchedule.objects.filter(therapist=instance)
        elif instance.role == 'Manager':
            schedules = ManagerSchedule.objects.filter(manager=instance)
        else:
            return []

        schedule_data = []
        for schedule in schedules:
            schedule_data.append({
                "backgroundColor": "#21BA45",
                "borderColor": "#21BA45",
                "editable": True,
                "start": schedule.start_time.strftime('%Y-%m-%d %H:%M:%S'),
                "end": schedule.end_time.strftime('%Y-%m-%d %H:%M:%S'),
                "title": instance.username
            })
        return schedule_data
    def to_representation(self, instance):
        data = super().to_representation(instance)
        data['username'] = instance.username
        # Role-based conditional logic
        if instance.role == 'Therapist':
            data['exp'] = instance.exp
            data['specialty'] = instance.specialty
        elif instance.role == 'Manager':
            data['exp'] = instance.exp
            data.pop('specialty', None)
        else:
            data.pop('exp', None)
            data.pop('specialty', None)
        
        return data
# Register Serializer
class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=True, style={'input_type': 'password'})
    password2 = serializers.CharField(write_only=True, required=True, style={'input_type': 'password'})

    class Meta:
        model = User
        fields = ['username', 'email', 'phone', 'password', 'password2']

    def validate(self, data):
        """
        Check that the two password fields match.
        """
        if data['password'] != data['password2']:
            raise serializers.ValidationError({"password": "Passwords do not match."})
        
        # Optionally, add more password validation rules (Django's validate_password is already called)
        return data

    def validate_email(self, value):
        """
        Check if the email is valid and not already in use.
        """
        if value and User.objects.filter(email=value).exists():
            raise serializers.ValidationError("Email is already in use.")
        return value

    def validate_phone(self, value):
        """
        Check if the phone number is unique.
        """
        if User.objects.filter(phone=value).exists():
            raise serializers.ValidationError("Phone number is already in use.")
        return value

    def create(self, validated_data):
        # Remove password2 as it's not needed in the User model
        validated_data.pop('password2')
        
        # Create user
        user = User.objects.create_user(
            username=validated_data['username'],
            phone=validated_data['phone'],
            password=validated_data['password'],
            email=validated_data.get('email', None)
        )
        return user
# Store Serializer
class StoreSerializer(serializers.ModelSerializer):
    managers = UserSerializer(many=True,required=False)
    therapists = UserSerializer(many=True,required=False)
    owner = serializers.ReadOnlyField(source='owner.id')
    class Meta:
        model = Store
        fields = '__all__'

# Staff Serializer (For Managers and Therapists)
class StaffSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = '__all__'  
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        username = validated_data['username']
        phone = validated_data['phone']
        password = validated_data['password']
        email = validated_data.get('email', None)
        role = validated_data.get('role', None)
        exp = validated_data.get('exp', None)  
        specialty = validated_data.get('specialty', None)  
        
        if role == 'Therapist':
            if exp is None:
                exp = 0  # Default exp to 0 if not provided
            if specialty == '':
                specialty = None  
        elif role == 'Manager':
            if exp is None:
                exp = 0
        
        user = User.objects.create_user(
            username=username,  
            phone=phone,
            password=password,
            email=email,
            role=role,
            exp=exp,  
            specialty=specialty
        )
        if role == 'Manager' and exp is not None:
            user.exp = exp  
        elif role == 'Therapist':
            user.exp = exp
            user.specialty = specialty  

        user.save()
        return user

class ManageTherapistScheduleSerializer(serializers.ModelSerializer):
    therapist = serializers.PrimaryKeyRelatedField(queryset=User.objects.filter(role='Therapist'), required=True)
    store = serializers.PrimaryKeyRelatedField(queryset=Store.objects.all(), required=True)
    backgroundColor = serializers.CharField(source='color', required=False)
    start_time = serializers.TimeField(required=True)  # Accept as hh:mm[:ss[.uuuuuu]] format
    end_time = serializers.TimeField(required=True)    

    class Meta:
        model = TherapistSchedule
        fields = ['therapist', 'store', 'title', 'backgroundColor', 'date', 'start_time', 'end_time']

    def validate(self, data):
        start_time = data.get('start_time')
        end_time = data.get('end_time')

        if not start_time or not end_time:
            raise serializers.ValidationError("Both start and end time are required.")

        # Combine with date to create datetime for validation
        date = data.get('date')
        if not date:
            raise serializers.ValidationError("Date is required.")

        # Ensure start time is before end time
        if start_time >= end_time:
            raise serializers.ValidationError("End time must be after start time.")

        therapist = data.get('therapist', None)
        store = data.get('store', None)

        # Check if therapist is assigned to the store
        if therapist and store:
            if therapist not in store.therapists.all():
                raise serializers.ValidationError("Selected therapist is not assigned to this store.")

        # Check for existing bookings including date
        existing_bookings = TherapistSchedule.objects.filter(
            therapist=therapist,
            store=store,
            date=date,
            start_time__lt=end_time,
            end_time__gt=start_time
        )

        if existing_bookings.exists():
            raise serializers.ValidationError("Therapist is already booked during this time slot.")

        return data


    def create(self, validated_data):
        # Create the TherapistSchedule instance with validated data
        validated_data['color'] = validated_data.pop('backgroundColor', None)  # Handle color field
        
        # Ensure required fields are set
        return TherapistSchedule.objects.create(**validated_data)
        
        
class TherapistScheduleSerializer(serializers.ModelSerializer):
    backgroundColor = serializers.CharField(source='color', required=False)
    therapist = serializers.PrimaryKeyRelatedField(
        queryset=User.objects.filter(role='Therapist'), 
        required=True
    )
    store = serializers.PrimaryKeyRelatedField(
        queryset=Store.objects.all(), 
        required=True
    )
    
    start_time = serializers.TimeField(required=True)
    end_time = serializers.TimeField(required=True)

    class Meta:
        model = TherapistSchedule
        fields = [
            'id', 'therapist', 'store', 'date', 'start_time', 'end_time', 
            'is_day_off', 'status', 'title', 'color', 'customer_name', 
            'backgroundColor', 'customer_phone', 'customer_email', 
            'customer_confirmation_status',
        ]

    def validate(self, data):
        start_time = data.get('start_time')
        end_time = data.get('end_time')

        if start_time and end_time:
            if start_time >= end_time:
                raise serializers.ValidationError("End time must be after start time.")
        else:
            raise serializers.ValidationError("Both start time and end time are required.")
    
        # Check if it's a day off; if not, customer details must be provided
        is_day_off = data.get('is_day_off', False)
        if not is_day_off:
            if not data.get('customer_name') or not data.get('customer_phone'):
                raise serializers.ValidationError("Customer name and phone are required for bookings.")
    
        therapist = data.get('therapist', None)
        store = data.get('store', None)
    
        # Ensure the selected therapist is assigned to the store
        if therapist and store:
            if therapist not in store.therapists.all():
                raise serializers.ValidationError("Selected therapist is not assigned to this store.")
    
        # Check for overlapping bookings on the same date and time
        if therapist and store and start_time and end_time:
            existing_bookings = TherapistSchedule.objects.filter(
                therapist=therapist,
                store=store,
                date=data['date'],
                start_time__lt=end_time,
                end_time__gt=start_time
            )
            if existing_bookings.exists():
                raise serializers.ValidationError("Therapist is already booked during this time slot.")
    
        return data


    def create(self, validated_data):
        validated_data['color'] = validated_data.get('backgroundColor', '#00FF00')  # Default color
        return super().create(validated_data)    
    
class TherapistSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['username', 'phone', 'password','exp', 'specialty','email']
        extra_kwargs = {
            'password': {'write_only': True}
        }

    def create(self, validated_data):
        user = User.objects.create(
            username=validated_data['username'],
            phone=validated_data['phone'],
            email=validated_data['email'],
            role='Therapist',
            exp=validated_data.get('exp'),  # Optional
            specialty=validated_data.get('specialty') 
        )
        
        user.set_password(validated_data['password'])
        user.save()
        return user
    
class AddStaffToStoreSerializer(serializers.Serializer):
    store_id = serializers.IntegerField(required=False)  
    store_name = serializers.CharField(max_length=255, required=False)  
    staff_phone = serializers.CharField(max_length=15)
    username = serializers.CharField(max_length=30)
    staff_email = serializers.EmailField(required=False)
    staff_password = serializers.CharField(write_only=True)
    role = serializers.CharField(max_length=10)  
    exp = serializers.IntegerField(required=False, min_value=0)  
    specialty = serializers.CharField(max_length=255, required=False, allow_blank=True)  

    def validate_role(self, value):
        """Ensure the role is valid, and allow case-insensitive input."""
        allowed_roles = ['Manager', 'Therapist']
        role = value.capitalize()
        if role not in allowed_roles:
            raise serializers.ValidationError(f"{value} is not a valid role.")
        return role

    def validate(self, data):
        store_id = data.get('store_id')
        store_name = data.get('store_name')
        user = self.context['request'].user

        # Check if either store_id or store_name is provided
        if not store_id and not store_name:
            raise serializers.ValidationError("Either 'store_id' or 'store_name' must be provided.")

        # Try to fetch the store by ID or name
        try:
            if store_id:
                store = Store.objects.get(id=store_id)
            elif store_name:
                store = Store.objects.get(name=store_name)
        except Store.DoesNotExist:
            raise serializers.ValidationError("Store not found.")

        # Check if the user is the owner or manager of the store
        if not (store.owner == user or user in store.managers.all()):
            raise serializers.ValidationError("You are not authorized to add staff to this store.")

        data['store'] = store  
        return data

    def create_staff(self, validated_data):
        # Create the staff member (Manager or Therapist)
        staff = {
            "phone": validated_data['staff_phone'],
            "username": validated_data['username'],
            "email": validated_data.get('staff_email'),
            "password": validated_data['staff_password'],
            "role": validated_data['role'],
            "exp": validated_data.get('exp'),  # Optional exp
            "specialty": validated_data.get('specialty', '').strip() if validated_data['role'] == 'Therapist' else None
        }

        staff = User.objects.create_user(**staff)
        store = validated_data['store']  # The store we validated

        # Assign the staff to the store based on their role
        if staff.role == 'Manager':
            store.managers.add(staff)
        elif staff.role == 'Therapist':
            store.therapists.add(staff)

        store.save()
        return staff


class StoreDetailSerializer(serializers.ModelSerializer):
    therapists = UserSerializer(many=True, read_only=True)
    
    class Meta:
        model = Store
        fields = ['id', 'name', 'address', 'phone', 'email', 'opening_days', 'start_time', 'end_time', 'lunch_start_time', 'lunch_end_time', 'therapists']
    
    
class AppointmentSerializer(serializers.ModelSerializer):
    previous_start_time = serializers.DateTimeField(format='%Y-%m-%d %H:%M', required=False)
    previous_end_time = serializers.DateTimeField(format='%Y-%m-%d %H:%M', required=False)

    class Meta:
        model = TherapistSchedule
        fields = ['id', 'therapist', 'customer_name', 'customer_phone', 'customer_email', 'store', 'status', 'start_time', 'end_time', 'previous_start_time', 'previous_end_time']
        

      
      
class PlanSerializer(serializers.ModelSerializer):
    class Meta:
        model = Plan
        fields = '__all__'

class SubscriptionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Subscription
        fields = '__all__'
        
class PaymentIntentSerializer(serializers.ModelSerializer):
    class Meta:
        model = PaymentIntent
        fields = '__all__'