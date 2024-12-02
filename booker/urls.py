from django.urls import path
from .views import (
    RegisterAPI, CreateStoreWithStaffAPI, AddStaffAPI, ManageStaffAPI,
    UpdateManagerProfileAPI, UpdateStoreDetailsAPI, ManageTherapistScheduleAPI,
    UpdateTherapistProfileAPI, RoleDetailsAPI, ManagerLoginView, StoreListView, 
    TherapistLoginView, OwnerLoginView, BookAppointmentAPI, StoreStaffDetailsAPI,
    AddStaffToStoreView, AllSchedulesAPI, StoreScheduleAPI, ManagerScheduleAPI,
    TherapistScheduleAPI, DeleteStoreAPI, PasswordResetRequestView, PasswordResetConfirmView,
    CompleteRegistrationAPI,AppointmentsByStoreAPI, UpdateAppointmentStatusAPI,AppointmentDetailsAPI, ListAllBookingsAPI,StoreListAPI,ConfirmRescheduledAppointmentAPI,
    CreateCheckoutSessionView,AllSubscriptionsView, stripe_webhook, success, cancel)

urlpatterns = [
    # User Registration and Login APIs
    path('register/', RegisterAPI.as_view(), name='register'),
    path('complete-registration/', CompleteRegistrationAPI.as_view(), name='complete-registration'),
    path('login/owner/', OwnerLoginView.as_view(), name='owner-login'),
    path('login/manager/', ManagerLoginView.as_view(), name='manager-login'),
    path('login/therapist/', TherapistLoginView.as_view(), name='therapist-login'),

    # Password Reset APIs
    path('password-reset/request/', PasswordResetRequestView.as_view(), name='password-reset-request'),
    path('password-reset/confirm/<uidb64>/<token>/', PasswordResetConfirmView.as_view(), name='password-reset-confirm'),

    # Store Management APIs
    path('stores/create/', CreateStoreWithStaffAPI.as_view(), name='create_store_with_staff'),
    path('stores/<int:store_id>/staff/add/', AddStaffAPI.as_view(), name='add_staff'),
    path('stores/add-staff/', AddStaffToStoreView.as_view(), name='add-staff'),
    path('stores/<int:store_id>/delete/', DeleteStoreAPI.as_view(), name='delete-store'),
    path('stores/<int:store_id>/staff/manage/', ManageStaffAPI.as_view(), name='manage_staff'),
    
    # Staff Management APIs (specific actions)
    path('stores/<int:store_id>/staff/<int:staff_id>/update/', ManageStaffAPI.as_view(), name='update_staff'),
    path('stores/<int:store_id>/staff/<int:staff_id>/delete/', ManageStaffAPI.as_view(), name='delete_staff'),

    # Manager and Therapist Profile APIs
    path('manager/update-profile/', UpdateManagerProfileAPI.as_view(), name='update-manager-profile'),
    path('store/<int:store_id>/update/', UpdateStoreDetailsAPI.as_view(), name='update-store'),
    path('therapist/update-profile/', UpdateTherapistProfileAPI.as_view(), name='update-therapist-profile'),

    # Therapist Schedule Management APIs
    path('therapists/<int:therapist_id>/schedule/manage/', ManageTherapistScheduleAPI.as_view(), name='manage_therapist_schedule'),
    path('therapists/schedule/<int:schedule_id>/delete/', ManageTherapistScheduleAPI.as_view(), name='delete_schedule'),

    # Appointment Booking and Management APIs
    path('appointments/book/', BookAppointmentAPI.as_view(), name='book_appointment'),
    path('appointments/<int:appointment_id>/update_status/', UpdateAppointmentStatusAPI.as_view(), name='update_appointment_status'),
    path('appointments/<int:appointment_id>/confirm/', ConfirmRescheduledAppointmentAPI.as_view(), name='confirm_rescheduled_appointment'),
    path('appointments/', ListAllBookingsAPI.as_view(), name='list_all_bookings'),
    path('appointments/store/<int:store_id>/', AppointmentsByStoreAPI.as_view(), name='appointments-by-store'),
    path('appointment-details/<int:appointment_id>/', AppointmentDetailsAPI.as_view(), name='appointment-details'),



    # Role and Staff Details APIs
    path('role-details/', RoleDetailsAPI.as_view(), name='role-details'),
    path('store/<int:store_id>/staff-details/', StoreStaffDetailsAPI.as_view(), name='store-staff-details'),

    # Store List API
    path('stores/', StoreListView.as_view(), name='store-list'),
    path('stores/list/', StoreListAPI.as_view(), name='store-list'),
    
    # Schedule APIs
    path('stores/<int:store_id>/schedules/', AllSchedulesAPI.as_view(), name='all-schedules'),
    path('store/<int:store_id>/schedule/', StoreScheduleAPI.as_view(), name='store-schedule'),
    path('managers/<int:manager_id>/schedule/', ManagerScheduleAPI.as_view(), name='manager-schedule'),
    path('therapists/<int:therapist_id>/schedule/', TherapistScheduleAPI.as_view(), name='therapist_schedule'),
    
    
    path('create-checkout-session/', CreateCheckoutSessionView.as_view(), name='create-checkout-session'),
    path('webhook/', stripe_webhook, name='stripe-webhook'),
    path('all-subscriptions/',AllSubscriptionsView.as_view(),name='allAllSubscriptions'),
    path('success/', success, name='success'),
    path('cancel/', cancel, name='cancel'),
    
]