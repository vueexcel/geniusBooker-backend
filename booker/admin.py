from django.contrib import admin
from .models import Store, User

class ManagerInline(admin.TabularInline):
    model = Store.managers.through  # Shows the intermediary table for managers
    extra = 0

class TherapistInline(admin.TabularInline):
    model = Store.therapists.through  # Shows the intermediary table for therapists
    extra = 0

class StoreAdmin(admin.ModelAdmin):
    # Displays store name, owner name, and managers and therapists in the list view
    list_display = ('name', 'owner_name', 'get_managers', 'get_therapists')

    # Add the inlines for managers and therapists
    inlines = [ManagerInline, TherapistInline]

    # Function to show the owner's full name in the list view
    def owner_name(self, obj):
        return f'{obj.owner.first_name} {obj.owner.last_name}'

    # Function to display all managers assigned to the store
    def get_managers(self, obj):
        return ", ".join([f'{manager.first_name} {manager.last_name}' for manager in obj.managers.all()])

    # Function to display all therapists assigned to the store
    def get_therapists(self, obj):
        return ", ".join([f'{therapist.first_name} {therapist.last_name}' for therapist in obj.therapists.all()])

    # Optional: Shorten the column headers
    owner_name.short_description = 'Owner'
    get_managers.short_description = 'Managers'
    get_therapists.short_description = 'Therapists'

# Register StoreAdmin with the Store model
admin.site.register(Store, StoreAdmin)
