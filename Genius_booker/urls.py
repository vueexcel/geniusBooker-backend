from django.contrib import admin
from django.urls import path, include
from django.contrib.staticfiles.urls import staticfiles_urlpatterns

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/', include('booker.urls')),  # Ensure this line is correctly included
]
urlpatterns += staticfiles_urlpatterns()
