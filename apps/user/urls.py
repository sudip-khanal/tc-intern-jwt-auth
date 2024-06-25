from django.urls import path
from apps.user.views import *

urlpatterns = [
    path('register/', register, name='register'),
    path('login/', login, name='login'),
    path('logout/', logout, name='logout'),
    path('change-password/', change_password, name='change_password'),
    path('forgot-password/', forgot_password, name='forgot_password'),
    path('refresh-token/', token_refresh, name='token_refresh'),
    path('verify-token/', token_verify, name='token_verify'),

    path('user/verify-email/<str:uidb64>/<str:token>/', verify_email, name='verify_email'),
    path('user/reset-password/<str:uidb64>/<str:token>/', reset_password, name='reset_password'),


]
