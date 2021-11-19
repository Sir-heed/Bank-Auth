from django.urls import path

from .views import ResolveUser, Register, VerifyMobileNumber, VerifyOTP, Login, ForgotPassword, ChangePassword, ChangePin, UpdateUser, Logout

urlpatterns = [
    path('resolve-user', ResolveUser.as_view(), name='resolve-user'),
    path('register', Register.as_view(), name='register'),
    path('verify-mobile-number', VerifyMobileNumber.as_view(), name='verify-mobile-number'),
    path('verify-otp', VerifyOTP.as_view(), name='verify-otp'),
    path('login', Login.as_view(), name='login'),
    path('forgot-password', ForgotPassword.as_view(), name='forgot-password'),
    path('change-password', ChangePassword.as_view(), name='change-password'),
    path('change-pin', ChangePin.as_view(), name='change-pin'),
    path('update-user', UpdateUser.as_view(), name='update-user'),
    path('logout', Logout.as_view(), name='logout'),
]