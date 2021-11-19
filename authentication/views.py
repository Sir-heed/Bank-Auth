import pyotp
import base64
from django.shortcuts import render
from django.contrib.auth.hashers import check_password, make_password
from requests.api import request
from drf_yasg.utils import swagger_auto_schema
from rest_framework import serializers, status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.token_blacklist.models import OutstandingToken, BlacklistedToken
from django.contrib.auth import authenticate, login, logout

from .utils import generateKey, resolve_account_number, resolve_card_bin
from .serializers import ChangePasswordSerializer, ChangePinSerializer, LoginSerializer, LogoutSerializer, RegisterSerializer, ResolveUserSerializer, \
                            UpdateUserSerializer, VerifyMobileNumberSerializer, VerifyOTPSerializer, ForgotPasswordSerializer
from.models import User

# Create your views here.

class ResolveUser(APIView):
    """
    API is called before registration to confirm the user has an account with the bank
    User pin is check here (Don't have access)
    """
    permission_classes = [AllowAny,]
    authentication_classes = []

    @swagger_auto_schema(request_body=ResolveUserSerializer)
    def post(self, request):
        serializer = ResolveUserSerializer(data=request.data)
        if serializer.is_valid():
            account_number = serializer.validated_data['account_number']
            card_type = serializer.validated_data['card_type']
            first_six_digits = serializer.validated_data['first_six_digits']
            last_four_digits = serializer.validated_data['last_four_digits']
            card_pin = serializer.validated_data['card_pin']
            check_bin = resolve_card_bin(first_six_digits)
            check_account_number = resolve_account_number(account_number)
            if check_bin is not None:
                # if check_bin['data']['brand'] == card_type and check_bin['data']['brand'] == "United Bank For Africa":
                print(check_bin['data']['bank'])
                if check_bin['data']['bank'].lower() == "united bank for africa":
                    if check_account_number is None:
                        return Response({
                            'status': False,
                            'message': 'Invalid account details'
                        }, status=status.HTTP_406_NOT_ACCEPTABLE)
                    else:
                        # Compare user pin with account number
                        return Response({
                            'account_owner': check_account_number['data']['account_name'],
                            'account_number': check_account_number['data']['account_number'],
                            # 'phonenumber': '000000000' # Gotten fromt the bank
                        }, status=status.HTTP_200_OK)
                else:
                    return Response({
                    'status': False,
                    'message': 'The card provided is not issued by UBA'
                }, status=status.HTTP_406_NOT_ACCEPTABLE)
            else:
                return Response({
                    'status': False,
                    'message': 'Invalid card details'
                }, status=status.HTTP_406_NOT_ACCEPTABLE)
        else:
            return Response({
                'status': False,
                'data': serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)


class Register(APIView):
    permission_classes = [AllowAny,]
    authentication_classes = []

    @swagger_auto_schema(request_body=RegisterSerializer)
    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            phone_number = serializer.validated_data['phone_number']
            password = serializer.validated_data['password']
            pin = serializer.validated_data['pin']
            referrer = serializer.validated_data['referrer'] if 'referrer' in serializer.validated_data else None
            pin = make_password(pin)
            user = User.objects.create(phone_number=phone_number, pin=pin, referrer=referrer)
            user.set_password(password)
            user.save()
            return Response({
                'status': True,
                'message': 'User created successfully'
            }, status=status.HTTP_201_CREATED)
        else:
            return Response({
                'status': False,
                'data': serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)


class VerifyMobileNumber(APIView):
    """
    This API is called after resolve user to verify the account information provided actually belongs to the user
    Card expiry date and month is checked here (Don't have access)
    """
    permission_classes = [AllowAny,]
    authentication_classes = []

    @swagger_auto_schema(request_body=VerifyMobileNumberSerializer)
    def post(self, request):
        serializer = VerifyMobileNumberSerializer(data=request.data)
        if serializer.is_valid():
            # Send OTP to user Phone
            phone = serializer.validated_data['phone_number']
            keygen = generateKey()
            key = base64.b32encode(keygen.returnValue(phone).encode())
            OTP = pyotp.TOTP(key, interval=300)
            # Send OTP to the phone number
            return Response({
                "status": True,
                "otp": OTP.now() # Should be sent using an sms service
            }, status=status.HTTP_200_OK)
        else:
            return Response({
                'status': False,
                'data': serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)


class VerifyOTP(APIView):
    """
    This API is called to verify the OTP sent in the Verify Mobile Number view
    """
    permission_classes = [AllowAny,]
    authentication_classes = []

    @swagger_auto_schema(request_body=VerifyOTPSerializer)
    def post(self, request):
        serializer = VerifyOTPSerializer(data=request.data)
        if serializer.is_valid():
            phone = serializer.validated_data['phone_number']
            otp = serializer.validated_data['otp']
            keygen = generateKey()
            key = base64.b32encode(keygen.returnValue(
                phone).encode())  # Generating Key
            OTP = pyotp.TOTP(key, interval=300)  # TOTP Model
            print(OTP.verify(otp))
            if OTP.verify(otp):  # Verifying the OTP
                return Response({
                    "status": True,
                    "message": "phone number verified"
                }, status=status.HTTP_200_OK)
            return Response({
                "status": False,
                "message": "Invalid OTP"
            }, status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response({
                'status': False,
                'data': serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)


class Login(APIView):
    permission_classes = [AllowAny,]
    authentication_classes = []

    @swagger_auto_schema(request_body=LoginSerializer)
    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            phone_number = serializer.validated_data['phone_number']
            password = serializer.validated_data['password']
            try:
                user = User.objects.get(phone_number=phone_number)
                if user.is_active:
                    login(request, user)
                    refresh = RefreshToken.for_user(user)
                    return Response({
                        'status': True,
                        'access': str(refresh.access_token),
                        'refresh': str(refresh),
                    }, status=status.HTTP_200_OK)
            except User.DoesNotExist:
                return Response({
                    'status': False,
                    'message': 'User not found, Please enter a valid phone number'
                }, status=status.HTTP_404_NOT_FOUND)
        else:
            return Response({
                'status': False,
                'data': serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)


class ForgotPassword(APIView):
    """
    Resolve user and verify needs to be done before calling this
    """
    permission_classes = [AllowAny,]
    authentication_classes = []

    @swagger_auto_schema(request_body=ForgotPasswordSerializer)
    def post(self, request):
        serializer = ForgotPasswordSerializer(data=request.data)
        if serializer.is_valid():
            phone_number = serializer.validated_data['phone_number']
            new_password = serializer.validated_data['new_password']
            confirm_password = serializer.validated_data['confirm_password']
            if new_password != confirm_password:
                return Response({
                    'status': False,
                    'message': 'Password do not match'
                }, status=status.HTTP_406_NOT_ACCEPTABLE)
            try:
                user = User.objects.get(phone_number=phone_number)
                user.set_password(new_password)
                user.save()
                return Response({
                    'status': True,
                    'message': 'Password updated successfully'
                }, status=status.HTTP_200_OK)
            except User.DoesNotExist:
                return Response({
                    'status': False,
                    'message': 'User does not exist'
                }, status=status.HTTP_404_NOT_FOUND)
        else:
            return Response({
                'status': False,
                'data': serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)


class ChangePassword(APIView):
    @swagger_auto_schema(request_body=ChangePasswordSerializer)
    def post(self, request):
        serializer = ChangePasswordSerializer(data=request.data)
        if serializer.is_valid():
            old_password = serializer.validated_data['old_password']
            new_password = serializer.validated_data['new_password']
            confirm_password = serializer.validated_data['new_password']
            if new_password != confirm_password:
                return Response({
                    'status': False,
                    'message': 'Password do not match'
                }, status=status.HTTP_406_NOT_ACCEPTABLE)
            user = request.user
            if user.check_password(old_password):
                user.set_password(new_password)
                user.save()
                return Response({
                    'status': True,
                    'message': 'Password changed successfully'
                }, status=status.HTTP_200_OK)
            else:
                return Response({
                    'status': False,
                    'message': 'Incorrect password'
                }, status=status.HTTP_406_NOT_ACCEPTABLE)
        else:
            return Response({
                'status': False,
                'data': serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)


class ChangePin(APIView):
    @swagger_auto_schema(request_body=ChangePinSerializer)
    def post(self, request):
        serializer = ChangePinSerializer(data=request.data)
        if serializer.is_valid():
            old_pin = serializer.validated_data['old_pin']
            new_pin = serializer.validated_data['new_pin']
            confirm_pin = serializer.validated_data['confirm_pin']
            if new_pin != confirm_pin:
                return Response({
                    'status': False,
                    'message': 'Pin do not match'
                }, status=status.HTTP_406_NOT_ACCEPTABLE)
            user = request.user
            if check_password(old_pin, user.pin):
                user.pin = make_password(new_pin)
                user.save()
                return Response({
                    'status': True,
                    'message': 'Pin changed successfully'
                }, status=status.HTTP_200_OK)
            else:
                return Response({
                    'status': False,
                    'message': 'Incorrect pin'
                }, status=status.HTTP_406_NOT_ACCEPTABLE)
        else:
            return Response({
                'status': False,
                'data': serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)


class UpdateUser(APIView):
    @swagger_auto_schema(request_body=UpdateUserSerializer)
    def post(self, request):
        serializer = UpdateUserSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            user = request.user
            user.email = email
            user.save()
            return Response({
                'status': True,
                'message': 'User updated successfully'
            }, status=status.HTTP_200_OK)
        else:
            return Response({
                'status': False,
                'data': serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)


class Logout(APIView):
    @swagger_auto_schema(request_body=LogoutSerializer)
    def post(self, request, *args, **kwargs):
        for token in OutstandingToken.objects.filter(user=request.user):
            _, _ = BlacklistedToken.objects.get_or_create(token=token)
        refresh_token = self.request.data.get('refresh_token')
        token = RefreshToken(token=refresh_token)
        token.blacklist()
        return Response({
            'status': True,
            'message': 'Logged out successfully'
        }, status=status.HTTP_200_OK)