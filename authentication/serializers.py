from rest_framework import serializers

from .models import User

class RegisterSerializer(serializers.ModelSerializer):
    phone_number = serializers.RegexField(r'^0[789][01]\d{8}$', max_length=None, min_length=None, allow_blank=False, required=True)
    pin = serializers.RegexField(r'^\d{4}$', max_length=None, min_length=None, allow_blank=False, required=True)
    password = serializers.RegexField(r'^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d@$!%*#?&]{8,}$', error_messages={'invalid': 'Password must be alphanumeric, and minimum of 8 characters'}, max_length=None, min_length=None, allow_blank=False, required=True)
    referrer = serializers.CharField(required=False)

    def validate(self, data):
        phone_number = data['phone_number']
        if User.objects.filter(phone_number=phone_number).exists():
            raise serializers.ValidationError('Phone number exists already')
        return data

    class Meta:
        model = User
        fields = ('phone_number', 'pin', 'password', 'referrer')
    

class ResolveUserSerializer(serializers.Serializer):
    account_number = serializers.RegexField(r'^\d{10}$', max_length=None, min_length=None, allow_blank=False, required=True)
    card_type = serializers.ChoiceField(choices=['mastercard', 'american_express_card', 'visa_card', 'verve_card'])
    first_six_digits = serializers.RegexField(r'^\d{6}$', max_length=None, min_length=None, allow_blank=False, required=True)
    last_four_digits = serializers.RegexField(r'^\d{4}$', max_length=None, min_length=None, allow_blank=False, required=True)
    card_pin = serializers.RegexField(r'^\d{4}$', max_length=None, min_length=None, allow_blank=False, required=True)


class VerifyMobileNumberSerializer(serializers.Serializer):
    phone_number = serializers.RegexField(r'^0[789][01]\d{8}$', max_length=None, min_length=None, allow_blank=False, required=True)


class VerifyOTPSerializer(serializers.Serializer):
    phone_number = serializers.RegexField(r'^0[789][01]\d{8}$', max_length=None, min_length=None, allow_blank=False, required=True)
    otp = serializers.CharField(required=True)


class LoginSerializer(serializers.Serializer):
    phone_number = serializers.RegexField(r'^0[789][01]\d{8}$', max_length=None, min_length=None, allow_blank=False, required=True)
    password = serializers.RegexField(r'^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d@$!%*#?&]{8,}$', error_messages={'invalid': 'Password must be alphanumeric, and minimum of 8 characters'}, max_length=None, min_length=None, allow_blank=False, required=True)


class ForgotPasswordSerializer(serializers.Serializer):
    phone_number = serializers.RegexField(r'^0[789][01]\d{8}$', max_length=None, min_length=None, allow_blank=False, required=True)
    new_password = serializers.RegexField(r'^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d@$!%*#?&]{8,}$', error_messages={'invalid': 'Password must be alphanumeric, and minimum of 8 characters'}, max_length=None, min_length=None, allow_blank=False, required=True)
    confirm_password = serializers.RegexField(r'^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d@$!%*#?&]{8,}$', error_messages={'invalid': 'Password must be alphanumeric, and minimum of 8 characters'}, max_length=None, min_length=None, allow_blank=False, required=True)


class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(required=True)
    new_password = serializers.RegexField(r'^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d@$!%*#?&]{8,}$', error_messages={'invalid': 'Password must be alphanumeric, and minimum of 8 characters'}, max_length=None, min_length=None, allow_blank=False, required=True)
    confirm_password = serializers.RegexField(r'^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d@$!%*#?&]{8,}$', error_messages={'invalid': 'Password must be alphanumeric, and minimum of 8 characters'}, max_length=None, min_length=None, allow_blank=False, required=True)


class ChangePinSerializer(serializers.Serializer):
    old_pin = serializers.RegexField(r'^\d{4}$', max_length=None, min_length=None, allow_blank=False, required=True)
    new_pin = serializers.RegexField(r'^\d{4}$', max_length=None, min_length=None, allow_blank=False, required=True)
    confirm_pin = serializers.RegexField(r'^\d{4}$', max_length=None, min_length=None, allow_blank=False, required=True)


class UpdateUserSerializer(serializers.Serializer):
    email = serializers.EmailField()

class LogoutSerializer(serializers.Serializer):
    refresh_token = serializers.CharField(required=False)