from django.contrib.auth.models import BaseUserManager

class UserManager(BaseUserManager):
    def create_user(self, phone_number, password=None, active=False, admin=False, staff=False):
        if not phone_number:
            raise ValueError("Users must have a phonenumber")
        # user_obj = self.model(phone_number=self.normalize_phone_number(phone_number))
        user_obj = self.model(phone_number=phone_number)
        user_obj.set_password(password)
        user_obj.staff = staff
        user_obj.admin = admin
        user_obj.active = active
        user_obj.save(using=self._db)
        return user_obj

    def create_staff_user(self, phone_number, password):
        user = self.create_user(phone_number, password=password, staff=True)
        return user

    def create_superuser(self, phone_number, password):
        user = self.create_user(phone_number, password=password, staff=True, admin=True)
        return user