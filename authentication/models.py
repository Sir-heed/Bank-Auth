from django.db import models
from django.contrib.auth.models import AbstractUser

from .managers import UserManager

# Create your models here.
class User(AbstractUser):
    # Password
    phone_number = models.CharField(max_length=11, unique=True)
    pin = models.CharField(max_length=250)
    referrer = models.CharField(max_length=10, null=True, blank=True)
    email = models.EmailField(null=True, blank=True)

    USERNAME_FIELD = 'phone_number'
    REQUIRED_FIELDS = []

    objects = UserManager()

    def __str__(self):
        return self.phone_number