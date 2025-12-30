from django.contrib.auth.models import AbstractUser,BaseUserManager
from django.db import models
import uuid

class CustomUserManager(BaseUserManager):
    def create_superuser(self, email, name, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('role', User.Role.ADMIN)
        return self.create_user(email, name, password, **extra_fields)
    
    def create_user(self, email, name, password=None, **extra_fields):
        if not email:
            raise ValueError('The Email field must be set')
        email = self.normalize_email(email)
        user = self.model(email=email, name=name, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user
    
class User(AbstractUser):
    class Role(models.TextChoices):
        ADMIN  = 'ADMIN','Admin'
        USER = 'USER','User'

    id = models.CharField(max_length=30, primary_key=True, unique=True)
    username = None
    email = models.EmailField(unique=True)
    contact = models.CharField(max_length=100) #phone number
    name = models.CharField(max_length=255, default = "DefaultName")
    role = models.CharField(max_length=20, choices=Role.choices, default=Role.USER)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['name']
    objects = CustomUserManager()


    def save(self, *args, **kwargs):
        # Now, generate the prefixed custom_id only after the object is saved
        if not self.id:
            role_prefix_map = {
            User.Role.USER: 'USR',
            User.Role.ADMIN: 'ADM',
            }
            prefix = role_prefix_map.get(self.role, 'UNKNOWN')
            
            # Get the highest custom_id with the same prefix
            last_custom_id = User.objects.filter(id__startswith=prefix).order_by('-created_at').first()
            
            if last_custom_id:
                # Extract the numerical part after the prefix and increment by 1
                last_number = int(last_custom_id.id[len(prefix):])
                print(f'last id is {last_number}')
                new_number = last_number + 1
            else:
                # If no existing ID with the prefix, start from 1
                new_number = 1
            
            # Set the custom_id field using the prefix and the new number
            self.id = f"{prefix}{new_number}"
            # Save the object again to store the custom_id
        super(User, self).save(*args, **kwargs)
    def __str__(self):
        return self.email
    
