from rest_framework import serializers
from .models import *
from rest_framework.exceptions import ValidationError
from django.contrib.auth.password_validation import validate_password

class LoginSerializer(serializers.Serializer):
    email = serializers.CharField()
    password = serializers.CharField(style={'input_type': 'password'}, write_only=True)

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id','name', 'email', 'password','role']
        extra_kwargs = {
            'password': {'write_only': True, 'required': False},
            'contact': {'required': False},
            'id': {'read_only': True}
        }

    def create(self, validated_data):
        """Override create to hash the password before saving."""
        password = validated_data.pop('password', None)  # Extract password safely
        user = User(**validated_data)  # Create user instance without saving

        if password:
            user.set_password(password)  # Hash the password
        
        user.save()  # Save the user object
        return user
        
class ChangePasswordSerializer(serializers.Serializer):
    current_password = serializers.CharField(required=True, write_only=True)
    new_password = serializers.CharField(required=True, write_only=True)
    new_password_confirm = serializers.CharField(required=True, write_only=True)

    def validate(self, data):
        # Check if the new passwords match
        if data['new_password'] != data['new_password_confirm']:
            raise serializers.ValidationError("New passwords do not match.")

        # Validate the new password
        try:
            validate_password(data['new_password'])
        except ValidationError as e:
            raise serializers.ValidationError(str(e))

        return data
    
class PasswordResetRequestSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate_email(self, value):
        try:
            User.objects.get(email=value)
        except User.DoesNotExist:
            raise ValidationError("User with this email does not exist.")
        return value

class PasswordResetConfirmSerializer(serializers.Serializer):
    # token = serializers.CharField()
    password = serializers.CharField(write_only=True)
    password_confirm = serializers.CharField(write_only=True)

    def validate(self, data):
        if data['password'] != data['password_confirm']:
            raise ValidationError("Passwords do not match.")
        return data