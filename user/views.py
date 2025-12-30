from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.response import Response
from rest_framework import status,viewsets,permissions
from .models import *
from .serializers import *
from django.contrib.auth import authenticate
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.http import urlsafe_base64_encode,urlsafe_base64_decode
from django.utils.encoding import force_bytes
from django.urls import reverse
from .serializers import PasswordResetRequestSerializer, PasswordResetConfirmSerializer
from rest_framework import status
from django.core.mail import send_mail
from django.conf import settings
from rest_framework.views import APIView
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from django.utils.encoding import force_str 
from rest_framework.permissions import IsAuthenticated,AllowAny
from django.contrib.auth import update_session_auth_hash
from .serializers import ChangePasswordSerializer
from utils.send_email import send_set_password_email
from django.utils.timezone import now
from decouple import config
import requests

class LoginView(APIView):
    serializer_class = LoginSerializer
    authentication_classes = []
    
    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        user= request.user
        if serializer.is_valid():
            email = serializer.validated_data.get('email')
            password = serializer.validated_data.get('password')
            
            try:
                user = User.objects.get(email=email)
            except User.DoesNotExist:
                return Response({
                    'error':'The user does not exist'}, 
                    status=status.HTTP_404_NOT_FOUND)
            
            if not user.is_active:
                return Response(
                    {'error': 'Account is inactive, please contact the administrator'}, 
                    status=status.HTTP_403_FORBIDDEN)
            
            user = authenticate(request, username=email, password=password)
            
            if user is not None:
                user.last_login = now()
                user.save(update_fields=['last_login'])
                
                refresh = RefreshToken.for_user(user)
                
                # Add the user's role to the token
                refresh['role'] = user.role

                return Response({
                    'message': 'Logged In Successfully',
                    'refresh_token': str(refresh),
                    'access_token': str(refresh.access_token),
                    'role': user.role,
                    'name': user.name,
                    'email': user.email,
                }, status=status.HTTP_200_OK)
            else:
                return Response({'error': 'Invalid Credentials'}, status=status.HTTP_401_UNAUTHORIZED)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = []

    def get_queryset(self):
        if getattr(self, 'swagger_fake_view', False):
            return User.objects.none()  # Return an empty queryset for schema generation
        
        # Check if user is authenticated and has the required attributes
        if not self.request.user.is_authenticated:
            return User.objects.none()
        
        if self.request.user.role == 'ADMIN':
            return User.objects.all()
        
        # Safely check for location attribute
        if hasattr(self.request.user, 'location') and self.request.user.location:
            if hasattr(self.request.user.location, 'company'):
                return User.objects.filter(location__company=self.request.user.location.company)
        
        return User.objects.none() 

    def get_queryset(self):
        if getattr(self, 'swagger_fake_view', False):
            return User.objects.none()  # Return an empty queryset for schema generation
        
        if self.request.user.role == 'ADMIN':
            return User.objects.all()
        return User.objects.filter(location__company=self.request.user.location.company)
    
    def perform_create(self, serializer):
        user = serializer.save()  # Save the new user object
        # Send an email
        send_set_password_email(user)
        return Response({
            "success": "User Created successfully!",
            "data": serializer.data
        }, status=status.HTTP_201_CREATED)
    
    def create(self, request, *args, **kwargs):
        print("Request data:", request.data)
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)  # Pass the serializer instead of the user object

        return Response({
            "success": 'User created successfully.',
            "data": serializer.data
        }, status=status.HTTP_201_CREATED)
    
    def list(self, request, *args, **kwargs):
        queryset = User.objects.all()
        serializer = self.serializer_class(queryset, many=True)
        return Response({
            "success": "Users fetched successfully",
            "data":serializer.data
        }, status=status.HTTP_200_OK)
              

    def update(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.serializer_class(instance, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response({
            "success": "User updated successfully",
            "data":serializer.data
            }, status=status.HTTP_200_OK)

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        instance.delete()
        return Response({
            "success": "User deleted successfully",
        }, status=status.HTTP_200_OK)

class ChangePasswordView(APIView):
    permission_classes = [IsAuthenticated]  # Only authenticated users can access this view

    def post(self, request):
        serializer = ChangePasswordSerializer(data=request.data)
        if serializer.is_valid():
            user = request.user

            # Check if the current password is correct
            if not user.check_password(serializer.validated_data['current_password']):
                return Response({"message": "Current password is incorrect."}, status=status.HTTP_400_BAD_REQUEST)

            # Set the new password
            user.set_password(serializer.validated_data['new_password'])
            user.save()

            # Update the session to prevent the user from being logged out
            update_session_auth_hash(request, user)

            return Response({"message": "Password changed successfully."}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
class PasswordResetRequestView(APIView):
    def post(self, request):
        serializer = PasswordResetRequestSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            user = User.objects.get(email=email)
            user_name = user.name
            token_generator = PasswordResetTokenGenerator()
            token = token_generator.make_token(user)
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            # reset_url = reverse('password_reset_confirm', kwargs={'uidb64': uid, 'token': token})
            reset_link = f"http://localhost:3000/password-reset-confirm/{uid}/{token}/"
            html_message = render_to_string('emails/password_reset_email.html', {
                'reset_link': reset_link,'user_name': user_name
            })
            plain_message = strip_tags(html_message)
            send_mail(
                subject='Password Reset Request',
                message=plain_message,  # Plain text version
                html_message=html_message,  # HTML version
                from_email=settings.EMAIL_HOST_USER,
                recipient_list=[email],
                fail_silently=False,
            )
            return Response({"message": "Password reset link sent to your email."}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class PasswordResetConfirmView(APIView):
    def post(self, request, uidb64, token):
        serializer = PasswordResetConfirmSerializer(data=request.data)
        if serializer.is_valid():
            try:
                uid = force_str(urlsafe_base64_decode(uidb64))
                user = User.objects.get(pk=uid)
            except (TypeError, ValueError, OverflowError, User.DoesNotExist):
                user = None
            if user is not None and PasswordResetTokenGenerator().check_token(user, token):
                user.set_password(serializer.validated_data['password'])
                user.save()
                return Response({"message": "Password has been reset successfully."}, status=status.HTTP_200_OK)
            else:
                return Response({"message": "Invalid token or user."}, status=status.HTTP_400_BAD_REQUEST)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    

    