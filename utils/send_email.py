from django.contrib.auth.tokens  import PasswordResetTokenGenerator
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.urls import reverse
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from django.core.mail import send_mail
from django.conf import settings
import logging

def send_set_password_email(user):
    """
    The function `send_set_password_email` generates a password reset token for a user, creates a reset
    URL, and sends an email with the reset link to the user.
    
    :param user: The `user` parameter in the `send_set_password_email` function is an instance of a user
    model in your application. It contains information about the user, such as their email address,
    which is used to send the password reset email
    """
    
    try:
        token_generator = PasswordResetTokenGenerator()
        token = token_generator.make_token(user)
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        # reset_url = reverse('password_reset_confirm', kwargs={'uidb64': uid, 'token': token})
        reset_link = f"https://hfc-webapp.vercel.app/password-reset-confirm/{uid}/{token}/"

        html_message = render_to_string('emails/password_reset_email.html', {
            'reset_link': reset_link,
        })
        plain_message = strip_tags(html_message)

        send_mail(
            'Welcome! Set Your Password',
            plain_message,
            settings.EMAIL_HOST_USER,
            [user.email],
            html_message=html_message,
            fail_silently=False,
        )
    except Exception as e:
        logging.info(f"Failed to send welcome email to {user.email}: {e}")