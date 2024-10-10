from django.contrib.auth.tokens import default_token_generator
from django.contrib.sites.shortcuts import get_current_site
from django.core.mail import EmailMessage
from django.template.loader import render_to_string
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode


def detectUser(user):
    if user.role == 1:
        return 'vendorDashboard'  # Return the URL name for vendors
    elif user.role == 2:
        return 'customerDashboard'  # Return the URL name for customers
    elif user.role is None and user.is_superadmin:
        return 'admin:index'  # Use Django's default admin URL namespace
    else:
        return 'login'  # Fallback case if none of the above matches


def send_verification_email(request, user):
    current_site = get_current_site(request)
    mail_subject = 'Activate your account verification code'
    message = render_to_string('accounts/emails/account_verification_email.html', {
        'user': user,
        'domain': current_site,
        'uid': urlsafe_base64_encode(force_bytes(user.pk)),
        'token': default_token_generator.make_token(user),
    })
    to_email = user.email
    mail = EmailMessage(mail_subject, message, to=[to_email])
    mail.send()
