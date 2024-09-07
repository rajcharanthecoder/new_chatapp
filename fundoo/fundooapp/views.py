from django.http import HttpResponsePermanentRedirect
from django.urls import reverse
from django.contrib.auth import get_user_model, login
import jwt
from django.contrib.sites.shortcuts import get_current_site
from django.http import HttpResponse
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate
from .forms import SignupForm
from django.utils.encoding import force_bytes, force_str
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.template.loader import render_to_string
from .tokens import account_activation_token
from django.core.mail import EmailMessage

User = get_user_model()  # Retrieve the user model class from Django.

# Homepage
def index(request):
    return render(request, 'index.html', {})

# Login page
def login_u(request):
    return render(request, 'login.html', {})

def Signup(request):
    if request.method == 'POST':
        form = SignupForm(request.POST)  # Get signup data from user
        if form.is_valid():
            user = form.save(commit=False)
            user.is_active = False  # Set user as inactive until email is confirmed
            user.save()  # Store in the database
            current_site = get_current_site(request)
            message = render_to_string('acc_email.html', {
                'user': user,
                'domain': current_site.domain,
                'uid': urlsafe_base64_encode(force_bytes(user.pk)).decode(),
                'token': account_activation_token.make_token(user),
            })
            mail_subject = 'Activate Your ChatApp Account'  # Email subject
            to_email = form.cleaned_data.get('email')  # Recipient email
            email = EmailMessage(mail_subject, message, to=[to_email])
            email.send()  # Send email
            return HttpResponse('The confirmation link has been sent to your email. Please click on the link to confirm your registration.')
    else:
        form = SignupForm()
    return render(request, 'signup.html', {'form': form})

def activate(request, uidb64, token):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None
    if user is not None and account_activation_token.check_token(user, token):
        user.is_active = True
        user.save()
        return HttpResponsePermanentRedirect(reverse('sign_in'))
    else:
        return HttpResponse('Activation link is invalid!')

def user_login(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(username=username, password=password)
        if user:
            if user.is_active:
                login(request, user)
                payload = {'username': username}
                jwt_token = jwt.encode(payload, "secret_key", algorithm='HS256')
                return render(request, 'chat.html', {'jwt_token': jwt_token.decode('utf-8')})
            else:
                return HttpResponse("Your account is inactive.")
        else:
            return HttpResponse("Invalid login details.")
    else:
        return render(request, 'login.html', {})
