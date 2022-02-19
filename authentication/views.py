import email
from email.message import EmailMessage
from functools import reduce
import imp
import re
from tokenize import generate_tokens
from urllib.request import Request
from django.shortcuts import redirect, render
from django.http import HttpResponse
from django.contrib.auth.models import User
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from DjangoLS import settings
from django.core.mail import EmailMessage, send_mail
from django.utils.encoding import force_bytes, force_text
from django.contrib.sites.shortcuts import get_current_site
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from .tokens import generate_token 
from DjangoLS import settings
from django.template.loader import render_to_string

# Create your views here.
def home(request):
  return render(request, "authentication/index.html")


def signup(request):
  if request.method == "POST":
    #username = request.POST.get('username')
    username = request.POST['username']
    fname = request.POST['fname']
    lname = request.POST['lname']
    email = request.POST['email']
    pass1 = request.POST['pass1']
    pass2 = request.POST['pass2']

    if User.objects.filter(username=username):
      messages.error(request, "Username already exists try another username")
      return redirect('home')

    if User.objects.filter(email=email):
      messages.error(request, "Email already registered!")
      return redirect('home')

    if len(username)>10:
      messages.error(request, "Username must be under 10 char")

    if pass1 != pass2:
      messages.error(request, "Passwords are not same!")
    
    if not username.isalnum():
      messages.error(request, "Username must be Alpha-Numeric!")
      return redirect('home')


    myuser = User.objects.create_user(username, email, pass1)
    myuser.first_name = fname
    myuser.last_name = lname
    myuser.is_active = False
    myuser.save()

    messages.success(request, "your Account has been successfuly created. \n And we have sent a confirmation mail on your account please validate email.!")

    #welcome email that will be sent to the user
    subject = "Welcome to DjangoLS - Django Login System!!"
    message = "Hello " + myuser.first_name + "!!\n" + "Welcome to my project \n" + "Please confirm your email address \n" + "THANKS!"
    from_email = settings.EMAIL_HOST_USER
    to_list = [myuser.email]
    send_mail(subject, message, from_email, to_list, fail_silently=True)

    # Email Address Confirmation Email
    current_site = get_current_site(request)
    email_subject = "Confirm your email at Django Login System!!"
    message2 = render_to_string('email_confirmation.html',{
            
            'name': myuser.first_name,
            'domain': current_site.domain,
            'uid': urlsafe_base64_encode(force_bytes(myuser.pk)),
            'token': generate_token.make_token(myuser)
        })
    email = EmailMessage(
    email_subject,
    message2,
    settings.EMAIL_HOST_USER,
    [myuser.email],
    )
    email.fail_silently = True
    email.send()

    return redirect('signin')

  return render(request, "authentication/signup.html")

def activate(request, uidb64, token):
  try:
    uid = force_text(urlsafe_base64_decode(uidb64))
    myuser = User.objects.get(pk=uid)
  except(TypeError, ValueError, OverflowError, User.DoesNotExist):
    myuser = None

  if myuser is not None and generate_token.check_token(myuser, token):
    myuser.is_active = True
    myuser.save()
    login(request, myuser)
    messages.success(request, "Your Account has been activated!!")
    return redirect('signin')
  else:
    return render(request, 'activation_failed.html')

def signin(request):

  if request.method == 'POST':
    username = request.POST['username']
    pass1 = request.POST['pass1']

    user = authenticate(username=username, password=pass1)

    if user is not None:
      login(request, user)
      fname = user.first_name
      return render(request, "authentication/index.html", {'fname': fname})
    else:
      messages.error(request, "Add Credentials!")
      return redirect(request, 'home')

  return render(request, "authentication/signin.html")


def signout(request):
  logout(request)
  messages.success(request, "Logged Out Successfully!")
  return redirect('home')


