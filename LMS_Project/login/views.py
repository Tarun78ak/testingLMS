'''
from django.shortcuts import render
from django.views.generic import TemplateView

Create your views here.
class LoginView(TemplateView):
	template_name = 'index.html'

'''
from django.shortcuts import render

# Create your views here.

# By Andy Nguyen
from django.shortcuts import render, HttpResponse, redirect
from django.contrib import messages
from .models import Authentications
#import bcrypt

# Create your views here.


def index(request):
    if 'user_id' in request.session:
        return redirect('/success')
    else:
        return render(request, 'index.html')


def register(request):
    if request.method == "POST":
        errors = Authentications.objects.register_validator(request.POST)
        if len(errors):
            for key, value in errors.items():
                messages.add_message(
                    request, messages.ERROR, value, extra_tags='register')
            return redirect('/')
        else:
           # pw_hash = bcrypt.hashpw(request.POST['password'].encode(), bcrypt.gensalt())
            auth = Authentications.objects.create(
                username=request.POST['username'], password=request.POST['password'], role_id=request.POST['role_id'])
            request.session['user_id'] = auth.id
            return redirect("/success")
    else:
        return redirect("/")


def login(request):
    if request.method == "POST":
        errors = Authentications.objects.login_validator(request.POST)
        if len(errors):
            for key, value in errors.items():
                messages.add_message(
                    request, messages.ERROR, value, extra_tags='login')
            return redirect('/')
        else:
            auth = Authentications.objects.get(
                username=request.POST['username'])
            request.session['user_id'] = auth.id
            return redirect("/wall")


def wall(request):
    if 'user_id' not in request.session:
        return redirect('/')
    else:
        context = {
            "authentication": Authentications.objects.get(id=request.session['user_id'])
        }
        return render(request, 'userpage.html', context)


def success(request):
    if 'user_id' not in request.session:
        return redirect('/')
    else:
        context = {
            "authentication": Authentications.objects.get(id=request.session['user_id'])
        }
        return render(request, 'successreg.html', context)


def reset(request):
    if 'user_id' not in request.session:
        return redirect('/')
    else:
        request.session.clear()
        print("session has been cleared")
        return redirect("/")
