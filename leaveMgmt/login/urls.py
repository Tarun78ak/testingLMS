from django.urls import path
from . import views
'''
urlpatterns=[
    path('',views.index,name='index'),
    path('login/', auth_view.LoginView.as_view(template_name='templates/login.html'), name="login"),
]

'''

urlpatterns = [
    path('', views.index),
    path('register', views.register),
    path('login', views.login),
    path('success', views.success),
    path('reset', views.reset),
    path('wall', views.wall),
]