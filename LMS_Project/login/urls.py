from django.urls import path
from . import views

# urlpatterns = [
#     path('login/', views.LoginView.as_view(), name="Login"),
# ]

urlpatterns = [
    path('', views.index),
    path('register', views.register),
    path('login', views.login),
    path('success', views.success),
    path('reset', views.reset),
    path('wall', views.wall),
]
