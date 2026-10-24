from django.urls import path
from . import views

urlpatterns = [
    path('', views.home, name='home'),
    path('auth/login/', views.login, name='login'),
    path('auth/callback/', views.callback, name='callback'),
    path('auth/logout/', views.logout, name='logout'),
    path('welcome/', views.welcome, name='welcome'),
]