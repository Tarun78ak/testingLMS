'''
from django.db import models

# Create your models here.
class Members(models.Model):
  firstname = models.CharField(max_length=255)
  lastname = models.CharField(max_length=255)

class Authentication(models.Model):
  username = models.CharField(max_length=100,primary_key=True)
  password = models.CharField(max_length=16)
  last_login = models.DateField()
  role_id = models.IntegerField()
  '''

from django.db import models
import re
#import bcrypt

EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')

# Create your models here.
class EmpManager(models.Manager):
    def register_validator(self, postData):
        errors = {}
        # Validation Rules for First Name
        if len(postData['username']) < 1:
            errors["username"] = "Username is required"
        '''
        elif len(postData['first_name']) < 2:
            errors["first_name"] = "First name should be at least 2 characters"
        elif not postData['first_name'].isalpha():
            errors["first_name"] = "First Name can only have letters"
        '''
        '''
        # Validation Rules for Last Name
        if len(postData['last_name']) < 1:
            errors["last_name"] = "Last name is required"
        
        elif len(postData['last_name']) < 2:
            errors["last_name"] = "Last name should be at least 2 characters"
        elif not postData['last_name'].isalpha():
            errors["last_name"] = "Last name can only have letters"
        '''
        '''
        # Validation Rules for Email
        if len(postData['email']) < 1:
            errors["email"] = "Email is required"
        elif not EMAIL_REGEX.match(postData['email']):
            errors["email"] = "Invalid Email Address"
        if User.objects.filter(email = postData['email']):
            errors["email"] = "Sorry, email is already in use"
        '''
        # Validation Rules for Password
        if len(postData['password']) < 1:
            errors["password"] = "Password is required"
        elif len(postData['password']) < 8:
            errors["password"] = "Password should be at least 8 characters"
        
        # Validation Rules for Confirm Password
        if postData['password'] != postData['confirm_password']:
            errors["confirm_password"] = "Password and Password Confirmation did not match"

        return errors
    
    def login_validator(self, postData):
        errors = {}
        # Validation Rules for Login Email
        if len(postData['username']) < 1:
            errors["username"] = "Username is required"
        elif not Authentications.objects.filter(username = postData['username']):
            errors["username"] = "This account does not exist. Please register."
            
        # Validation Rules for Login Password
        if len(postData['password']) < 1:
            errors["password"] = "Password is required"
        else:
            auth = Authentications.objects.get(username=postData['username'])
            
            print(auth)
            # pwhash=bcrypt.hashpw(auth.password.encode('utf8'), bcrypt.gensalt())
            # self.password_hash = pwhash.decode('utf8')
            # if not bcrypt.checkpw(postData['password'].encode(), self.password_hash.encode()):
            #     errors["password"] = "Password is not correct"
            if postData['password'] != auth.password:
                errors["password"] = "Password is not correct"
        
        return errors

'''
class User(models.Model):
    first_name = models.CharField(max_length=255)
    last_name = models.CharField(max_length=255)
    email = models.CharField(max_length=255)
    password = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    def __repr__(self):
        return f"<User: {self.id} {self.first_name} {self.last_name} {self.email}>"
    
    objects = UserManager()
'''
class Authentications(models.Model):
#    username = models.CharField(max_length=100,primary_key=True)
    username = models.CharField(max_length=100)
    password = models.CharField(max_length=16)
    last_login = models.DateField(auto_now=True)
    role_id = models.IntegerField()
    def __repr__(self):
        return f"<Authentication: {self.username} {self.role_id} >"
    
    objects = EmpManager()