from django.db import models
import re
#import bcrypt

#EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')

# Create your models here.


class EmpManager(models.Manager):
    def register_validator(self, postData):
        errors = {}
        # Validation Rules for First Name
        if len(postData['username']) < 1:
            errors["username"] = "Username is required"
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
        elif not Authentications.objects.filter(username=postData['username']):
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


class Authentications(models.Model):
    #    username = models.CharField(max_length=100,primary_key=True)
    username = models.CharField(max_length=100)
    password = models.CharField(max_length=16)
    last_login = models.DateField(auto_now=True)
    role_id = models.IntegerField()

    def __repr__(self):
        return f"<Authentication: {self.username} {self.role_id} >"

    objects = EmpManager()
