"""  DynaSwapApp/models.py  """
from django.db import models
from django.urls import reverse
import hashlib
from hashlib import md5


class Roles(models.Model):
    """  openMRS Roles Class  """
    class Meta:
        db_table = 'role'
    role = models.CharField(max_length=50, unique=True, primary_key=True)
    description = models.CharField(max_length=255)
    uuid = models.CharField(max_length=38)
    url = models.URLField(max_length=255)
    role_key = models.CharField(max_length=40)
    feature = models.BinaryField()

    def __str__(self):
        return self.role

    def get_absolute_url(self):
        return reverse("get_graph")

class Users(models.Model):
    """  openMRS Users Class  """
    class Meta:
        db_table = 'users'
    user_id = models.IntegerField(max_length=11, unique=True, primary_key=True)
    username = models.CharField(max_length=50, unique=True)
    password = models.CharField(max_length=50)
    
    def get_SID(self):
        return md5(self.password.encode("utf-8")).hexdigest()

class DynaSwapUsers(models.Model):
    """  DynaSwapUsers Class  """
    class Meta:
        db_table = 'dynaswap_users'
    dynaswap_user_id = models.IntegerField(max_length=11, primary_key=True)
    role = models.CharField(max_length=50)
    bio_capsule = models.BinaryField()
    classifier = models.BinaryField()
    created_on = models.DateTimeField(auto_now=True)
    last_authenticated = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.dynaswap_user_id


class UsersRoles(models.Model):
    """  openMRS User_Role Class  """
    class Meta:
        db_table = 'user_role'
    user_id = models.ForeignKey(Users, db_column='user_id', on_delete=models.CASCADE)
    role = models.ForeignKey(Roles, db_column='role', on_delete=models.CASCADE)

    def __str__(self):
        return self.user_id, self.role


class RoleEdges(models.Model):
    """  openMRS Role_Role class """
    class Meta:
        db_table = "role_role"
    parent_role = models.ForeignKey(Roles, db_column='parent_role', on_delete=models.CASCADE)
    child_role = models.ForeignKey(Roles, db_column='child_role', on_delete=models.CASCADE)
    # Making the length longer for now
    edge_secret = models.CharField(max_length=40)
    edge_key = models.CharField(max_length=100)

    def __str__(self):
        return "{},{}".format(self.parent_role, self.child_role)
    