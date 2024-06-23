"""
Models related to User and User permissions.
"""

from django.db import models
from django.contrib.auth.models import BaseUserManager,AbstractUser

class Organization(models.Model):
    """
    This table stores all the Organisation information.
    """
    LOW= 'low'
    MEDIUM= 'medium'
    HIGH= 'high'
    ROLE_CHOICES=[
        (LOW, 'low'),
        (MEDIUM, 'medium'),
        (HIGH, 'high')
    ]
    org_id = models.AutoField(primary_key=True, unique=True)
    name   = models.CharField(max_length=200, null=True, blank= True)
    level  = models.CharField(max_length= 50, choices= ROLE_CHOICES, default= 'low', null= True, blank= True)
    class Meta:
        db_table= 'fuzzer_organization'
    def __str__(self):
        return self.name

class SubOrganization(models.Model):
    """
    This table stores all the Sub Organisation information.
    """
    sub_org_id = models.AutoField(primary_key=True, unique=True)
    name = models.CharField(max_length=200, null=True, blank= True)
    org = models.ForeignKey(Organization, on_delete=models.CASCADE, null=True, blank=True)
    class Meta:
        db_table= 'fuzzer_sub_organization'
    def __str__(self):
        return self.name

class Environment(models.Model):
    """
    This table stores all the Environments information.
    """
    env_id = models.AutoField(primary_key=True, unique=True)
    name = models.CharField(max_length=50,default= 'other', null= True, blank=True)
    sub_org = models.ForeignKey(SubOrganization, on_delete=models.CASCADE, null=True, blank=True)
    class Meta:
        db_table= 'fuzzer_environment'
    def __str__(self):
        return self.name
class Role(models.Model):
    """
    This table stores all the role information.
    """
    rid     = models.AutoField(primary_key= True, unique= True)
    name    = models.CharField(max_length=50, default='other', null=True, blank= True)    
    env     = models.ForeignKey(Environment, on_delete= models.CASCADE, null=True, blank= True)
    is_staff= models.BooleanField(default= False, null= True, blank= True)
    class Meta:
        db_table = 'fuzzer_role'
    
class Permission(models.Model):
    """
    This table stores all the Permissions list.
    """
    perm_id = models.AutoField(primary_key=True, unique=True)
    name = models.CharField(max_length=100, null=True, blank=True)
    codename = models.CharField(max_length=200, null=True, blank= True)
    class Meta:
        db_table = 'fuzzer_permission'
    def __str__(self):
        return self.codename

class RolePermission(models.Model):
    """
    This table stores all the Sub_id, Role_id, Env_id, Permission_id.
    """
    role_perm_id = models.AutoField(primary_key=True, unique=True)
    perm = models.ForeignKey(Permission, on_delete= models.CASCADE, null=True, blank=True)
    rid = models.ForeignKey(Role, on_delete= models.CASCADE, null=True, blank=True)
    class Meta:
        db_table = 'fuzzer_role_permission'

class UserManager(BaseUserManager):

    def _create_user(self, email,password, **extra_fields):
        """
        Create and save a User with the given email and password.
        """
        if not email:
            raise ValueError("User must have an email")
        if not password:
            raise ValueError("User must have a password")
        if "name" not in extra_fields:
            raise ValueError("User must have a name")
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user        

    def create_superuser(self, email,password=None, **extra_fields):
        """
        Method for creating a Administrator with role=ROLE_ADMIN
        """
        return self._create_user(email,password, **extra_fields)

class User(AbstractUser):

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ["name"]
    first_name = None
    last_name = None
    id = models.AutoField(primary_key=True,unique=True)
    username = models.CharField(max_length=200,null=True,blank=True)
    email = models.EmailField(('email address'), unique=True ,error_messages={
            'unique': ("A user with that username already exists."),
        }) # changes email to unique and blank to false
    name = models.CharField(max_length=200)
    password = models.CharField(max_length=200)
    email_verified =models.BooleanField(default=False)
    uu_id = models.UUIDField(db_index = True,default = None,editable = False,unique=True,null=True,blank=True)
    secret_key = models.CharField(max_length=255,null=True,blank=True,default=None)
    is_confirmed_sk  = models.BooleanField(default=False,null=True,blank=True)
    is_smtp_enabled = models.BooleanField(default=False,null=True,blank=True)
    rid = models.ForeignKey(Role, on_delete = models.CASCADE, related_name= 'users', null= True, blank= True)
    password_timestamp = models.DateTimeField(default= None, blank=True,null=True)
    is_staff= models.BooleanField(default= False, null= True, blank= True)
    is_jira_enabled= models.BooleanField(default=False, null=True, blank=True)
    jira_username= models.CharField(max_length=200,null=True, blank=True)
    jira_password= models.CharField(max_length=200, null=True, blank=True)
    class Meta:
        db_table = "fuzzer_user" #giving custom name to the table

    objects = UserManager()
    def __str__(self):                                                       
        return self.email