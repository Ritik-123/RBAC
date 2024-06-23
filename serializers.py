from .models import *
from rest_framework.serializers import ModelSerializer
from rest_framework import serializers
from uuid import uuid4
from fuzzer.models import Project, SMTP
from rest_framework import status
from django.db import transaction
from django.core.validators import RegexValidator
import logging
from django.contrib.auth.hashers import make_password
from fuzzer.base.base import check_valid_password
# from django.core.exceptions import PermissionDenied
from django.contrib.auth.hashers import check_password, make_password
from datetime import datetime

logger = logging.getLogger("api_fuzzer_server_logger")
logger.propagate = False

class PostSubOrganizationSerializer(ModelSerializer):
    class Meta:
        model= SubOrganization
        fields= '__all__'
    
    def validate(self, attrs):
        data= self.initial_data
        org= data.get('org')
        if not org:
            raise serializers.ValidationError('org id is required')
        org_obj = Organization.objects.filter(org_id=org).first()
        if not org_obj:
            raise serializers.ValidationError('Organisation is not found with the given org id.')
        if (org_obj.level).lower() == 'low':
            if SubOrganization.objects.all().count() >= 1:
                raise serializers.ValidationError('Multiple Sub-Organisation is not allowed.')
        return attrs    
    
class EnvironmentSerializer(ModelSerializer):
    class Meta:
        model = Environment
        fields= '__all__'

class PostEnvironmentSerializer(ModelSerializer):
    class Meta:
        model= Environment
        fields= '__all__'

    def validate(self, attrs):
        data= self.initial_data
        sub_org= data.get('sub_org')
        org= data.get('org')
        name= data.get('name')
        env_obj= Environment.objects.filter(name=name).first()
        if not sub_org or not org or not name:
            raise serializers.ValidationError('Sub_org id, Org id, Name required')
        org_obj= Organization.objects.filter(org_id=org).first()
        if not org_obj:
            raise serializers.ValidationError('Organisation not found with given org id')
        sub_org_obj= SubOrganization.objects.filter(sub_org_id= sub_org).first()
        if not sub_org_obj:
            raise serializers.ValidationError('Sub-Organisation is not found with given sub_org id')
        if env_obj: 
            raise serializers.ValidationError('Environment already exist with this name')
        if name:
            name= name.lower()
        return attrs

class SMTPUserSerializer(ModelSerializer):
    name_regex = "^[a-zA-Z]([\\s](?![\\s])|[a-zA-Z]){1,32}[a-zA-Z]$"
    name_validator = RegexValidator(regex = name_regex, message = "The name should be having a minimum of 3 and maximum of 32 characters")
    password = serializers.JSONField(required=True)
    email = serializers.EmailField(required=True)
    name = serializers.CharField(required=True,
                                 max_length=32, 
                                 min_length=3,
                                 validators = [name_validator]
                                )
    keys_to_exclude = ['date_joined','updated_on','password', 'secret_key', 'password_timestamp']
    class Meta:
        model = User
        fields = ['name',"password",'last_login', 'email', 'is_active', 'rid']

    def validate_email(self,email):
        if User.objects.filter(email=email).exists():
            raise serializers.ValidationError("Email already exists")
        return email
    
    def validate(self, data):
        data["uu_id"] = str(uuid4()).replace('-','') # add uuid to the new user 
        data['name'] = data['name'].lower() # user name is always in lowercase
        data['is_staff'] = False
        data['email_verified'] = True
        admin_obj= User.objects.filter(is_staff=True).first()
        if admin_obj.is_smtp_enabled == True:
            data['password_timestamp']= datetime.now()
        if not check_valid_password(data['password']): # For password validation
            raise serializers.ValidationError("The password must contain a minimum of 8 characters, a minimum of 1 uppercase, a minimum of 1 lowercase, a minimum of 1 special character, and 1 number")
        return data
    
    def to_representation(self, instance):
        """
        In built serializer method which creates the representation of
        the queryset object.
        """
        representation = super().to_representation(instance)
        if isinstance(self.keys_to_exclude, list):
            for key in self.keys_to_exclude:
                representation.pop(key, None)
        return representation
    
    def create(self, validated_data):
        """
        Create or update the user details in the database.
        """
        user = User.objects._create_user(**validated_data)    
        return user

class EditUserSerializer(serializers.ModelSerializer):
    name_regex = "^[a-zA-Z]([\\s](?![\\s])|[a-zA-Z]){1,32}[a-zA-Z]$"
    name_validator = RegexValidator(regex = name_regex, message = "The name should be having a minimum of 3 and maximum of 32 characters")
    password = serializers.JSONField(required=False)
    email = serializers.EmailField(required=False)
    name = serializers.CharField(required=False,
                                 max_length=32, 
                                 min_length=3,
                                 validators = [name_validator,]
                                )
    class Meta:
        model = User
        fields = ['name', 'username', 'last_login', 'email','uu_id','is_active','password']    
    
    def validate_email(self,email):
        pk = self.context.get('request').parser_context.get('kwargs').get('pk')
        if email.lower() != User.objects.filter(id=pk).values()[0]['email']:
            logger.info(f"Email can not be updated {email}")
            raise serializers.ValidationError("Email can not be updated")
        return email
    
    def validate_password(self, password):
        if check_valid_password(password): # For password validation
            password = make_password(password)
        else:
            raise serializers.ValidationError("The password must contain a minimum of 8 characters, a minimum of 1 uppercase, a minimum of 1 lowercase, a minimum of 1 special character, and 1 number")
        return password
    
    def validate_role(self,role):
        if role ==" ROLE_ADMIN":
            raise serializers.ValidationError("Admin can not be updated")
        return role
        

    def validate(self, data):

        pk = self.context.get('request').parser_context.get('kwargs').get('pk')
        user_obj= User.objects.filter(id=pk).first()
        login_user= self.context.get('request').user
        if login_user.is_staff == True:
            data['is_admin']= True
            if not 'name' in data and not 'password' in data and not 'is_active' in data:
                raise serializers.ValidationError('Name, Password, is_active anyone required')
        else:
            data['is_admin']= False
            if not 'name' in data and not 'password' in data:
                raise serializers.ValidationError('Name, Password anyone required')
        data['email_verified'] = True
        if user_obj.is_staff == True:
            logger.info("Admin permissions can not be updated")
            raise serializers.ValidationError('Admin Permission can not be updated')      
        # Admin permissions can not be changed 
        if User.objects.get(id = pk).role == "ROLE_ADMIN":
            logger.info("Admin permissions can not be updated")
            raise serializers.ValidationError("Admin can not be updated")  
        return data
    
    def to_representation(self, instance):
        """
        In built serializer method which creates the representation of
        the queryset object.
        """
        representation = super().to_representation(instance)
        if instance.role == "ROLE_ADMIN":
            raise serializers.ValidationError("Admin details can't be accessed")
        permissions = Permission.objects.filter(user_ID = instance.id)
        permissions = PermissionSerializer(permissions,many=True).data
        permissions_representation = find_permissions_representation(permissions)
        representation.pop('password', None)# Exclude the 'password' field from the serialized data
        return representation
     
    def update(self,instance,validated_data):
        """
        This method is to update the resource details in the database
        """ 
        if "permissions" in self.context['request'].data:
            permissions = prepare_permission_data(self.context['request'].data['permissions'])
        else:
            if 'name' in validated_data:
                instance.name= validated_data['name'].lower()
            if 'password' in validated_data:
                instance.password= validated_data['password']
            if 'is_active' in validated_data:
                instance.is_active= validated_data['is_active']
        instance.save()
        return instance
    

class EdirProfileSerializer(serializers.ModelSerializer):
    old_password = serializers.CharField(required=False)
    name_regex = "^[a-zA-Z]([\\s](?![\\s])|[a-zA-Z]){1,32}[a-zA-Z]$"
    name_validator = RegexValidator(regex = name_regex, message = "The name should be having a minimum of 3 and maximum of 32 characters")
    name = serializers.CharField(required=False,
                                 max_length=32, 
                                 min_length=3,
                                 validators = [name_validator,]
                                )
                                

    class Meta:
        model = User
        fields = ['password', 'name', 'email', 'old_password']



    def validate_password(self,password): 
        if check_valid_password(password):  # For password validation
            password = make_password(password)
        else:
            raise serializers.ValidationError("The password must contain a minimum of 8 characters, a minimum of 1 uppercase, a minimum of 1 lowercase, a minimum of 1 special character, and 1 number")
        return password
    
    def validate(self, data):
        if 'password' in data and 'old_password' not in data:
            raise serializers.ValidationError("Old password is required")
        return data

    def update(self, instance, validated_data):
        if 'password' in validated_data:
            encoded_password = instance.password
            old_password = validated_data.get('old_password')
            if 'bcrypt_sha256' not in encoded_password:
                encoded_password = "%s$%s" % ('bcrypt_sha256', encoded_password)
            check = check_password(old_password, encoded_password)
            if not check:
                raise serializers.ValidationError("Old password is incorrect")
        return super().update(instance, validated_data)
