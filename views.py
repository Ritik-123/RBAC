"""
Views regarding user creation and updation.
"""
from rest_framework import status
from rest_framework.response import Response
from .serializers import *
from rest_framework.permissions import IsAuthenticated, IsAdminUser
import logging,string,random
from rest_framework.views import APIView
from rest_framework.generics import CreateAPIView,UpdateAPIView,RetrieveUpdateAPIView,ListAPIView
from django.contrib.auth.hashers import make_password
import random,datetime,time
from rest_framework.decorators import api_view
from django.core.mail import EmailMessage
from django.core.mail.backends.smtp import EmailBackend
from django.http import HttpResponse
from fuzzer.components.customlog import AESCipher
from fuzzer.models import SMTP,BlacklistedDomains
from fuzzer.components.helper import base64_encode,base64
from uuid import uuid4
from datetime import datetime, timedelta
from django.utils import timezone
import pytz
from django.forms.models import model_to_dict

logger = logging.getLogger("api_fuzzer_server_logger")
logger.propagate = False

def secret_key(size=32, chars=string.ascii_uppercase + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))

# For Organisation
class AllOrganisation(APIView):
    """
    This api is only for GET Method.
    Input : org id.
    return organisation info
    -> Organisation detail will be auto filled through license.

    """
    permission_classes= [IsAdminUser]
    def get(self, request):
        org= request.query_params.get('org')
        if not org:
            raise serializers.ValidationError('Org id is required')
        org_details = Organization.objects.filter(org_id=org).values().first()
        if not org_details:
            raise serializers.ValidationError('Organisation is not found with the given org id')
        if 'level' in org_details:
            org_details.pop('level')
        return Response(org_details,status=status.HTTP_200_OK)
    
class AllSubOrganisation(APIView):
    """
    This class is for get, post, patch Suborganisation.

    GET Method : 
        If sub_org_id is present in request.data then this api will return only that sub_org_id related info.
        Else it will return all the sub_org list (No nee of org_id as it is always one).
    
    POST Method : 
        This api is for creating a new suborganisation.
        Input : org_id is required.
            -> First we check by given org_id is exist.
        ------
        For Now not more than one Sub Organisation.
        # if organisation level is small then Not more than one suborganisation.
        # if organisation level is high then as many as he wants.

    PATCH Method:
        This api is update the existing data. 
        Input : org_id, sub_org_id
        -> Only change name of sub-organisation.
    """
    permission_classes= [IsAdminUser]
    def get(self, request):
        payload = request.query_params
        org= payload.get('org')
        sub_org= payload.get('sub_org')
        if not org and not sub_org:
            raise serializers.ValidationError('Org id or sub_org id any one is required')
        if sub_org:
            sub_org_details= SubOrganization.objects.filter(sub_org_id= sub_org).values().first()
            if not sub_org_details:
                raise serializers.ValidationError('Sub-Organisation not found with given sub_org id')
            return Response(sub_org_details,status=status.HTTP_200_OK)
        org_obj= Organization.objects.filter(org_id= org).first()
        if not org_obj:
            raise serializers.ValidationError('Organisation not found with given org id')
        sub_org_details= list(SubOrganization.objects.filter(org_id= org).values())
        return Response(sub_org_details,status=status.HTTP_200_OK)
       
    def post(self, request):
        payload = request.data
        serializer= PostSubOrganizationSerializer(data=payload) 
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        print(serializer.errors)
        return Response({'msg': 'Sub-Organisation not created'}) 
    
    def patch(self, request):
        payload = request.data
        name= payload.get('name')
        if not name:
            raise serializers.ValidationError('Name is required')
        sub_org = request.query_params.get('sub_org')
        if not sub_org:
            raise serializers.ValidationError('Sub-org id is required')
        sub_org_obj= SubOrganization.objects.filter(sub_org_id=sub_org).first()
        if not sub_org_obj:
            raise serializers.ValidationError('Sub-organisation not found with given sub_org id')
        sub_org_obj.name= name
        sub_org_obj.save()
        data=SubOrganization.objects.filter(sub_org_id=sub_org).values().first()
        return Response(data,status=status.HTTP_200_OK)   

class AllEnvironment(APIView):
    """
    This class is for get, post, patch the environment. 

    GET Method :
        if env_id is present in request.data then it will return only that env info. 
        If sub_org_id is present in request.data then this api will return all the environment list related with 
        \ sub_org_id.
    
    POST Method : 
        This api is for creating a new Environment.
        Input :Org_id and sub_org_id required.
            -> First we check by given org_id and sub_org_id exist.
        create many env as superadmin want.
    
    PATCH Method:
        This api is update the existing data. 
        Input : sub_org_id
            -> Only name will be update.
    """
    permission_classes= [IsAdminUser]   
    def get(self, request):
        payload= request.query_params
        env_id= payload.get('env_id')
        sub_org_id = payload.get('sub_org_id')
        if not env_id and not sub_org_id:
            raise serializers.ValidationError('Env id or sub_org_id anyone is required')
        if env_id:
            data= Environment.objects.filter(env_id= env_id).values().first()
            if not data:
                raise serializers.ValidationError('Environment not found with given env_id')
            return Response(data,status=status.HTTP_200_OK)
        sub_org_obj= SubOrganization.objects.filter(sub_org_id= sub_org_id).first()
        if not sub_org_obj:
            raise serializers.ValidationError('Sub Organisation not found with given sub_org_id')
        data= list(Environment.objects.filter(sub_org_id=sub_org_id).values())
        return Response(data,status=status.HTTP_200_OK)        
    
    def post(self, request):
        payload= request.data        
        serializer= PostEnvironmentSerializer(data= payload)
        if serializer.is_valid(raise_exception= True):
            serializer.save()
            return Response(serializer.data,status=status.HTTP_201_CREATED)
        print(serializer.errors)
        return Response({'msg': 'Environment not updated'})
        
    def patch(self, request):
        payload= request.data
        env= request.query_params.get('env')
        name= payload.get('name')
        if not env:
            raise serializers.ValidationError('Env id is required')
        if not name:
            raise serializers.ValidationError('Name is required')
        env_obj= Environment.objects.filter(env_id=env).first()
        if not env_obj:
            raise serializers.ValidationError('Environment not found with given env_id')
        existing_obj= Environment.objects.filter(name=name).first()
        if existing_obj:
            raise serializers.ValidationError('Environment already exist with this name')
        env_obj.name= name
        env_obj.save()
        data= Environment.objects.filter(env_id=env).values().first()
        return Response(data, status=status.HTTP_200_OK)
class AllRole(APIView):
    """
    This class is for get, create, update Role.

    GET Method :
        if role_id is present in request.data then it will return only that role info. 
        If env_id is present in request.data then this api will return all the role list related with 
        \ env_id.
    
    POST Method : 
        This api is for creating a new Environment.
        Input :org_id and env_id is required.
            -> First we check by given org_id env_id is exist.
            -> Only three roles are allowed per environment.(That's why we need org_id)
        If organisation has level= 'high' then it will create many role as he want.
        Else only three roles are allowed per environment.
        For Now there should be three roles per environment.

    PATCH Method:
        This api is update the existing data. 
        Input : role_id
            -> Only name will be update.
    """
    permission_classes= [IsAdminUser]
    def get(self, request):
        payload= request.query_params
        role= payload.get('rid')
        env= payload.get('env')
        if not env and not role:
            raise serializers.ValidationError('Env_id or rid anyone is required')
        if role:
            role_detail= Role.objects.filter(rid=role).values().first()
            if not role_detail:
                raise serializers.ValidationError('Role not found with given rid')
            if 'is_staff' in role_detail:
                role_detail.pop('is_staff')
            return Response(role_detail,status=status.HTTP_200_OK)
        env_obj= Environment.objects.filter(env_id= env).first()
        if not env_obj:
            raise serializers.ValidationError('Environment not found with given env_id')
        role_details= list(Role.objects.filter(env_id=env).values())
        for role in role_details:
            role.pop('is_staff')
        return Response(role_details,status=status.HTTP_200_OK)

    def post(self, request):
        payload= request.data
        env= payload.get('env')
        org= payload.get('org')
        name= payload.get('name')
        if not org or not env:
            raise serializers.ValidationError('Org id and env id both required')
        org_obj= Organization.objects.filter(org_id=org).first()
        if not org_obj:
            raise serializers.ValidationError('Organisation not found with given org id')
        env_obj= Environment.objects.filter(env_id= env).first()
        if not env_obj:
            raise serializers.ValidationError('Environment not found with given env_id')            
        if not name:
            raise serializers.ValidationError('Name (name) is required')    
        name= name.lower()
        if name == 'superadmin':
            raise serializers.ValidationError('Role name not be superadmin')
        role_obj= Role.objects.filter(name= name, env_id= env).first()
        if role_obj:
            raise serializers.ValidationError('Role already exist with this name')
        if (org_obj.level).lower() == 'low':
            if Role.objects.filter(env_id= env).count() >= 3:
                raise serializers.ValidationError('Only three roles are allowed per Environment')
        r_obj= Role.objects.create(name= name, env_id= env)
        r_obj.save()
        return Response({
            'rid':r_obj.rid,
            'name':r_obj.name,
            'env_id':r_obj.env.env_id
        },status=status.HTTP_201_CREATED)
        
    def patch(self, request):        
        payload= request.data
        role= request.query_params.get('rid')
        name= payload.get('name')
        env= request.query_params.get('env') # required to check role with same name exist or not.
        if not role or not env or not name:
            raise serializers.ValidationError('Role id, env_id, name required')
        env_obj= Environment.objects.filter(env_id=env).first()
        if not env_obj:
            raise serializers.ValidationError('Environment not found with given env id')
        role_obj= Role.objects.filter(rid= role).first()
        if not role_obj:
            raise serializers.ValidationError('Role not found with given id')
        existing_obj= Role.objects.filter(rid=role, env_id=env).first()
        if not existing_obj:
            raise serializers.ValidationError('Role not exist in given Env id')
        temp_obj= Role.objects.filter(name=name, env_id= env).first()
        if temp_obj:
            raise serializers.ValidationError('Role already exist with this name')
        role_obj.name= name
        role_obj.save()
        data= Role.objects.filter(rid= role).values().first()
        if 'is_staff' in data:
            data.pop('is_staff')
        return Response(data,status=status.HTTP_200_OK)
            
class AddPermList:
    """
    This class prepare the permission list for post(create) and patch(update)case.
    """
    def __init__(self, perm):
        self.perm= perm

    def prepare_list(self):
        # For projects.
        view_p= Permission.objects.filter(codename= 'view_projects').first()
        add_p= Permission.objects.filter(codename= 'add_projects').first()
        change_p= Permission.objects.filter(codename= 'change_projects').first()
        assign_p= Permission.objects.filter(codename= 'change_assign_projects').first()
        view_p_id= view_p.perm_id
        add_p_id= add_p.perm_id
        change_p_id= change_p.perm_id
        assign_p_id= assign_p.perm_id
        if view_p_id not in self.perm:
                self.perm.append(view_p_id)
        if add_p_id in self.perm:
            if view_p_id not in self.perm:
                self.perm.append(view_p_id)
        if change_p_id in self.perm:
            if view_p_id not in self.perm:
                self.perm.append(view_p_id)
            if add_p_id not in self.perm:
                self.perm.append(add_p_id)
        if assign_p_id in self.perm:
            if view_p_id not in self.perm:
                self.perm.append(view_p_id)
            if add_p_id not in self.perm:
                self.perm.append(add_p_id)
            if change_p_id not in self.perm:
                self.perm.append(change_p_id)
        # For Scans.
        view_s= Permission.objects.filter(codename= 'view_scans').first()
        add_s= Permission.objects.filter(codename= 'add_scans').first()
        change_s= Permission.objects.filter(codename= 'change_scans').first()
        view_s_id= view_s.perm_id
        add_s_id= add_s.perm_id
        change_s_id= change_s.perm_id
        if view_s_id in self.perm:
            if view_p_id not in self.perm:
                self.perm.append(view_p_id)
        if add_s_id in self.perm:
            if view_p_id not in self.perm:
                self.perm.append(view_p_id)
            if view_s_id not in self.perm:
                self.perm.append(view_s_id)
            if change_s_id not in self.perm:
                self.perm.append(change_s_id)
        # For Individual API's.
        view_ind= Permission.objects.filter(codename= 'view_individual_api').first()
        add_ind= Permission.objects.filter(codename= 'add_individual_api').first()
        change_ind= Permission.objects.filter(codename= 'change_individual_api').first()
        view_ind_id= view_ind.perm_id
        add_ind_id= add_ind.perm_id
        change_ind_id= change_ind.perm_id
        if view_ind_id in self.perm:
            if view_p_id not in self.perm:
                self.perm.append(view_p_id)
        if add_ind_id in self.perm:
            if view_ind_id not in self.perm:
                self.perm.append(view_ind_id)
            if change_ind_id not in self.perm:
                self.perm.append(change_ind_id)
        if change_ind_id in self.perm:
            if view_ind_id not in self.perm:
                self.perm.append(view_ind_id)
            if add_ind_id not in self.perm:
                self.perm.append(add_ind_id)
        # For Custom Payloads.
        view_payload= Permission.objects.filter(codename= 'view_custom_payload').first()
        add_payload= Permission.objects.filter(codename= 'add_custom_payload').first()
        change_payload= Permission.objects.filter(codename= 'change_custom_payload').first()
        view_payload_id= view_payload.perm_id
        add_payload_id= add_payload.perm_id
        change_payload_id= change_payload.perm_id
        if add_payload_id in self.perm:
            if view_payload_id not in self.perm:
                self.perm.append(view_payload_id)
        if change_payload_id in self.perm:
            if view_payload_id not in self.perm:
                self.perm.append(view_payload_id)
            if add_payload_id not in self.perm:
                self.perm.append(add_payload_id)
        # For Custom Status Codes.
        view_code= Permission.objects.filter(codename= 'view_custom_status_codes').first()
        add_code= Permission.objects.filter(codename= 'add_custom_status_codes').first()
        change_code= Permission.objects.filter(codename= 'change_custom_status_codes').first()
        view_code_id= view_code.perm_id
        add_code_id= add_code.perm_id
        change_code_id= change_code.perm_id
        if add_code_id in self.perm:
            if view_code_id not in self.perm:
                self.perm.append(view_code_id)
        if change_code_id in self.perm:
            if view_code_id not in self.perm:
                self.perm.append(view_code_id)
            if add_code_id not in self.perm:
                self.perm.append(add_code_id)
         # For reports.   
        view_html= Permission.objects.filter(codename= 'view_html').first()
        view_pdf= Permission.objects.filter(codename= 'view_pdf').first()
        view_excel= Permission.objects.filter(codename= 'view_excel').first()
        view_html_id= view_html.perm_id
        view_pdf_id= view_pdf.perm_id
        view_excel_id= view_excel.perm_id   
        if view_html_id in self.perm:
            if view_s_id not in self.perm:
                self.perm.append(view_s_id)
            if view_p_id not in self.perm:
                self.perm.append(view_p_id)
        if view_pdf_id in self.perm:
            if view_s_id not in self.perm:
                self.perm.append(view_s_id)
            if view_p_id not in self.perm:
                self.perm.append(view_p_id)
            if view_html_id not in self.perm:
                self.perm.append(view_html_id)
        if view_excel_id in self.perm:
            if view_s_id not in self.perm:
                self.perm.append(view_s_id)
            if view_p_id not in self.perm:
                self.perm.append(view_p_id)
            if view_html_id not in self.perm:
                self.perm.append(view_html_id)
        # For Compare.
        compare_html= Permission.objects.filter(codename= 'add_compare_html').first()
        compare_pdf= Permission.objects.filter(codename= 'add_compare_pdf').first()
        compare_excel= Permission.objects.filter(codename= 'add_compare_excel').first()
        compare_html_id= compare_html.perm_id
        compare_pdf_id= compare_pdf.perm_id
        compare_excel_id= compare_excel.perm_id     
        if compare_html_id in self.perm:
            if view_s_id not in self.perm:
                self.perm.append(view_s_id)
            if view_p_id not in self.perm:
                self.perm.append(view_p_id)
            if view_html_id not in self.perm:
                self.perm.append(view_html_id)
        if compare_pdf_id in self.perm:
            if view_s_id not in self.perm:
                self.perm.append(view_s_id)
            if view_p_id not in self.perm:
                self.perm.append(view_p_id)
            if view_html_id not in self.perm:
                self.perm.append(view_html_id)
            if compare_html_id not in self.perm:
                self.perm.append(compare_html_id)
            if view_pdf_id not in self.perm:
                self.perm.append(view_pdf_id)
        if compare_excel_id in self.perm:
            if view_s_id not in self.perm:
                self.perm.append(view_s_id)
            if view_p_id not in self.perm:
                self.perm.append(view_p_id)
            if view_html_id not in self.perm:
                self.perm.append(view_html_id)
            if compare_html_id not in self.perm:
                self.perm.append(compare_html_id)
            if view_excel_id not in self.perm:
                self.perm.append(view_excel_id)
        return self.perm
    
class AllRolePermission(APIView):
    """
    This class is for Get, Post, Patch Role.

    GET Method :
        if role_id is present in request.data then it will return the all permission assign to that role. 
            
    POST Method : 
        This api is for assign permission to role.
        Input: rid (Role id) is required.
            -> First we check by given rid is exist.
    
    PATCH Method:
        This api is update permission of role. 
        Input : role_id
        -> All existing permission will be deleted and new permissions are assigned to role. 
    """
    permission_classes= [IsAdminUser]
    def get(self, request):
        payload= request.query_params
        role= payload.get('rid')
        if not role:
            raise serializers.ValidationError('Role id is required')
        role_obj= Role.objects.filter(rid=role).first()
        if not role_obj:
            raise serializers.ValidationError('Role not found with given role id')
        data= list(RolePermission.objects.filter(rid= role).order_by('role_perm_id').values())
        if not data:
            return Response({'msg': 'No Permission assign to role'})
        return Response(data,status=status.HTTP_200_OK)

    def post(self,request):
        payload= request.data
        role= payload.get('rid')
        perm_value= payload.get('perm') #should be int value in a list
        perm = [perm_value] if isinstance(perm_value, int) else perm_value if isinstance(perm_value, list) else []
        if not role:
            raise serializers.ValidationError('Role id is required')
        if perm == '' or perm == [] or perm == "" or perm == None:
            raise serializers.ValidationError('Permission id is required')
        role_obj= Role.objects.filter(rid= role).first()
        if not role_obj:
            raise serializers.ValidationError('Role not found with given role id')
        if role_obj.name == 'superadmin' and role_obj.is_staff == True:
            raise serializers.ValidationError('Cannot assign permission to Superadmin')
        role_perm_obj= RolePermission.objects.filter(rid= role).first()
        if role_perm_obj:
            raise serializers.ValidationError('Role already exist in Role Permission table')
        prepare_obj= AddPermList(perm)
        perm= prepare_obj.prepare_list()
        success= []
        failure= []
        for i in perm:
            perm_obj= Permission.objects.filter(perm_id= i).first()
            if not perm_obj:
                failure.append({'perm id': i, 'msg': 'Permission not found'})
                continue
            existing_obj= RolePermission.objects.filter(rid= role, perm_id= i).first()
            if existing_obj:
                failure.append({'perm_id': perm_obj.perm_id, 'codename':perm_obj.codename, 'name':perm_obj.name, 'msg': 'Permission already assigned to role'})
                continue
            RolePermission.objects.create(perm_id= perm_obj.perm_id, rid= role_obj)
            success.append({'perm_id': perm_obj.perm_id, 'codename': perm_obj.codename, 'name': perm_obj.name})
        print(f"failure:{failure}")
        return Response(success,status=status.HTTP_201_CREATED)

    def patch(self, request):
        payload= request.data
        role= request.query_params.get('rid')
        perm_value= payload.get('perm')
        perm = [perm_value] if isinstance(perm_value, int) else perm_value if isinstance(perm_value, list) else []        
        if perm == '' or perm == [] or perm == "" or perm == None:
            raise serializers.ValidationError('Permission id is required')
        if not role:
            raise serializers.ValidationError('Role id is required')
        role_obj= Role.objects.filter(rid= role).first()
        if not role_obj:
            raise serializers.ValidationError('Role not exist with given role id')
        if role_obj.name == 'superadmin' and role_obj.is_staff == True:
            raise serializers.ValidationError('Cannot assign permission to Superadmin')
        role_perm= RolePermission.objects.filter(rid=role)
        if not role_perm:
            raise serializers.ValidationError('Role not exist in Role permission table')
        role_perm.delete()
        prepare_obj= AddPermList(perm)
        perm= prepare_obj.prepare_list()
        success= []
        failure= []
        for i in perm:
            perm_obj= Permission.objects.filter(perm_id= i).first()
            if not perm_obj:
                failure.append({'perm id': i, 'msg': 'Permission not found'})
                continue
            existing_obj= RolePermission.objects.filter(rid= role, perm_id= i).first()
            if existing_obj:
                failure.append({'perm_id': perm_obj.perm_id, 'codename':perm_obj.codename, 'name':perm_obj.name, 'msg': 'Permission already assigned to role'})
                continue
            RolePermission.objects.create(perm_id= perm_obj.perm_id, rid= role_obj)
            success.append({'perm_id': perm_obj.perm_id, 'codename': perm_obj.codename, 'name': perm_obj.name})
        return Response(success,status=status.HTTP_200_OK)    
    
class EmailToggle(APIView):
    """
    This Api will update SMTP boolean value of admin in User table.
    -> If it is True then user will be created through SMTP.
    -> Else user will be created without SMTP.
    """
    permission_classes= [IsAdminUser]
    def patch(self, request):
        bool_value= request.data.get('bool_value')
        if bool_value == None or bool_value == "":
            raise serializers.ValidationError('Boolean value is required')
        admin_obj= User.objects.filter(is_staff=True).first()
        if not admin_obj:
            raise serializers.ValidationError('Admin not found')
        if bool_value == True:
            if admin_obj.is_smtp_enabled == True:
                return Response({'msg': 'Mail Toggle already enable'})
            admin_obj.is_smtp_enabled = True
            admin_obj.save()
            return Response({'msg': 'Mail Toggle enable'})
        if admin_obj.is_smtp_enabled == False:
                return Response({'msg': 'Mail Toggle already disable'})
        admin_obj.is_smtp_enabled = False
        admin_obj.save()
        return Response({'msg': 'Mail Toggle disable'})
        
class UserRetrieveUpdateView(RetrieveUpdateAPIView):
    """
    For updating the user details.

    This class view updates the User details
    in the user table.
    """
    lookup_field = 'pk'
    lookup_url_kwarg = 'pk'
    serializer_class = EditUserSerializer
    def get_queryset(self):
        user= self.request.user
        rid= user.rid
        if rid.name == 'superadmin' and rid.is_staff == True:
            user_id= self.kwargs[self.lookup_url_kwarg]
            queryset= User.objects.filter(id=user_id)    
        else:
            find_user= self.kwargs[self.lookup_url_kwarg]
            if user.id != find_user:
                raise serializers.ValidationError('Given user id not match with user')
            queryset= User.objects.filter(id=user.id)
        return queryset
       
class CreateUser(APIView):
    """
    This api is for creating User with SMTP or without SMTP.
    """
    permission_classes= [IsAdminUser]
    def post(self, request):
        data= request.data
        if 'rid' not in data or 'name' not in data or 'email' not in data or 'password' not in data:
            raise serializers.ValidationError('Name, Email, Password, Role id must required')
        rid= data['rid']
        rid_obj= Role.objects.filter(rid=rid).first()
        if not rid_obj:
            raise serializers.ValidationError('Role not found with given id')
        if rid_obj.name == 'superadmin' and rid_obj.is_staff == True:
            raise serializers.ValidationError('User can not add in superadmin role')
        admin_obj= User.objects.filter(is_staff=True).first()
        if admin_obj.is_smtp_enabled == False:
            serializer= SMTPUserSerializer(data= request.data)
            if serializer.is_valid(raise_exception=True):
                serializer.save()
                return Response(serializer.data,status=status.HTTP_201_CREATED)
        else:
            if not SMTP.objects.order_by('-id').first():
                raise serializers.ValidationError('SMTP credentials not found')
            user= request.data
            if User.objects.filter(email=request.data.get('email')).exists():
                raise serializers.ValidationError("Email already exists")
            serializer= SMTPUserSerializer(data= request.data)
            if serializer.is_valid(raise_exception=True):
                flag= self.send_link(user)
                if flag == False:
                    return Response({'msg': 'Email not sent, User not created'})
                serializer.save()
                return Response(serializer.data,status=status.HTTP_201_CREATED)
        
    def send_link(self,user):
        """
        This method is for sending the verificstion link to mail given by the user.
        """
        try:
            obj = AESCipher()
            to_email = user['email']
            timestamp= str(datetime.now())
            decode_timestamp = base64.b64encode(bytes(timestamp,'utf-8'))
            encoded_timestamp= decode_timestamp.decode('utf-8')       
            smtp_data= SMTP.objects.order_by('-id').first()
            password = obj.decrypt(smtp_data.password).decode('utf8')
            backend = EmailBackend(host=smtp_data.host, port=smtp_data.port, username=smtp_data.username,password=password, fail_silently=False)
            subject = "EMAIL VERIFICATION"
            domain = BlacklistedDomains.objects.filter(description="Dfront").values('host')[0]['host']
            msg = f"Hi {user['name']},\n"\
                "This email id sent for verification of you RAPIFUZZ account.\n"\
                f"Please go to this link and verify your account: http://{domain}/account/verification?timestamp={encoded_timestamp}\n"\
                "Kindly note the link is valid for 15 minutes from the reception time of this email,\n"\
                "If it has expired kindly use the 'Refresh link' button in the verification page to generate new link which will be sent to your mail again.\n"\
                "Regards,\n"\
                "RAPIFUZZ Team"
            email = EmailMessage(subject=subject, body=msg, from_email= smtp_data.username, to = [to_email], connection=backend)
            a= email.send()
            if a == 0:
                logger.info("Email failed %s", to_email)
                return False
            logger.info("Email sent successfully to %s", to_email)
            return True
        except Exception as e:
            logger.exception(str(e))
            return False

class ForgotPassword(APIView):
    """
    Input : Email
    This api Sends the link to email for reset password 
    """
    def patch(self, request):
        email = request.data.get('email')
        if not email:
            raise serializers.ValidationError('email must required')
        admin_obj= User.objects.filter(is_staff=True).first()
        if admin_obj.is_smtp_enabled == False:
            raise serializers.ValidationError('SMTP disable')
        if not SMTP.objects.order_by('-id').first():
                raise serializers.ValidationError('SMTP credentials not found')
        user_obj= User.objects.filter(email= email).first()
        if not user_obj:
            logger.info('User not found')
            return HttpResponse('Email sent', status= status.HTTP_200_OK)
        if user_obj.is_staff == True:
            raise serializers.ValidationError('Admin credentials can not changed')
        user_obj.password_timestamp = datetime.now()
        user_obj.save()
        user= {'name': user_obj.name, 'email':user_obj.email}
        a=self.send_link(user)
        if a == False:
            return Response('msg : Email not sent, Timestamp updated',status=status.HTTP_200_OK)
        return Response({"msg" : "Timestamp updated, Email sent"},status=status.HTTP_200_OK)
    
    def send_link(self,user):
        """
        This method is for sending the otp to mail given by the user.
        """
        try:
            obj = AESCipher()
            to_email = user['email']
            user_obj= User.objects.filter(email= to_email).first()
            timestamp= str(user_obj.password_timestamp)
            decode_timestamp = base64.b64encode(bytes(timestamp,'utf-8'))
            encoded_timestamp= decode_timestamp.decode('utf-8')         
            smtp_data= SMTP.objects.order_by('-id').first()
            password = obj.decrypt(smtp_data.password).decode('utf8')
            backend = EmailBackend(host=smtp_data.host, port=smtp_data.port, username=smtp_data.username,password=password, fail_silently=False)
            subject = "EMAIL VERIFICATION"
            domain = BlacklistedDomains.objects.filter(description="Dfront").values('host')[0]['host']
            msg = f"Hi {user['name']},\n"\
                "This email id sent for Reset-Password of your RAPIFUZZ account.\n"\
                f"Please go to this link and verify your account: http://{domain}/account/verification?timestamp={encoded_timestamp}\n"\
                "Kindly note the link is valid for 15 minutes from the reception time of this email,\n"\
                "If it has expired kindly use the 'Refresh link' button in the verification page to generate new link which will be sent to your mail again.\n"\
                "Regards,\n"\
                "RAPIFUZZ Team"
            email = EmailMessage(subject=subject, body=msg, from_email= smtp_data.username, to = [to_email], connection=backend)
            a= email.send()
            if a == 0:
                logger.info("Email failed %s", to_email)
                return False
            logger.info("Email sent successfully to %s", to_email)
            return True
        except Exception as e:
            logger.exception(str(e))
            return False

class ResetPassword(APIView):
    """
    Input : Email, Password
    This api reset the password and send the confirmation email.
    """
    def patch(self, request):
        data = request.data
        email= data.get('email')
        now= datetime.now(pytz.timezone('Asia/Kolkata'))
        if not email:
            raise serializers.ValidationError('email must required')
        password = data['password']
        if not password:
            raise serializers.ValidationError('Password required')
        admin_obj= User.objects.filter(is_staff=True).first()
        if admin_obj.is_smtp_enabled == False:
            raise serializers.ValidationError('SMTP disable')
        if not SMTP.objects.order_by('-id').first():
                raise serializers.ValidationError('SMTP credentials not found')
        user_obj= User.objects.filter(email= email).first()
        if not user_obj:
            logger.info('User not found')
            return HttpResponse('Password Updated, Email sent', status= status.HTTP_200_OK)
        if user_obj.is_staff == True:
            raise serializers.ValidationError('Admin credentials can not changed')
        user_time= user_obj.password_timestamp
        if not user_time:
            return Response('msg : Link Expired')
        user_time= timezone.localtime(user_obj.password_timestamp) # Convert time to calculate the difference             
        time_diff= now - user_time
        fifteen_min= timedelta(minutes=15)
        if time_diff <= fifteen_min:
            user_obj.password= make_password(password)
            user_obj.password_timestamp = None
            user_obj.save()
            user ={'name': user_obj.name, 'email': user_obj.email}
            a = self.send_link(user)
            if a == False:
                return Response('msg : Email not sent, Password updated')
            return Response({"msg" : "Password updated, Email sent"},status=status.HTTP_200_OK)
        return Response({'msg': 'Link expired'})
    
    def send_link(self,user):
        """
        This method is for sending the otp to mail given by the user.
        """
        try:
            obj = AESCipher()
            to_email = user['email']     
            smtp_data= SMTP.objects.order_by('-id').first()
            password = obj.decrypt(smtp_data.password).decode('utf8')
            backend = EmailBackend(host=smtp_data.host, port=smtp_data.port, username=smtp_data.username,password=password, fail_silently=False)
            subject = "PASSWORD UPDATE NOTIFICATION"
            msg =   f"Hi {user['name']},\n"\
                    f"This is to inform you that your password for RAPIFUZZ account has been successfully updated.\n"\
                    "Your account security is important to us, and we appreciate your effort to keep your password secure.\n"\
                    "If you did not make this change, please contact to Admin immediately.\n"\
                    "Thank you for using RAPIFUZZ.\n"\
                    "Regards,\n"\
                    "RAPIFUZZ Team"                
            email = EmailMessage(subject=subject, body=msg, from_email= smtp_data.username, to = [to_email], connection=backend)
            a= email.send()
            if a == 0:
                logger.info("Email failed %s", to_email)
                return False
            logger.info("Email sent successfully to %s", to_email)
            return True
        except Exception as e:
            logger.exception(str(e))
            return False
    
class UserList(APIView):
    permission_classes= [IsAdminUser]
    def get(self, request):
        data= list(User.objects.all().values())
        data = [{k: v for k, v in user_data.items() if k != 'password'} for user_data in data]
        return Response(data,status=status.HTTP_200_OK)
    
from django.contrib.auth.hashers import check_password,make_password
from fuzzer.components.authbackend import CustomPasswordHasher
class ProfileView(APIView):


    permission_class = IsAuthenticated
    def get(self,request):
        user = User.objects.get(email=str(getattr(request, 'user', '')))
        user_id,name = user.id,user.name
        
        return Response({
            "name":name,
            "email":user.email
        })
 
    def patch(self,request):

     
 
       
        try:
            instance = User.objects.get(email=str(getattr(request, 'user', '')))
        except User.DoesNotExist:
            return Response(status=status.HTTP_404_NOT_FOUND)

        serializer = EdirProfileSerializer(instance, data=request.data, partial=True)
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            return Response({"message":"Profile updated successfully"} ,status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

