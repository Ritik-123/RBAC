# from .models import Role, Permission, RolePermission
# from django.http import JsonResponse
# from .models import User
# # from fuzzer.components.helper import JWTManager
# from django.urls import reverse, resolve
# # from fuzzer.components.helper import get_uuid
# from django.core.exceptions import PermissionDenied

# class RBACMiddleware:
#     def __init__(self, get_response):
#         self.get_response = get_response
#     def __call__(self, request):
#         if not self.check_permissions(request):
#             data= {
#                 "type": "PermissionDenied",
#                 "message": 'You do not have permission to perform this action',
#                 "field_name": None,  
#                 "status_code": 403
#             }
#             return JsonResponse(data)
#         response = self.get_response(request)
#         return response
        
#     def check_permissions(self, request):
#         if request.path == '/api/token' or request.path == 'api/token/refresh' or request.path == '/rbac/forgot-password/' or request.path == '/rbac/reset-password/':
#             return True
#         token = request.META.get('HTTP_AUTHORIZATION')
#         if not token:
#             return False
#         if token.startswith('Bearer'):
#             token= token.replace('Bearer ', '').replace('"', '')
#         if token == "" or token == '' or token == '{{access}}' or token == None:
#             return False
#         jwt_obj= JWTManager(token)
#         payload= jwt_obj.decode_jwt_token(token)
#         uid= payload[1]['id']
#         user_obj= User.objects.filter(uu_id= uid).first()
#         if not user_obj:
#             return False
#         role_id= user_obj.rid # role object
#         if not role_id:
#             return False
#         if user_obj.is_staff == True and role_id.name == 'superadmin' and role_id.is_staff == True: 
#             return True
#         resolve_match= resolve(request.path)
#         viewname= resolve_match.url_name
#         if viewname:    
#             api_method= request.method
#             if api_method == 'GET':
#                 perm_name= f"view_{viewname}"
#                 check_perm= Permission.objects.filter(codename= perm_name).first()
#                 if check_perm:
#                     allow_obj= RolePermission.objects.filter(rid= role_id, perm_id= check_perm.perm_id).first()
#                     if allow_obj:
#                         return True
#                     return False
#                 return True
#             if api_method == 'POST':
#                 perm_name= f"add_{viewname}"
#                 check_perm= Permission.objects.filter(codename= perm_name).first()
#                 if check_perm:
#                     allow_obj= RolePermission.objects.filter(rid= role_id, perm_id= check_perm.perm_id).first()
#                     if allow_obj:
#                         return True
#                     return False
#                 return True
#             if api_method == 'PATCH' or api_method == "PUT":
#                 perm_name= f"change_{viewname}"
#                 check_perm= Permission.objects.filter(codename= perm_name).first()
#                 if check_perm:
#                     allow_obj= RolePermission.objects.filter(rid= role_id, perm_id= check_perm.perm_id).first()
#                     if allow_obj:
#                         return True
#                     return False
#                 return True
#         else:
#             return True