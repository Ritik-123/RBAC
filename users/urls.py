# from django.urls import path
# from .views import  (
#                         AllOrganisation,
#                         AllSubOrganisation,
#                         AllEnvironment,
#                         AllRole,
#                         AllRolePermission,
#                         EmailToggle,
#                         CreateUser,
#                         UserList,
#                         UserRetrieveUpdateView,
#                         ForgotPassword,
#                         ResetPassword,
#                         ProfileView
#                     ) 

# urlpatterns = [
#     path('org/', AllOrganisation.as_view()),
#     path('sub-org/', AllSubOrganisation.as_view()),
#     path('env/', AllEnvironment.as_view()),
#     path('role/', AllRole.as_view()),
#     path('role-perm/', AllRolePermission.as_view()),
#     path('smtp-toggle/', EmailToggle.as_view()),
#     path('users/', CreateUser.as_view()),
#     path('users-list/',UserList.as_view()),
#     path('users/<int:pk>/',UserRetrieveUpdateView.as_view()),
#     path('forgot-password/', ForgotPassword.as_view()),
#     path('reset-password/',ResetPassword.as_view()),
#     path("profile",ProfileView.as_view())    
# ]