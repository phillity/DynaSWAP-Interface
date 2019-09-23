from django.conf.urls import url
from django.urls import path
from django.conf import settings
from DynaSwapApp import views

urlpatterns = [
    path('graph/', views.GetGraph, name='get_graph'), 
    path('delete_role/', views.DeleteRoleView.as_view(), name='delete_role'),
    path('add_role/', views.AddRoleView.as_view(), name='add_role'),
    path('add_edge/', views.AddEdgeView.as_view(), name='add_edge'),
    path('delete_edge/', views.DeleteEdgeView.as_view(), name='delete_edge'),
]
