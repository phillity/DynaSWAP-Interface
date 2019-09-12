from django.conf.urls import url
from django.urls import path
from django.conf.urls.static import static
from django.conf import settings
from DynaSwapApp import views

urlpatterns = [
    url(r'^$', views.HomePageView.as_view(), name='home_page'),
    url(r'^register_page/$', views.RegisterPageView.as_view(), name='register_page'),
    url(r'^authenticate_page/$', views.AuthenticatePageView.as_view(), name='authenticate_page'),
    url(r'^accepted_page/$', views.AcceptedPageView.as_view(), name='accepted_page'),
    url(r'^rejected_page/$', views.RejectedPageView.as_view(), name='rejected_page'),
    url(r'^get_roles/$', views.GetRolesView.as_view(), name='get_roles'),
    url(r'^registration/$', views.RegisterView.as_view(), name='registration'),
    url(r'^authentication/$', views.AuthenticateView.as_view(), name='authentication'),
    url(r'^get_user_role/$', views.GetUserRoleView.as_view(), name='get_user_role'),
    path('graph/', views.GetGraph, name='get_graph'), 
    path('delete_role/', views.DeleteRoleView.as_view(), name='delete_role'),
    path('add_role/', views.AddRoleView.as_view(), name='add_role'),
    path('add_edge/', views.AddEdgeView.as_view(), name='add_edge'),
    path('delete_edge/', views.DeleteEdgeView.as_view(), name='delete_edge'),
]

urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
