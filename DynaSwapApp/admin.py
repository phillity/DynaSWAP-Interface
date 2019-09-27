from django.contrib import admin

from DynaSwapApp.models import Roles, RoleEdges, Users

# Register your models here.
admin.site.register(Roles)
admin.site.register(RoleEdges)
admin.site.register(Users)