from django import forms
from DynaSwapApp.models import Roles
 
class allRoles(forms.Form):

    roleList = []

    for role in Roles.objects.all():
        roleList.append([role.role, role.role])

    allRoleChoices = forms.ChoiceField(choices=roleList)


class allEdges(forms.Form):

    roleList = []

    for role in Roles.objects.all():
        roleList.append([role.role, role.role])

    parentRoleChoices = forms.ChoiceField(choices=roleList)
    childRoleChoices = forms.ChoiceField(choices=roleList)
    

