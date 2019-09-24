import numpy as np
import json
import queue
from django import forms
from DynaSwapApp.forms import allRoles, allEdges
from django.http import JsonResponse, HttpResponseRedirect, HttpResponse
from django.shortcuts import render, render_to_response
from django.views.generic import TemplateView, View, CreateView
from DynaSwapApp.models import Roles, Users, UsersRoles, RoleEdges
from DynaSwapApp.services.dag import Node, Edge, DAG
from DynaSwapApp.services.acp import ACP
from django.urls import reverse_lazy



#simple view to display the graph
def GetGraph(request):
    roles = []
    edges = []
    graph = DAG()

    checkVisited = dict()
    rightCor = dict()
    checkOrigin = dict()

    for node in graph.node_list.keys():
        checkOrigin[node] = True

    for node in graph.node_list.keys():
        checkVisited[node] = False
        for edge in graph.node_list[node].edges.keys():
            checkOrigin[edge] = False
    q = queue.Queue()
    row = 0
    for origin in checkOrigin.keys():
        if checkOrigin[origin]:
            q.put(origin)
            checkVisited[origin] = True
    
    while not q.empty():
        row = row + 1
        rightCor[row] = 1
        qsize = q.qsize()
        for i in range(qsize):
            cur = q.get()
            roles.append({'id': cur, 'label': cur, 'x': 30 / (qsize + 1) * rightCor[row], 'y': row * 5, 'size': 5})
            rightCor[row] = rightCor[row] + 1
            for curedge in graph.node_list[cur].edges.keys():
                if not checkVisited[curedge]:
                    q.put(curedge)
                    checkVisited[curedge] = True
    
    inc = 1
    for node in graph.node_list.keys():
        for edge in graph.node_list[node].edges.keys():
            edges.append({'id': inc, "source": node, "target": edge})
            inc = inc + 1

    JsonList = {'nodes': roles, "edges": edges}

    return render(
        request, 'graph.html', {
            'JsonList': json.dumps(JsonList),
        }
    )

 
class DeleteRoleView(View):
    
    def get(self, request):
        roleTab = allRoles()
        return render(request, 'delete_role.html', locals())


    def post(self, request):
        selectRole = allRoles(request.POST)
        if selectRole.is_valid():    
            getRole = request.POST.get('allRoleChoices', "")

            graph = DAG()
            graph.del_role(getRole)
            return HttpResponseRedirect(reverse_lazy('get_graph')) 


class AddRoleView(CreateView):
    model = Roles
    template_name = "add_role.html"
    fields = ['role', 'description']
    
    def form_valid(self, form):
        self.object = form.save()
        name = self.object.role
        desc = self.object.description
        graph = DAG()
        graph.add_node(name, desc)
        return HttpResponseRedirect(self.get_success_url())


class AddEdgeView(View):
    
    def get(self, request):
        roleTab = allEdges()
        return render(request, 'add_edge.html', locals())

    def post(self, request):
        resultObj = allEdges(request.POST)
        if resultObj.is_valid():
            parentRole = request.POST.get('parentRoleChoices', "")
            childRole = request.POST.get('childRoleChoices', "")

            graph = DAG()
            graph.add_edge(parentRole, childRole)
            return HttpResponseRedirect(reverse_lazy('get_graph')) 

class DeleteEdgeView(View):

    def get(self, request):
        roleTab = allEdges()
        return render(request, 'delete_edge.html', locals())

    def post(self, request):
        resultObj = allEdges(request.POST)
        if resultObj.is_valid():
            parentRole = request.POST.get('parentRoleChoices', "")
            childRole = request.POST.get('childRoleChoices', "")

            graph = DAG()
            graph.del_edge(parentRole, childRole)
            return HttpResponseRedirect(reverse_lazy('get_graph')) 
