from DynaSwapApp.models import Roles, RoleEdges, Users, UsersRoles
import os
import hashlib
from hashlib import md5
from acp import ACP
from atallah import hash_fun, encrypt, decrypt


"""
Notes about notation:
public:
    l_i: node label
    y_ij: edge label
private:
    s_i: random secret value
    t_i: derive key
    k_i: decrypt key
    r_ij: edge seed
"""


class Node:
    def __init__(self, name, l_i, s_i):
        """
        Constructor for node. Will use urandom and md5 hash to generate node
        label (l_i) and secret value (s_i). Each node contains a list of all
        the edges to it's child nodes.
        Args:
            name (string): name to identify node
            l_i (string): public label
            s_i (string): secrect
        Returns:
            N/A
        """
        self.name = name
        self.l_i = l_i
        self.__s_i = s_i
        self.acp = ACP(name, self.__s_i)
        self.edges = {}

    def update_secret(self):
        """
        Update the value of the secret key of the node
        Args:
            N/A
        Returns:
            N/A
        """
        self.__s_i = md5(os.urandom(16)).hexdigest()
        self.acp = ACP(self.name, self.__s_i)
        Roles.objects.get(role=self.name).update(role_key=self.__s_i)

    def update_label(self):
        """
        Changes the label of a node to a new random value
        Args:
            N/A
        Returns:
            N/A
        """
        self.l_i = hashlib.md5(os.urandom(16)).hexdigest()
        Roles.objects.get(role=self.name).update(uuid=self.l_i)

    def get_t_i(self):
        """
        Return the value of the derive key (t_i).
        Args:
            N/A
        Returns:
            hex digest (string): hash of s_i + "0" + l_i
        """
        return hash_fun(self.__s_i, self.l_i, val_opt="0")

    def get_k_i(self):
        """
        Return the value of the decrypt key (k_i).
        Args:
            N/A
        Returns:
            hex digest (string): hash of s_i + "1" + l_i
        """
        return hash_fun(self.__s_i, self.l_i, val_opt="1")


class Edge:
    def __init__(self, t_i, l_j, t_j, k_j):
        """
        Constructor for edge. Given the parent derive key, child label, child
        derive key and child decrypt key the edge will calculate the edge seed
        and the edge label.
        Args:
            t_i (string): hex string of parent derive key
            l_j (string): hex string of child label
            t_j (string): hex string of child dervive key
            k_j (string): hex string of child decrypt key
        Returns:
            N/A
        """
        self.__r_ij = hash_fun(t_i, l_j)
        self.y_ij = encrypt(self.__r_ij, t_j, k_j)

    def update_r_ij(self, t_i, l_j):
        """
        Update the value of the private information (r_ij).
        Args:
            t_i (string): hex string of parent derive key
            l_j (string): hex string of child label
        Returns:
            N/A
        """
        self.__r_ij = hash_fun(t_i, l_j)

    def update_y_ij(self, t_j, k_j):
        """
        Update the value of the public information (y_ij).
        Args:
            t_j (string): hex string of child derive key
            k_j (string): hex string of child decrypt key
        Returns:
            N/A
        """
        self.y_ij = encrypt(self.__r_ij, t_j, k_j)


class DAG:
    def __init__(self):
        """
        Constructor for DAG.
        Args:
            N/A
        Returns:
            N/A
        """
        self.node_list = {}
        for roles in Roles.objects.all():
            self.node_list[roles.role] = Node(roles.role, roles.uuid, roles.role_key)
        for edges in RoleEdges.objects.all():
            paren = self.node_list[edges.parent_role.role]
            child = self.node_list[edges.child_role.role]
            self.node_list[paren.role].edges[child.role] = Edge(paren.get_t_i(), child.l_i, child.get_t_i(), child.get_k_i())

    def add_node(self, name, desc):
        """
        Adds a new Node object to the node_list dictionary on the DAG and the 'Roles' table in the database.
        Args:
            name (string): key to be used for node in node_list
            desc (string): description of the role
        Returns:
            N/A
        """
        if name not in self.node_list.keys():
            new_node = Node(name, desc)
            self.node_list[name] = new_node
        Roles(role=name, description=desc, uuid=new_node.l_i, role_key=new_node.__s_i).save()

    def add_edge(self, paren_node, child_node):
        """
        Given a the name of a parent and child node, a new edge will be created
        between them.
        Args:
            paren_node (string): name identifying parent node
            child_node (string): name identifying child node
        Returns:
            N/A
        """
        if(paren_node == child_node):
            return False

        paren = self.node_list[paren_node]
        child = self.node_list[child_node]

        if child_node in paren.edges:
            return False

        paren_obj = Roles.objects.get(role=paren_node)
        child_obj = Roles.objects.get(role=child_node)

        new_edge = Edge(
            paren.get_t_i(), child.l_i, child.get_t_i(), child.get_k_i())
        self.node_list[paren_node].edges[child_node] = new_edge

        if not self.is_cyclic():
            RoleEdges(parent_role=paren_obj, child_role=child_obj).save()
        else:
            self.node_list[paren_node].edges.pop(child_node)
            return False

    def have_path(self, src_node, des_node):
        """
        Checks to see if there is a path between two nodes.
        Args:
            src_node (string): name to identify starting node
            des_node (string): name to identify target destination node
        Returns:
            boolean: True or False depending on if there is a valid path
        """
        visited = set()
        queue = []

        # visit the first node and place on queue
        visited.add(src_node)
        queue.append(src_node)

        while queue:
            # grab node from front of queue
            popped_node = queue.pop(0)

            if popped_node == des_node:
                return True

            for adj_node in self.node_list[popped_node].edges:
                if adj_node not in visited:
                    queue.append(adj_node)
                    visited.add(adj_node)

    def descendant(self, v_i):
        """
        Find all v_j s.t. there is a path from v_i to v_j.
        Args:
            v_i (Node): Node to find descendants of.
            graph (np.ndarray): Adjacency matrix of DAG.
        Returns:
            v_j (list): List of descendant nodes of v_i.
        """

        desc = []
        for node in self.node_list.keys():
            if (node not in desc) and (self.have_path(v_i, node)):
                desc.append(node)
        return desc

    def predecessor(self, v_i):
        """
        Find all v_j s.t. there is a directed edge connecting v_j to v_i.
        Args:
            v_i (Node): Node to find predecessors of.
            graph (np.ndarray): Adjacency matrix of DAG.
        Returns:
            v_j (list): List of predecessor nodes of v_i.
        """

        pred = []
        for node in self.node_list.keys():
            if (node not in pred) and (v_i in self.node_list[node].edges):
                pred.append(node)
        return pred

    def is_cyclic_util(self, node, visited, rec_stack):
        """
        Method to help is_cyclic determine if a graph is cyclic.
        Args:
            node (string): key to identify a node in the graph
            visited (dictionary): keeps track of previously visited nodes
            rec_stack (dictionary): used for recursion
        Returns:
            boolean: True if graph is cyclic
        """
        # Mark current node as visited and adds to recursion stack
        visited[node] = True
        rec_stack[node] = True

        # Recur for all neighbours. If any neighbour is visited
        # and in recStack then graph is cyclic
        for children in self.node_list[node].edges.keys():
            if visited[children] is False:
                if self.is_cyclic_util(children, visited, rec_stack):
                    return True
            elif rec_stack[children]:
                return True

        # The node needs to be poped from
        # recursion stack before function ends
        rec_stack[node] = False
        return False

    def is_cyclic(self):
        """
        Returns True if graph is cyclic else False
        Args:
            N/A
        Returns:
            boolean: True if graph is cyclic
        """
        visited = dict()
        recStack = dict()
        for node in self.node_list.keys():
            visited[node] = False
        rec_stack = visited.copy()
        for node in self.node_list.keys():
            if visited[node] is False:
                if self.is_cyclic_util(node, visited, rec_stack):
                    return True
        return False

    def del_edge(self, parent_node, child_node):
        """
            Given two nodes this method will remove the edge between them.
            First generates a new label (ID) for the parent and recomputes
            new k. Then the label is updated for all descendants of the
            parent role. Then for all the roles involved find the predecessors
            and update their edge keys.
        Args:
            parent_node (string): key to identify parent node in graph
            child_node (string): key to idenfity child node in graph
        Returns:
            N/A
        """
        for node in self.descendant(child_node):
            self.node_list[node].update_label()

        for node in self.descendant(child_node):
            for pred in self.predecessor(node):
                self.node_list[pred].edges[node].update_r_ij(
                    self.node_list[pred].get_t_i(), self.node_list[node].l_i)
                self.node_list[pred].edges[node].update_y_ij(
                    self.node_list[node].get_t_i(),
                    self.node_list[node].get_k_i())
                paren = Roles.objects.get(role=pred)
                    child = Roles.objects.get(role=node)
                    #RoleEdges.objects.filter(parent_role=paren, child_role=child).update(edge_key=)

        self.node_list[parent_node].edges.pop(child_node)
        paren = Roles.objects.get(role=parent_node)
        child = Roles.objects.get(role=child_node)
        RoleEdges.objects.filter(parent_role=paren, child_role=child).delete()

    def del_role(self, node):
        """
        Deletes a node and it's edges from the graph.
        Args:
            node (string): key to identify node in graph
        Returns:
            N/A
        """
        for node_name, node_obj in self.node_list.items():
            if node_name == node:
                # del all children edges
                for children in list(node_obj.edges):
                    self.del_edge(node_name, children)
            if node in node_obj.edges:
                # del all parent edges
                self.del_edge(node_name, node)
        self.node_list.pop(node)
        Roles.objects.filter(role=node).delete()

    def update_node_secret(self, node):
        """
        Update the secret key for a node and then compute the new private key.
        Also update edge keys to reflect this change.
        Args:
            node (string): key to identify node in graph
        Returns:
            N/A
        """
        self.node_list[node].update_secret()

        for pred in self.predecessor(node):
            self.node_list[pred].edges[node].update_r_ij(
                self.node_list[pred].get_t_i(), self.node_list[node].l_i)
            self.node_list[pred].edges[node].update_y_ij(
                self.node_list[node].get_t_i(), self.node_list[node].get_k_i())
            paren = Roles.objects.get(role=pred)
            child = Roles.objects.get(role=node)
            #RoleEdges.objects.filter(parent_role=paren, child_role=child).update(edge_key=)

        # for edges from this role, change edge keys
        for children in self.node_list[node].edges.keys():
            self.node_list[node].edges[children].update_r_ij(
                self.node_list[node].get_k_i(), self.node_list[children].l_i)
            self.node_list[node].edges[children].update_y_ij(
                self.node_list[children].get_t_i(),
                self.node_list[children].get_k_i())
            paren = Roles.objects.get(role=node)
            child = Roles.objects.get(role=children)
            #RoleEdges.objects.filter(parent_role=parent, child_role=child).update(edge_key=)
        
        #ACP operation here


    def remove_node_user(self, node, username):
        """
        Remove the user from the given node.
        Args:
            node (string): key to identify node in graph
            username (string): key to identify user in graph
        Returns:
            N/A
        """
        user_obj = Users.objects.get(username=user)
        role_obj = Roles.objects.get(role=node)
        
        relat = UsersRoles.objects.filter(user_id=user_obj, role=role_obj)

        if len(relat) > 0:
            UsersRoles.objects.filter(user_id=user_obj, role=role_obj).delete()
            self.node_list[node].update_secret()

    def add_node_user(self, node, user):
        """
        Add a user to the specific node.
        Args:
            node (string): key to identify node in graph
            user (string): the user name of the user
        Returns:
            N/A
        """
        user_obj = Users.objects.get(username=user)
        role_obj = Roles.objects.get(role=node)
        
        relat = UsersRoles.objects.filter(user_id=user_obj, role=role_obj)

        if len(relat) < 1:
            UsersRoles(user_id=user_obj, role=role_obj).save()
            self.update_node_secret(node)


    def get_path(self, src_node, des_node):
        """
        Get the valid path from source node to the destination node
        Args:
            src_node (string): key to identify the source node in graph
            des_node (string): key to identify the destination node in graph
        Returns:
            list of nodes along the path if found
            empty list if not found
        """
        cur_path = [src_node]
        if self.get_path_helper(src_node, des_node, cur_path):
            return cur_path
        return []

    def get_path_helper(self, src_node, des_node, cur_path):
        if src_node == des_node:
            return True
        for children in self.node_list[src_node].edges.keys():
            cur_path.append(children)
            if self.get_path_helper(children, des_node, cur_path):
                return True
            cur_path.pop()
        return False

    def derive_key(self, path):
        """
        Derive the key of the destination node given the path to it
        Args:
            path (list of string): list of names of node in the path
        Returns:
            key of the node in hex string
        """
        src_node = path[0]
        t_j = self.node_list[src_node].get_t_i()
        k_j = self.node_list[src_node].get_k_i()
        for i in range(1, len(path)):
            child = path[i]
            t_j, k_j = decrypt(hash_fun(t_j, self.node_list[child].l_i), self.node_list[src_node].edges[child].y_ij)
            src_node = child
        return k_j
         
    def derive_desc_key(self, src_node, t_i):
        """
        Derive all the keys of the descendants of the source node
        Args:
            src_node (string): key to identify the source node in graph
            t_i (string): private key the node, can also be derived here if needed
        Returns:
            list of nodes along the path
        """
        key_list = []
        key_list.append(self.node_list[src_node].get_k_i())
        key_list += self.derive_desc_key_helper(src_node, t_i)
        return list(set(key_list))


    def derive_desc_key_helper(self, src_node, t_i):
        key_list = []
        for children in self.node_list[src_node].edges.keys():
            t_j, k_j = decrypt(hash_fun(t_i, self.node_list[children].l_i), self.node_list[src_node].edges[children].y_ij)
            key_list.append(k_j)
            key_list += self.derive_desc_key(children, t_j)
        return key_list


    def get_pub(self):
        """
        Get the public information of the graph
        Args:
            N/A
        Returns:
            list of lists of nodes and edges
        """
        nodes = []
        edges = []
        for node, node_obj in self.node_list.items():
            nodes.append([node, node_obj.l_i])
            for edge, edge_obj in self.node_list[node].edges.items():
                edges.append([node, edge, edge_obj.y_ij])
        return [nodes, edges]