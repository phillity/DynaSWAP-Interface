# DynaSWAP-Interface

Documentation for the simple interface.


DynaSwapApp\services\dag.py

    Contains the functions for creation and modification of DAG. 
    
    DAG():
        Constructor of DAG from the nodes and edges in the database. Every time we want do some operations on the DAG, call it first.
        Called in GetGraph() and all other classes in views.py.
        Args:
            N/A
        Returns:
            N/A

    add_node(self, name, desc):
        Adds a new Node object to the node_list dictionary on the DAG and the 'Roles' table in the database.
        Called in AddRoleView class.
        Args:
            name (string): key to be used for node in node_list
            desc (string): description of the role
        Returns:
            N/A (check for success currently not available)
    
    add_edge(self, paren_node, child_node):
        Given a the name of a parent and child node, a new edge will be created between them.
        Called in AddEdgeView class.
        Args:
            paren_node (string): name identifying parent node
            child_node (string): name identifying child node
        Returns:
            N/A (check for success currently not available)

    del_edge(self, parent_node, child_node):
            Given two nodes this method will remove the edge between them.
            Called in DeleteEdgeView class.
        Args:
            parent_node (string): key to identify parent node in graph
            child_node (string): key to idenfity child node in graph
        Returns:
            N/A (check for success currently not available)
    
    del_role(self, node):
        Deletes a node and it's edges from the graph.
        Called in DeleteRoleView class.
        Args:
            node (string): key to identify node in graph
        Returns:
            N/A (check for success currently not available)


DynaSwapApp\views.py

    Contains all the views rendered in Django.

    GetGraph():
        Function calls DAG() and generate the JSON file needed for Sigma.JS to display the graph.
        The structure of JSON is: {'nodes': [{'id': id, 'label': label, 'x': x, 'y': y, 'size': size}],
                                   'edges': [{'id': id, "source": node1, "target": node2}]}
        Here the x, y coordinates is simply generated by the rank of the node in the graph.

    DeleteRoleView:
        Extension of View class in Django, controls the deletion of nodes in the graph.
        The node to be deleted is identified by its name, and is chosen in a form.

    AddRoleView:
        Extension of CreatView class in Django, controls the creation of new nodes.
        Client provides the name and the description of the node to be added.
    
    AddEdgeView:
        Extension of View class in Django, controls the creation of edges in the graph.
        The edge to be created is identified by the names of the nodes chosen in two forms.
        
    DeleteEdgeView
        Extension of View class in Django, controls the deletion of edges in the graph.
        The edge to be deleted is identified by the names of the nodes chosen in two forms.


DynaSwapApp\templates\

    Contains all the HTML files.