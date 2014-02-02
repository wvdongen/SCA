'''
assignment_visitor.py

Copyright 2012 Andres Riancho

This file is part of w3af, w3af.sourceforge.net .

w3af is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation version 2 of the License.

w3af is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with w3af; if not, write to the Free Software
Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
'''
import phply.phpast as phpast

from core.visitors.base_visitor import BaseVisitor
from core.nodes.variable_def import VariableDef

class AssignmentVisitor(BaseVisitor):
    '''
    Create the VariableDef

    $ok = $_GET['a'];
    node:      Assignment(Variable('$ok'), ArrayOffset(Variable('$_GET'), 'a'), False)
    node.node: Variable('$ok')
    node.expr: ArrayOffset(Variable('$_GET'), 'a')
    
    $this->prop = 'property' (in method)
    node: Assignment(ObjectProperty(Variable('$this'), 'prop'), 'property', False)
    node.node: ObjectProperty(Variable('$this'), 'prop')
    node.expr: Variable('$prop')
    
    private $prop = 'property'
    node: ClassVariables(['private'], [ClassVariable('$prop', 'property')])
    
    $bla = $this->bla;
    node: Assignment(Variable('$bla'), ObjectProperty(Variable('$this'), 'bla'), False)
    node.node = Variable('$bla');
    
    $result = mysql_query("SELECT * FROM books WHERE Author = '$q'");
    Assignment(Variable('$result'), FunctionCall('mysql_query', [Parameter(BinaryOp('.', BinaryOp('.', "SELECT * FROM books WHERE Author = '", Variable('$q')), "'"), False)]), False)
    '''

    def __init__(self, main_visitor_method):
        super(AssignmentVisitor, self).__init__(main_visitor_method)
    
    def should_visit(self, nodety, node, state):
        return nodety is phpast.Assignment

    def visit(self, node, state):
        currscope = self.locate_scope(node, state)
        varnode = node.node
        var_name = varnode.name
        
        # Store object properties (vars, class variables) as $this->property
        # otherwise $a->var and $b->var overwrite each other (both stored as $var).
        if type(node.node) is phpast.ObjectProperty:
            var_name = node.node.node.name + '->' + varnode.name

        # Create var
        newobj = VariableDef(var_name, varnode.lineno, currscope, ast_node=node.expr)
        node._obj = newobj
        
        currscope.add_var(newobj)
        
        # New object property? Also add var to parent scope (if not exist)
        if type(node.node) is phpast.ObjectProperty:
            root_scope = currscope.get_root_scope()._parent_scope
            if not root_scope.get_var(var_name): 
                # create object var 
                property = VariableDef(var_name, varnode.lineno, currscope, ast_node=node.expr)
                property.parents = [newobj]
                root_scope.add_var(property)
 
        # Overwrite object property
        if type(node.node) is phpast.ObjectProperty:
            # link this var to object property
            root_scope = currscope.get_root_scope()
            if type(root_scope._ast_node) is phpast.Method:
                # link this var to property
                root_scope._parent_scope.get_var(var_name).parents = [newobj]
         
        # Object creation
        if type(node.expr) is phpast.New and node.expr.name in state.classes:
            # Start ast travel class Node
            class_node = state.classes[node.expr.name]
            class_node._object = True
            class_node._object_var = newobj # pass this var to object
            class_node.accept(self._main_visitor_method)

        return newobj, False

        