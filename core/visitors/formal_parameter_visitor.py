'''
formal_parameter_visitor.py

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


class FormalParameterVisitor(BaseVisitor):
    
    def __init__(self, main_visitor_method):
        super(FormalParameterVisitor, self).__init__(main_visitor_method)
    
    def should_visit(self, nodety, node, state):
        return nodety is phpast.FormalParameter

    def visit(self, node, state):
        currscope = self.locate_scope(node, state)
        newobj = VariableDef(node.name, node.lineno, currscope, ast_node = node)
        currscope.add_var(newobj)
        
        # If method add
        if type(node._parent_node) is phpast.Method:
            method_name = node._parent_node.name
            object_var = node._parent_node._parent_node._object_var
            object_var._obj_def.get_method(method_name).add_formal_param(newobj)
        # Function
        elif type(node._parent_node) is phpast.Function:
            function_name = node._parent_node.name
            state.functions_declarations[function_name].add_formal_param(newobj)
        
        return None, False