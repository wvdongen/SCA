'''
method_visitor.py

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
from core.nodes.method import Method
from core.nodes.variable_def import VariableDef
from core.scope import Scope


class MethodVisitor(BaseVisitor):
    def __init__(self, main_visitor_method):
        super(MethodVisitor, self).__init__(main_visitor_method)
    
    def should_visit(self, nodety, node, state):
        return nodety is phpast.Method

    def visit(self, node, state):
        stoponthis = False
        newobj = None
    
        # Methodes are not traveled untill called, this enables us to call methods from within methods
        method = node._parent_node._object_var._obj_def.get_method(node.name)
        if method:
            # Method object was already created, travel the children           
            state.scopes.append(method._scope)
        else:
            # Create method so we can travel childres nodes when called
            parentscope = self.locate_scope(node, state) 
            # Create new Scope and push it onto the stack
            newscope = Scope(node, parent_scope=parentscope, is_root=True)
            # node seen
            node._seen = True
            # add builtins to scope
            newscope._builtins = dict(
                    ((uv, VariableDef(uv, -1, newscope)) for uv in VariableDef.USER_VARS))            
            # Don't trigger vulnerabilities in this scope untill code is no longer dead
            newscope._dead_code = True
            
            state.scopes.append(newscope)
            
            newobj = Method(node.name, node.lineno, newscope, ast_node=node)
            
            node._scope = newscope
            
            # add this method to object
            node._parent_node._object_var._obj_def.add_method(newobj)
            
            # Stop parsing children nodes
            stoponthis = True

        return newobj, stoponthis

        