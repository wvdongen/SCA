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
#from core.nodes.return_node import Return
from core.nodes.variable_def import VariableDef

class ReturnVisitor(BaseVisitor):

    def __init__(self, main_visitor_method):
        super(ReturnVisitor, self).__init__(main_visitor_method)
    
    def should_visit(self, nodety, node, state):
        return nodety is phpast.Return

    def visit(self, node, state):
        
        currscope = self.locate_scope(node, state)
        
        # Create var
        newobj = VariableDef('return_value', node.lineno, currscope, ast_node=node)
        
        # Attach return vars to function
        root_scope = currscope.get_root_scope()        
        parent_obj = root_scope._ast_node.obj
        parent_obj._return_vars.append(newobj)
        
        return newobj, False

        