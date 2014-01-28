'''
method_call_visitor.py

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
from core.nodes.function_call import FuncCall


class FunctionCallVisitor(BaseVisitor):
    '''
    Custom function call
    '''

    def __init__(self, main_visitor_method):
        super(FunctionCallVisitor, self).__init__(main_visitor_method)
    
    def should_visit(self, nodety, node, state):
        return nodety is phpast.FunctionCall and node.name in state.functions_declarations

    def visit(self, node, state):
        # Link functionCall to custom function
        functionObj = state.functions_declarations[node.name]
        node._function = functionObj
        
        # Create funccall (parses the params of funccall)
        name = getattr(node, 'name', node.__class__.__name__.lower())
        newobj = FuncCall(name, node.lineno, node, self.locate_scope(node, state))

        # Set function scope as active code
        functionObj._scope._dead_code = False
        
        # Evaluate if vulnerable (this state will be overridden upon new function call)
        for funccall in functionObj._scope.get_functions():
            vulntype = funccall.is_vulnerable_for()
            if vulntype:
                funccall.add_vulntrace(vulntype)
        
        return newobj, True
