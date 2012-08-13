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


class MethodCallVisitor(BaseVisitor):
    '''
    node: MethodCall(Variable('$obj'), 'body', [Parameter(Variable('$hoi'), False)])
    node.node: Variable('$obj')
    '''

    def __init__(self, main_visitor_method):
        super(MethodCallVisitor, self).__init__(main_visitor_method)
    
    def should_visit(self, nodety, node, state):
        return nodety is phpast.MethodCall

    def visit(self, node, state):
        currscope = self.locate_scope(node, state)
        method_name = getattr(node, 'name', node.__class__.__name__.lower())
                    
        # Get object
        if node.node.name == '$this':
            object = currscope.get_root_scope()._parent_scope.obj
        else:    
            object = state.objects[node.node.name]._obj_def
        
        method = object.get_method(method_name)
        
        # clean formal parms to avoid false positives
        method.clean_formal_params()
        
        # keep track of the methos being traveled
        state.methods_deep.append(method)
        
        # Start ast travel method Node
        if method._parsed is False:
            method._parsed = True
            method._ast_node.accept(self._main_visitor_method)

        # Create funccall (parses the params)            
        newobj = FuncCall(method_name, node.lineno, node, currscope)
        
        # Add method object to call for easy reference
        newobj._method = method
        
        # Keep track of what methods are called within this method
        currscope.get_root_scope().add_method_call(newobj)
                    
        # Set method scope as active code
        method_scope = object.get_method(method_name)._scope
        method_scope._dead_code = False
        
        # Evaluate all raised methodcalls when all methods have been traveld
        if state.methods_deep[0] is method:
            
            # 1.We need to link all params and formal params together
            # all traveled methods
            for method0 in state.methods_deep:
                # All method calls in method
                for method_call1 in method0._scope.get_method_calls():
                    # Link
                    for par_index, param in enumerate(method_call1.params):
                        formal_param = method_call1._method.get_formal_param(par_index)
                        formal_param._controlled_by_user = None
                        formal_param.is_root = False
                        formal_param.parent = param.var
                                           
            # 2.Determine vulnerabilities
            for method0 in state.methods_deep:
                for method_call1 in method0._scope.get_method_calls():
                    method_scope = method_call1._method._scope
                    for funccall in method_scope.get_functions():
                        vulntype = funccall.is_vulnerable_for()
                        if vulntype: 
                            funccall.add_vulntrace(vulntype)
                    # clean formal params to avoid false positives
                    method_call1._method.clean_formal_params()
                    
            # 3.Determine vulnerabilities for current method
            for funccall in method._scope.get_functions():
                vulntype = funccall.is_vulnerable_for()
                if vulntype: 
                    funccall.add_vulntrace(vulntype)
            
            # reset method call stack
            state.methods_deep = []
            
        return newobj, True

        