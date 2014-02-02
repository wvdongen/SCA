'''
parameter.py

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

from core.nodes.node_rep import NodeRep
from core.nodes.variable_def import VariableDef
from core.vulnerabilities.definitions import get_vulnty_for_sec, SENSITIVE_FUNCTIONS

class Param(object):
    
    def __init__(self, node, scope, parent_obj):
        self._parent_obj = parent_obj
        self.vars = []
        self._parse_me(node, scope)
    
    def get_index(self):
        param_index = min(i for i in range(len(self._parent_obj._params)) if self == self._parent_obj._params[i])
        return param_index
    
    def get_root_obj(self):
        while getattr(self, '_parent_obj', None):
            self = self._parent_obj
        return self
            
    
    def _parse_me(self, node, scope):
        '''
        TODO: add method call
        
        Traverse this AST subtree until either a Variable or FunctionCall node
        is found...
        '''
        for node in NodeRep.parse(node):
            
            if type(node) is phpast.BinaryOp:
                # only parse direct nodes
                for item in NodeRep.parse(node, 0, 0, 1): 
                    self._parse_me(item, scope)
                break
            
            if type(node) is phpast.Variable:
                # object properties are stored as $this->property
                varname = node.name
                if type(node._parent_node) is phpast.ObjectProperty:
                    varname = node._parent_node.node.name + '->' + node._parent_node.name 
                 
                vardef = VariableDef(varname + '__$temp_anon_var$_', node.lineno, scope)
                vardef.var_nodes = [node]
                # anon var is not stored in scope
                vardef._anon_var = True
                # get and set parent
                scopevar = scope.get_var(varname)
                vardef.add_parent(scopevar)
                # add Param to VarDef
                # TODO: not really necessary?
                vardef._parent_obj = self
                # add var to current scope
                scope.add_var(vardef)
                self.vars.append(vardef)
                break
            
            elif type(node) is phpast.FunctionCall:
                
                # TEST call functioncal visitor
                from core.visitors.base_visitor import BaseVisitor
                from core.visitors.function_call_visitor import FunctionCallVisitor
                
                visitor = FunctionCallVisitor(BaseVisitor);
                fc, stoponthis = visitor.visit(node, scope.get_state())
                
                vardef = VariableDef(node.name + '_funvar', node.lineno, scope)
                
#                 from core.nodes.function_call import FuncCall
#                 from core.nodes.function_call import FuncCall
#                 fc = FuncCall(node.name, node.lineno, node, scope, self)
                
                #TODO: Can we do this in a more extensible way? Why different ways for handling FILE_DISC / XSS?
                # Add vulntrace
                vulntype = fc.is_vulnerable_for()
                if vulntype and 'FILE_DISCLOSURE' in vulntype and \
                self._parent_obj.name in SENSITIVE_FUNCTIONS['XSS']: 
                    # Add vulntrace to parent call with pending trace
                    fc.add_vulntrace(vulntype)
                    self._parent_obj._pending_trace = fc.get_vulntraces()[-1]
                    vardef._safe_for.append('XSS')
                    vardef.set_clean()
                 
#                 elif vulntype:
#                     fc.add_vulntrace(vulntype)
#                     # Keep track of thin funccal
#                     self.get_root_obj()._functions.append(fc)
#                     vardef.set_clean()
                
                # return values (custom function)?
                called_obj = fc.get_called_obj();
                if called_obj:
                    # Set function scope as active code
                    called_obj._scope._dead_code = False
                    for var in called_obj._return_vars:
                        vardef.add_parent(var)
#                  
                else:
                    for param in fc.params:
                        for var in param.vars:
                            vardef.add_parent(var)
                   
                # Securing function?
                vulnty = get_vulnty_for_sec(fc.name)
                if vulnty:
                    vardef._safe_for.append(vulnty)
                
                self.vars.append(vardef)
                break
        