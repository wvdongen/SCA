'''
scope.py

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
import re

import phply.phpast as phpast


class Scope(object):
    
    def __init__(self, ast_node, parent_scope=None, builtins={}, is_root=False):
        '''
        @param ast_node: AST node that originated this scope
        @param parent_scope: Parent scope
        @param builtins: Language's builtin variables
        '''
        # AST node that defines this scope 
        self._ast_node = ast_node
        self._parent_scope = parent_scope
        self._builtins = builtins
        self._vars = {}
        self._is_root = is_root
        self._dead_code = False
        self._functions = []
        self._method_calls = []
        self._file_name = None
    
    def add_method_call(self, method):
        if method is None:
            raise ValueError, "Invalid value for parameter 'Method': None"
        self._method_calls.append(method)
    
    def get_method_calls(self):
        return self._method_calls
    
    def add_function(self, function):
        if function is None:
            raise ValueError, "Invalid value for parameter 'function': None"
        self._functions.append(function)
        
    def get_functions(self):
        return self._functions
    
    def get_root_scope(self):
        while self._is_root == False:
            self = self._parent_scope
        return self
        
    def add_var(self, newvar):

        if newvar is None:
            raise ValueError, "Invalid value for parameter 'var': None"
        
        # No need to store anon vars
        if newvar._anon_var is True:
            return        
        
        selfvars = self._vars
        newvarname = newvar.name
        varobj = selfvars.get(newvarname)
        if not varobj or newvar > varobj:
            selfvars[newvarname] = newvar
            
            # don't add var to parent if scope is function or method
            if self._is_root:
                return
            
            # Now let the parent scope do his thing        
            if self._parent_scope:
                self._parent_scope.add_var(newvar)
    
    def get_var_like(self, varname):
        '''
        return vars matching a regular expression
        useful to get param vars
        '''
        varname = varname.replace('$', '\$')
        matches = []
        for v in self._vars:
            if re.search(r'%s'%varname, v):
                matches.append(self._vars[v])
        return matches
    
    def get_var(self, varname, requestvar = None):
        var = self._vars.get(varname, None) or self._builtins.get(varname)
        
        # Request var is used to avoid var setting itself as parent
        if requestvar and requestvar is var:
            var = None
        
        # Don't look in parent node for var
        if self._is_root and type(self._ast_node) is not phpast.Method:
            return var
        
        # look in parent parent scope
        if not var and self._parent_scope:
            var = self._parent_scope.get_var(varname, requestvar)
        
        return var
    
    @property
    def file_name(self):
        if self._file_name:
            return self._file_name
        
        node = self._ast_node
        while getattr(node, '_parent_node', None):
            #if isinstance(node, phply.phpast.GlobalParentNodeType) == False:
            node = node._parent_node
        
        self._file_name = node.name
        return self._file_name    

    def get_all_vars(self):
        return self._vars.values()
    
    def get_state(self):
        scope = self
        while scope._parent_scope:
            scope = scope._parent_scope
        return scope.state
    
    def __repr__(self):
        return "<Scope [%s]>" % ', '.join(v.name for v in self.get_all_vars())
