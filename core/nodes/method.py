'''
method.py

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
from core.nodes.node_rep import NodeRep


class Method(NodeRep):
    def __init__(self, name, lineno, scope, ast_node=None):
        NodeRep.__init__(self, name, lineno, ast_node=ast_node)
        
        self._scope = scope
        self._formal_params = []
        self._parsed = False
        self._method_call = []

    def add_formal_param(self, var):
        self._formal_params.append(var)

    def get_formal_param(self, index):
        return self._formal_params[index]
    
    def get_formal_params(self):
        return self._formal_params
    
    def add_method_calls(self, method):
        self._method_calls.append(method)
    
    def clean_formal_params(self):
        for param_var in self._formal_params:
            param_var.set_clean()