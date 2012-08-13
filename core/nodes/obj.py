'''
obj.py

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


class Obj(NodeRep):
    
    def __init__(self, name, lineno, scope, object_var, ast_node=None):
        
        NodeRep.__init__(self, name, lineno, ast_node=ast_node)
        
        self._scope = scope
        self._object_var = object_var
        self._methods = {}
        self._scope.obj = self
        
    def add_method(self, method):
        self._methods[method.name] = method
    
    def get_method(self, name):
        return self._methods.get(name, None)
    
    def get_methods(self):
        return self._methods    

    def __repr__(self):
        return "<Class definition '%s' at line %s>" % (self.name, self.lineno)
    
    def __str__(self):
        return "Line %s. declaration of Class '%s'" % (self.lineno, self.name)