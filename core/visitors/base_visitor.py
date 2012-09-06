'''
base_visitor.py

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

class BaseVisitor(object):
    
    def __init__(self, main_visitor_method):
        '''
        @param main_visitor_method: The method in sca_core that visits all the nodes,
                                    in some cases we need to call it in order to have
                                    recursive calls.
        '''
        self._main_visitor_method = main_visitor_method
    
    def should_visit(self, nodety, node, state):
        '''
        @return: True when this visitor should parse @node
        '''
        raise NotImplementedError
    
    def visit(self, node, state):
        '''
        Each visitor needs to implement this method in order to process/visit
        one AST node with the current state (state.py) object.
        
        @return: A tuple that contains:
                     (newobj that was created (if any),
                      True if the main _visitor() method should stop) 
        '''
        raise NotImplementedError
    
    def locate_scope(self, node, state):
        '''
        Utility function that retrieves the scope for a node.
        '''
        while True:
            currscope = state.scopes[-1]
            if node.__class__.__name__ == 'GlobalParentNodeType' or \
                self._compare_nodes(currscope._ast_node, node):
                return currscope
            state.scopes.pop()

    def _compare_nodes(self, ast_node, node):       
        while getattr(node, '_parent_node', None):
            node = node._parent_node
            if ast_node == node:
                return True            
