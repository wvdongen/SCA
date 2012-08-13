'''
node_rep.py

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
import sys

import phply.phpast as phpast


class NodeRep(object):
    '''
    Abstract Node representation for AST Nodes 
    '''
    
    MAX_LEVEL = sys.getrecursionlimit()
    
    def __init__(self, name, lineno, ast_node=None):
        self._name = name
        self._lineno = lineno
        # AST node that originated this 'NodeRep' representation
        self._ast_node = ast_node

    def _get_parent_nodes(self, startnode, nodetys=[phpast.Node]):
        '''
        Yields parent nodes of type `type`.
        
        @param nodetys: The types of nodes to yield. Default to list 
            containing base type.
        @param startnode: Start node. 
        '''
        parent = getattr(startnode, '_parent_node', None)
        while parent:
            if type(parent) in nodetys:
                yield parent
            parent = getattr(parent, '_parent_node', None)
    
    @staticmethod
    def parse(node, currlevel=0, maxlevel=MAX_LEVEL):
        yield node
        if currlevel <= maxlevel:
            for f in getattr(node, 'fields', []):
                val = getattr(node, f)
                if isinstance(val, phpast.Node):
                    val = [val]
                if type(val) is list:
                    for el in val:
                        el._parent_node = node
                        for ele in NodeRep.parse(el, currlevel+1, maxlevel):
                            yield ele
    
    @property
    def lineno(self):
        return self._lineno
    
    @property
    def name(self):
        return self._name
    
    @property
    def ast_node(self):
        return self._ast_node