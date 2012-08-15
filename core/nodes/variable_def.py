'''
variable_def.py

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
import itertools

import phply.phpast as phpast

from core.nodes.node_rep import NodeRep
from core.vulnerabilities.definitions import get_vulnty_for_sec


class VariableDef(NodeRep):
    '''
    Representation for the AST Variable Definition.
        (...)
    '''
    
    USER_VARS = ('$_GET', '$_POST', '$_COOKIES', '$_REQUEST')
    
    def __init__(self, name, lineno, scope, ast_node=None):
        
        NodeRep.__init__(self, name, lineno, ast_node=ast_node)
        
        # Containing Scope.
        self._scope = scope
        # Parent VariableDef
        self._parent = None
        # AST Variable node
        self.var_node = None
        # Is this var controlled by user?
        self._controlled_by_user = None
        # Vulns this variable is safe for. 
        self._safe_for = []
        # Being 'root' means that this var doesn't depend on any other.
        self._is_root = True if (name in VariableDef.USER_VARS) else None 
        # Request parameter name, source for a possible vuln.
        self._taint_source = None
        # Is object property?
        self._object_property = False
        # Anon var? (param var in functioncall).
        self._anon_var = False
        
    @property
    def is_root(self):
        '''
        A variable is said to be 'root' when it has no ancestor or when
        its ancestor's name is in USER_VARS
        '''
        if self._is_root is None:
            if self.parent:
                self._is_root = False
            else:
                self._is_root = True
        return self._is_root
    
    @is_root.setter
    def is_root(self, is_root):
        self._is_root = is_root

    @property
    def parent(self):
        '''
        Get this var's parent variable
        '''
        if self._is_root:
            return None
        
        if self._parent is None:
            self.var_node = varnode = self._get_ancestor_var(self._ast_node)
            if varnode:
                if getattr(varnode,'_parent_node', None) \
                and type(varnode._parent_node) is phpast.ObjectProperty \
                and varnode.name == '$this':
                    name = varnode.name + '->' + varnode._parent_node.name
                    self._parent = self._scope.get_root_scope()._parent_scope.get_var(name)
                    return self._parent
                # all other vars vars
                self._parent = self._scope.get_var(varnode.name)
        return self._parent

    @parent.setter
    def parent(self, parent):
        self._parent = parent
    
    @property
    def controlled_by_user(self):
        '''
        Returns bool that indicates if this variable is tainted.
        '''
        #cbusr = self._controlled_by_user
        cbusr = None # no cache
        if cbusr is None:
            if self.is_root:
                if self._name in VariableDef.USER_VARS:
                    cbusr = True
                else:
                    cbusr = False
            else:
                cbusr = self.parent.controlled_by_user
            
            self._controlled_by_user = cbusr

        return cbusr
    
    @property
    def taint_source(self):
        '''
        Return the taint source for this Variable Definition if any; otherwise
        return None.
        '''
        taintsrc = self._taint_source
        if taintsrc:
            return taintsrc
        else:
            deps = list(itertools.chain((self,), self.deps()))
            v = deps[-2].var_node if len(deps) > 1 else None
            if v and type(v._parent_node) is phpast.ArrayOffset:
                return v._parent_node.expr
            return None
    
    def __eq__(self, ovar):
        return self._scope == ovar._scope and \
                self._lineno == ovar.lineno and \
                self._name == ovar.name
    
    def __gt__(self, ovar):
        # This basically indicates precedence. Use it to know if a
        # variable should override another.
        return self._scope == ovar._scope and self._name == ovar.name and \
                self._lineno > ovar.lineno or self.controlled_by_user
    
    def __hash__(self):
        return hash(self._name)
    
    def __repr__(self):
        return "<Var %s definition at line %s in '%s'>" % (self.name, self.lineno, self.get_file_name())
    
    def __str__(self):
        return ("Line %(lineno)s in '%(file_name)s'. Declaration of variable '%(name)s'."
            " Status: %(status)s") % \
            {'name': self.name,
             'file_name': self.get_file_name(),
             'lineno': self.lineno,
             'status': self.controlled_by_user and \
                        ("'Tainted'. Source: '%s'" % self.taint_source) or \
                        "'Clean'"
            }
    
    def is_tainted_for(self, vulnty):
        return vulnty not in self._safe_for and \
                (self.parent.is_tainted_for(vulnty) if self.parent else True)

    def get_root_var(self):
        '''
        Return root var of var:
        
        $a = 'bla';
        $b = $a;
        $c = $b;
        
        $a is the root of $c
        '''
        while self.parent:
            self = self.parent
        return self

    def deps(self):
        '''
        Generator function. Yields this var's dependencies.
        '''
        parent = self.parent
        while parent:
            yield parent
            parent = parent.parent

    def _get_ancestor_var(self, node):
        '''
        Return the ancestor Variable for this var.
        For next example php code:
            <? $a = 'ls' . $_GET['bar'];
               $b = somefunc($a);
            ?>
        we got that $_GET is $a's ancestor as well as $a is for $b.
        '''
        for n in NodeRep.parse(node):
            if type(n) is phpast.Variable:
                nodetys = [phpast.FunctionCall]
                for fc in self._get_parent_nodes(n, nodetys=nodetys):
                    vulnty = get_vulnty_for_sec(fc.name)
                    if vulnty:
                        self._safe_for.append(vulnty)
                return n
        return None
    
    def set_clean(self):
        self._controlled_by_user = None
        self._taint_source = None
        self._is_root = True
    
    def get_file_name(self):
        return self._scope.file_name