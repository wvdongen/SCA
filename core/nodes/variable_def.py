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
        self._parents = []
        # AST Variable nodes
        self.var_nodes = []
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
            if not self.parents:
                self._is_root = True
            else:
                self._is_root = False
         
        return self._is_root
     
    @is_root.setter
    def is_root(self, is_root):
        self._is_root = is_root

    @property
    def parents(self):
        '''
        Get this var's parent variable
        '''
        if self._is_root:
            return None
        
        if not self._parents:
            self.var_nodes = varnodes = self._get_ancestor_vars(self._ast_node)
            if varnodes:
                for varnode in varnodes:
                    if getattr(varnode,'_parent_node', None) \
                    and type(varnode._parent_node) is phpast.ObjectProperty \
                    and varnode.name == '$this':
                        name = varnode.name + '->' + varnode._parent_node.name
                        parent_var = self._scope.get_root_scope()._parent_scope.get_var(name)
                        if self != parent_var:
                            self._parents.append(self._scope.get_root_scope()._parent_scope.get_var(name))
                            
                    # All other vars
                    # We should not set ourself as parent
                    parent_var = self._scope.get_var(varnode.name)
                    if self != parent_var:
                        self._parents.append(parent_var)
        return self._parents
    
    @parents.setter
    def parents(self, parents):
        self._parents = parents
         
    def add_parent(self, parent):
        self._parents.append(parent)
    
    @property
    def controlled_by_user(self):
        '''
        Returns bool that indicates if this variable is tainted.
        '''
                
        #cbusr = self._controlled_by_user
        #cbusr = None # no cache
        #if cbusr is None:
        cbusr = False #todo look at this
        if self.is_root:
            if self._name in VariableDef.USER_VARS:
                cbusr = True
            else:
                cbusr = False
        else:
            # Look at parents
            for parent in self.parents:
                # todo look at this hasattr
                if hasattr(parent, 'controlled_by_user') and parent.controlled_by_user == True:
                    cbusr = True
        
        #self._controlled_by_user = cbusr
        
        return cbusr
    
    @property
    def taint_source(self):
        '''
        Return the taint source for this Variable Definition if any; otherwise
        return None.
        
        $a = $_GET['test'];
        $b = $a . $_GET['ok'];
        print $b;
        
        $b taint source is ['test', 'ok']
        '''
        taintsrc = self._taint_source
        if taintsrc:
            return taintsrc
        else:
            deps = list(itertools.chain((self,), self.deps()))
            
            vars = []
            for item in reversed(deps):
                if not item.is_root:
                    for node in item.var_nodes:
                        vars.append(node)
            
            sources = []
            for v in vars:
                if hasattr(v, '_parent_node') and type(v._parent_node) is phpast.ArrayOffset:
                    sources.append(v._parent_node.expr)
            return sources
    
    # todo remove below when finished
    @property
    def taint_source_old(self):
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
        if vulnty in self._safe_for:
            return False
        
        if self.parents:
            for parent in self.parents:
                if parent.is_tainted_for(vulnty) == False:
                    return False
        
        return True

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
        seen = set()
        parents = self.parents
        while parents:
            for parent in parents:
                if parent not in seen:
                    yield parent
                    seen.add(parent)
                parents = parent.parents
    
    def _get_ancestor_vars(self, node, vars = None, level=0):
        '''
        Return the ancestor Variables for this var.
        For next example php code:
            <? $a = 'ls' . $_GET['bar'] . $_POST['foo'];
               $b = somefunc($a);
            ?>
        we got that $_GET and $_POST are both $a's ancestor as well as $a is for $b.
        
        Also determines if this var is safe for vulns
        '''
        if vars is None:
            vars = []
        
        for n in NodeRep.parse(node):
            if type(node) is phpast.BinaryOp:
                # only parse direct nodes
                for item in NodeRep.parse(node, 0, 0, 1): 
                    self._get_ancestor_vars(item, vars, level + 1)
                break
            
            if type(n) is phpast.Variable:
                vars.append(n)

        if level == 0:
            safe_for = {}
            for n in vars:
                # todo look at all vars
                nodetys = [phpast.FunctionCall]
                for fc in self._get_parent_nodes(n, nodetys=nodetys):
                    vulnty = get_vulnty_for_sec(fc.name)
                    if vulnty:
                        if vulnty not in safe_for:
                            safe_for[vulnty] = 1
                        else:
                            safe_for[vulnty] = safe_for[vulnty] + 1
            
            for vulnty, count in safe_for.iteritems():
                if count == len(vars):
                    self._safe_for.append(vulnty)
                   
        return vars
    
    def set_clean(self):
        self._controlled_by_user = None
        self._taint_source = None
        self._is_root = True
        
    def get_file_name(self):
        return self._scope.file_name