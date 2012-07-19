'''
sca.py

Copyright 2011 Andres Riancho

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
import sys
import threading
import re

from phply import phplex
from phply.phpparse import parser 
import phply.phpast as phpast


# We prefer our way. Slight modification to original 'accept' method.
# Now we can now know which is the parent of the current node while
# the AST traversal takes place. This will be *super* useful for 
# pushing/popping the scopes from the stack. 
Node = phpast.Node

def accept(nodeinst, visitor):
    skip = visitor(nodeinst)  
    if skip:
        return

    for field in nodeinst.fields:
        value = getattr(nodeinst, field)
        
        if isinstance(value, Node):
            # Add parent
            value._parent_node = nodeinst
            value.accept(visitor)
        
        elif isinstance(value, list):
            for item in value:            
                if isinstance(item, Node):
                    # Set parent
                    item._parent_node = nodeinst
                    item.accept(visitor)

# Finally monkeypatch phpast.Node's accept method.
Node.accept = accept


class CodeSyntaxError(Exception):
    pass


class PhpSCA(object):
    '''
    PHP Static Code Analyzer class. Intended to detect and report code
    vulnerabilities given an php source input.
    '''

    def __init__(self, code=None, file=None):
        
        if not code and not file:
            raise ValueError, ("Invalid arguments. Either parameter 'code' or "
                               "'file' should not be None.")
        if file:
            with open(file, 'r') as f:
                code = f.read()
        
        # Lexer instance
        lexer = phplex.lexer.clone()
        # Code AST
        try:
            self._ast_code = parser.parse(code, lexer=lexer)
        except SyntaxError, se:
            raise CodeSyntaxError, "Error while parsing the code"
        
        # Convenient definition of new node type
        GlobalParentNodeType = phpast.node('GlobalParentNodeType',
                                           ['name', 'children', '_parent_node'])
        ## Instantiate it and self-assign it as root node
        self._global_pnode = GlobalParentNodeType('dummy', self._ast_code, None)
        # Started parsing?
        self._started = False
        ## Parsing lock
        self._parselock = threading.RLock()
        # Define scope
        scope = Scope(self._global_pnode, parent_scope=None, is_root=True)
        scope._builtins = dict(
            ((uv, VariableDef(uv, -1, scope)) for uv in VariableDef.USER_VARS))
        self._scopes = [scope]
        # FuncCall nodes
        self._functions = []
        # FunctionDeclarations
        self._functionsDec = {}
        # For debugging purpose
        self.debugmode = False
    
    def _start(self):
        '''
        Start AST traversal
        '''
        with self._parselock:
            if not self._started:
                self._started = True
                global_pnode = self._global_pnode
                
                # Set parent
                for node in self._ast_code:
                    node._parent_node = global_pnode
                
                # Start AST traversal!
                global_pnode.accept(self._visitor)
    
    def get_vulns(self):
        '''
        Return a dict that maps vuln. types to FuncCall objects.
        
        Output example:
            {'XSS': [<'system' call at line 2>, <'echo' call at line 4>],
             'OS_COMMANDING': [<'system' call at line 6>]}
        '''
        self._start()
        resdict = {}
        for f in self.get_func_calls(vuln=True):
            for vulnty in f.vulntypes:
                flist = resdict.setdefault(vulnty, [])
                flist.append(f)
        return resdict
    
    def get_vars(self, usr_controlled=False):
        self._start()
        filter_tainted = (lambda v: v.controlled_by_user) if usr_controlled \
                            else (lambda v: 1)
        all_vars = filter(filter_tainted, self._scopes[0].get_all_vars())
        
        return all_vars
    
    def get_func_calls(self, vuln=False):
        self._start()
        filter_vuln = (lambda f: len(f.vulntypes)) if vuln \
                        else (lambda f: True)
        return filter(filter_vuln, self._functions)
    
    def _visitor(self, node):
        
        '''
        Visitor method for AST traversal. Used as arg for AST nodes' 'accept'
        method (Visitor Design Pattern)
        '''
        def locatescope():
            while True:
                currscope = self._scopes[-1]
                if node.__class__.__name__ == 'GlobalParentNodeType' or \
                    currscope._ast_node == node._parent_node:
                    return currscope
                self._scopes.pop()
        
        nodety = type(node)
        stoponthis = False
        newobj = None
        
        # Create FuncCall nodes. 
        # PHP special functions: echo, print, include, require
        if nodety in (phpast.FunctionCall, phpast.Echo, phpast.Print,
                      phpast.Include, phpast.Require):
            name = getattr(node, 'name', node.__class__.__name__.lower())
            newobj = FuncCall(name, node.lineno, node, locatescope())
            
            # FunctionCalls
            if nodety is phpast.FunctionCall and node.name in self._functionsDec:
                    
                functionNode = self._functionsDec[node.name]
                scope = functionNode._scope

                if scope._dead_code is True:
                    
                    # Put params in temp list to easily get index
                    temp_params = [param.name for param in functionNode.params]
                    
                    search = '|'.join(temp_params).replace('$', '\$')
                    
                    # Loop through all vars used as parameter in this scope
                    for var in scope.get_var_like('__$temp_anon_var$_'):   
                        root_var = var.get_root_var()
                        # directe call with param var or var with param as root 
                        if re.search(r"(%s)__\$temp_anon_var\$_.*"%search, root_var.name) or root_var._formal_parameter ==  True:
                            tainted_call =  var._parent_obj._parent_obj._ast_node
                            tainted_call_name = getattr(tainted_call, 'name', tainted_call.__class__.__name__.lower())
                            # Loop through PVFDB, check if functioncall is present
                            for vul, pvf in FuncCall.PVFDB.items():
                                for pvfname, info in pvf.items():
                                    if pvfname == tainted_call_name:
                                        # Add this function to PVFDB
                                        # Store vulnerable param index 
                                        param_index = temp_params.index(root_var.name)
                                        if functionNode.name not in FuncCall.PVFDB[vul]: 
                                            FuncCall.PVFDB[vul][functionNode.name] = [param_index]
                                        else:
                                            FuncCall.PVFDB[vul][functionNode.name].append(param_index)
                    
                    # This is no longer dead code, no further lookups necessary  
                    scope._dead_code = False

            self._functions.append(newobj)
            # Stop parsing children nodes
            stoponthis = True
        
        # Create the VariableDef
        elif nodety is phpast.Assignment:
            '''
            $ok = $_GET['a'];
            node:      Assignment(Variable('$ok'), ArrayOffset(Variable('$_GET'), 'a'), False)
            node.node: Variable('$ok')
            node.expr: ArrayOffset(Variable('$_GET'), 'a')
            '''            
            currscope = locatescope()
            varnode = node.node
            newobj = VariableDef(varnode.name, varnode.lineno,
                                 currscope, ast_node=node.expr)
            currscope.add_var(newobj)
            # Stop parsing children nodes
            stoponthis = True
        
        elif nodety in (phpast.Block, phpast.If, phpast.Else, phpast.ElseIf,
                    phpast.While, phpast.DoWhile, phpast.For, phpast.Foreach):
            parentscope = locatescope()
            # Use 'If's parent scope
            if nodety in (phpast.Else, phpast.ElseIf):
                parentscope = parentscope._parent_scope
            # Create new Scope and push it onto the stack
            newscope = Scope(node, parent_scope=parentscope)
            self._scopes.append(newscope)
        
        elif nodety is phpast.Function:
            '''
            function test($wouter) {
            node: Function('test', [FormalParameter('$wouter', None, False, None)], [], False)
            node.name: test
            '''           
            # global parent scope
            parentscope = locatescope()  
            
            # Create new Scope and push it onto the stack
            newscope = Scope(node, parent_scope=parentscope, is_root=True)
            
            # add builtins to scope
            newscope._builtins = dict(
                    ((uv, VariableDef(uv, -1, newscope)) for uv in VariableDef.USER_VARS))
            
            # Don't trigger vulnerabilities in this scope untill code is no longer dead
            newscope._dead_code = True
            
            self._scopes.append(newscope)
            
            node._scope = newscope
            self._functionsDec[node.name] = node 
        
        elif nodety is phpast.FormalParameter:
            currscope = locatescope()
            newobj = VariableDef(node.name, node.lineno, currscope, ast_node = node)
            newobj._formal_parameter = True
            currscope.add_var(newobj)
        
        # Debug it?
        if self.debugmode and newobj:
            print newobj
        
        return stoponthis


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
        # Is var a formal parameter of function?
        self._formal_parameter = False

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
        cbusr = self._controlled_by_user
        
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
        return "<Var definition at line %s>" % self.lineno
    
    def __str__(self):
        return ("Line  %(lineno)s. Declaration of variable '%(name)s'."
            " Status: %(status)s") % \
            {'name': self.name,
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
                    vulnty = FuncCall.get_vulnty_for_sec(fc.name)
                    if vulnty:
                        self._safe_for.append(vulnty)
                return n
        return None

class FuncCall(NodeRep):
    '''
    Representation for FunctionCall AST node.
    '''
    
    # Potentially Vulnerable Functions Database
    PVFDB = {
        'OS_COMMANDING':
            {'system':'', 'exec':'', 'shell_exec':''},
        'XSS':
            {'echo':'', 'print':'', 'printf':'', 'header':''},
        'FILE_INCLUDE':
            {'include':'', 'require':''},
        'FILE_DISCLOSURE':
            {'file_get_contents':'', 'file':'', 'fread':'', 'finfo_file':''},
        }
    # Securing Functions Database
    SFDB = {
        'OS_COMMANDING': 
            ('escapeshellarg', 'escapeshellcmd'),
        'XSS':
            ('htmlentities', 'htmlspecialchars'),
        'SQL':
            ('addslashes', 'mysql_real_escape_string', 'mysqli_escape_string',
             'mysqli_real_escape_string')
        }
    
    def __init__(self, name, lineno, ast_node, scope):
        NodeRep.__init__(self, name, lineno, ast_node=ast_node)
        self._scope = scope
        self._params = self._parse_params()
        self._vulntypes = None
        self._vulnsources = None
    
    @property
    def vulntypes(self):
        vulntys = self._vulntypes
        
        if type(vulntys) is list:
            return vulntys
        else:
            # Defaults to no vulns.
            self._vulntypes = vulntys = []
            
            possvulntypes = FuncCall.get_vulnty_for(self._name)

            for possvulnty in possvulntypes:
                for v in (p.var for p in self._params if p.var):
                    if v.controlled_by_user and v.is_tainted_for(possvulnty):
                        # if list we need to check params
                        if type(FuncCall.PVFDB[possvulnty][self.name]) == list:                   
                            root_scope = v._scope.get_root_scope()
                            param_index = v._parent_obj.get_index()
                            if param_index in FuncCall.PVFDB[possvulnty][self.name]:
                                vulntys.append(possvulnty)
                        else:
                            root_scope = v._scope.get_root_scope()
                            if root_scope._dead_code == False:
                                vulntys.append(possvulnty)

                
        return vulntys
    
    @property
    def vulnsources(self):
        vulnsrcs = self._vulnsources
        if type(vulnsrcs) is list:
            return vulnsrcs
        else:
            vulnsrcs = self._vulnsources = []
            # It has to be vulnerable; otherwise we got nothing to do.
            if self.vulntypes:
                map(vulnsrcs.append, (p.var.taint_source for p in self._params 
                                      if p.var and p.var.taint_source))
        return vulnsrcs
    
    @property
    def params(self):
        return self._params
    
    @staticmethod
    def get_vulnty_for(fname):
        '''
        Return the vuln types for the given function name `fname`.
        
        @param fname: Function name
        '''
        vulntypes = []
        for vulnty, pvfnames in FuncCall.PVFDB.iteritems():
            if any(fname == pvfn for pvfn in pvfnames):
                vulntypes.append(vulnty)
        return vulntypes
    
    @staticmethod
    def get_vulnty_for_sec(sfname):
        '''
        Return the the vuln. type secured by securing function `sfname`.
        
        @param sfname: Securing function name 
        '''
        for vulnty, sfnames in FuncCall.SFDB.iteritems():
            if any(sfname == sfn for sfn in sfnames):
                return vulnty
        return None
    
    def __repr__(self):
        return "<'%s' call at line %s>" % (self._name, self._lineno)
    
    def __str__(self):
        return "Line %s. '%s' function call. Vulnerable%s" % \
            (self.lineno, self.name, self.vulntypes and 
             ' for %s.' % ','.join(self.vulntypes) or ': No.')
    
    def _parse_params(self):
        def attrname(node):
            nodety = type(node)
            if nodety == phpast.FunctionCall:
                name = 'params'
            elif nodety == phpast.Echo:
                name = 'nodes'
            elif nodety == phpast.Print:
                name = 'node'
            elif nodety in (phpast.Include, phpast.Require):
                name = 'expr'
            else:
                name = ''
            return name
            
        params = []
        astnode = self._ast_node
        nodeparams = getattr(astnode, attrname(astnode), [])
        
        if nodeparams and type(nodeparams) is not list:
            nodeparams = [nodeparams]
        
        for par in nodeparams:
            # All nodes should have parents?
            par._parent_node = astnode
            params.append(Param(par, self._scope, self))
        return params


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
        
    def get_root_scope(self):
        while self._is_root == False:
            self = self._parent_scope
        return self
        
    def add_var(self, newvar):
        if newvar is None:
            raise ValueError, "Invalid value for parameter 'var': None"
        
        selfvars = self._vars
        newvarname = newvar.name
        varobj = selfvars.get(newvarname)
        if not varobj or newvar > varobj:
            selfvars[newvarname] = newvar
            
            # don't add var to parent if function
            if type(self._ast_node) is phpast.Function:
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
    
    def get_var(self, varname):
        var = self._vars.get(varname, None) or self._builtins.get(varname)
        
        # Don't look in parent node for var
        if type(self._ast_node) is phpast.Function:
            return var
        
        # look in parent node
        if not var and self._parent_scope:
            var = self._parent_scope.get_var(varname)
            
        return var
    
    def get_all_vars(self):
        return self._vars.values()
    
    def __repr__(self):
        return "<Scope [%s]>" % ', '.join(v.name for v in self.get_all_vars())


class Param(object):
    
    def __init__(self, node, scope, parent_obj):
        # Usefull to get parent function call
        self._parent_obj = parent_obj
        self.var = self._parse_me(node, scope)
    
    def get_index(self):
        param_index = min(i for i in range(len(self._parent_obj._params)) if self == self._parent_obj._params[i])
        return param_index
    
    def _parse_me(self, node, scope):
        '''
        Traverse this AST subtree until either a Variable or FunctionCall node
        is found...
        '''  
        vardef = None
        
        for node in NodeRep.parse(node):
            
            if type(node) is phpast.Variable:        
                varname = node.name
                scopevar = scope.get_var(varname)
                scope.get_var_like(varname + '__$temp_anon_var$_')
                vardef_nr = str(len(scope.get_var_like(varname + '__$temp_anon_var$_')))
                vardef = VariableDef(varname + '__$temp_anon_var$_' + vardef_nr, node.lineno, scope)
                vardef.var_node = node
                vardef.parent = scopevar
                vardef._parent_obj = self
                scope.add_var(vardef)
                break
            
            elif type(node) is phpast.FunctionCall:
                vardef = VariableDef(node.name + '_funvar', node.lineno, scope)
                fc = FuncCall(node.name, node.lineno, node, scope)
      
                # TODO: So far we only work with the first parameter.
                # IMPROVE THIS!!!
                vardef.parent = fc.params and fc.params[0].var or None

                vulnty = FuncCall.get_vulnty_for_sec(fc.name)
                if vulnty:
                    vardef._safe_for.append(vulnty)
                break
        
        return vardef
