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
        # class node to create new instances
        self._classes = {}
        # variableDefs that are objects
        self._objects = {}
        # used for method traveling
        self._methods_deep = []
        
    def get_functionDec(self):
        self._start()
        return self._functionsDec
    
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
            for trace in f._vulntraces:
            #for vulnty in f.vulntypes:
                vulnty = trace[0]
                flist = resdict.setdefault(vulnty, [])
                flist.append(trace[1:])
        return resdict
    
    def get_vars(self, usr_controlled=False):
        self._start()
        filter_tainted = (lambda v: v.controlled_by_user) if usr_controlled \
                            else (lambda v: 1)
        all_vars = filter(filter_tainted, self._scopes[0].get_all_vars())
        
        return all_vars
    
    def get_objects(self):
        self._start()
        return self._objects
    
    def get_func_calls(self, vuln=False):
        self._start()
        filter_vuln = (lambda f: len(f._vulntraces)) if vuln \
                        else (lambda f: True)
        funcs = filter(filter_vuln, self._functions)
        return funcs
    
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
        
        if nodety is phpast.MethodCall:
            '''
            node: MethodCall(Variable('$obj'), 'body', [Parameter(Variable('$hoi'), False)])
            node.node: Variable('$obj')
            '''
            currscope = locatescope()
            method_name = getattr(node, 'name', node.__class__.__name__.lower())
                        
            # Get object
            if node.node.name == '$this':
                object = currscope.get_root_scope()._parent_scope.obj
            else:    
                object = self._objects[node.node.name]._obj_def
            
            method = object.get_method(method_name)
            
            # clean formal parms to avoid false positives
            method.clean_formal_params()
            
            # keep track of the methos being traveled
            self._methods_deep.append(method)
            
            # Start ast travel method Node
            if method._parsed is False:
                method._parsed = True
                method._ast_node.accept(self._visitor)

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
            if self._methods_deep[0] is method:
                
                # 1.We need to link all params and formal params together
                # all traveled methods
                for method0 in self._methods_deep:
                    # All method calls in method
                    for method_call1 in method0._scope.get_method_calls():
                        # Link
                        for par_index, param in enumerate(method_call1.params):
                            formal_param = method_call1._method.get_formal_param(par_index)
                            formal_param._controlled_by_user = None
                            formal_param.is_root = False
                            formal_param.parent = param.var
                                               
                # 2.Determine vulnerabilities
                for method0 in self._methods_deep:
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
                
                self._methods_deep = [] # reset method call stack
                
            stoponthis = True
        
        # Custom function call
        if nodety is phpast.FunctionCall and node.name in self._functionsDec:
            
            # Link functionCall to custom function
            functionObj = self._functionsDec[node.name]
            node._function = functionObj
            
            # Create funccall (parses the params of funccall)
            name = getattr(node, 'name', node.__class__.__name__.lower())
            newobj = FuncCall(name, node.lineno, node, locatescope())

            # Set function scope as active code
            functionObj._scope._dead_code = False
            
            # Evaluate if vulnerable (this state will be overridden upon new function call)
            for funccall in functionObj._scope.get_functions():
                vulntype = funccall.is_vulnerable_for()
                if vulntype:
                    funccall.add_vulntrace(vulntype)
            
            stoponthis = True
        
        # Create FuncCall nodes. 
        # PHP special functions: echo, print, include, require
        if nodety in (phpast.FunctionCall, phpast.Echo, phpast.Print, 
                      phpast.Include, phpast.Require):

            currentscope = locatescope()
            name = getattr(node, 'name', node.__class__.__name__.lower())

            # Don't process custom functions until function call
            if name not in self._functionsDec:
                
                # new function call
                newobj = FuncCall(name, node.lineno, node, currentscope, self)
                self._functions.append(newobj)

                # Evaluate if vulnerable, if true add trace
                vulntype = newobj.is_vulnerable_for()
                if vulntype:
                    newobj.add_vulntrace(vulntype)     
                
                # add vuln trace of pending trace (from param)
                if getattr(newobj,'_pending_trace', None):
                    newobj.add_vulntrace(trace = newobj._pending_trace)
                    newobj._pending_trace = None
                                
                # add function to root scope.
                currentscope.get_root_scope().add_function(newobj)
                
                # Stop parsing children nodes
                stoponthis = True
    
        # Create the VariableDef
        elif nodety is phpast.Assignment:
            '''
            $ok = $_GET['a'];
            node:      Assignment(Variable('$ok'), ArrayOffset(Variable('$_GET'), 'a'), False)
            node.node: Variable('$ok')
            node.expr: ArrayOffset(Variable('$_GET'), 'a')
            
            $this->prop = 'property' (in method)
            node: Assignment(ObjectProperty(Variable('$this'), 'prop'), 'property', False)
            node.node: ObjectProperty(Variable('$this'), 'prop')
            node.expr: Variable('$prop')
            
            private $prop = 'property'
            node: ClassVariables(['private'], [ClassVariable('$prop', 'property')])
            
            $bla = $this->bla;
            node: Assignment(Variable('$bla'), ObjectProperty(Variable('$this'), 'bla'), False)
            node.node = Variable('$bla');
            '''
            
            currscope = locatescope()
            varnode = node.node
            var_name = varnode.name
            
            # Store object properties (vars, class variables) as $this->property
            # otherwise $a->var and $b->var overwrite each other (both stored as $var).
            if type(node.node) is phpast.ObjectProperty:
                var_name = node.node.node.name + '->' + varnode.name

            # Create var
            newobj = VariableDef(var_name, varnode.lineno, currscope, ast_node=node.expr)
            
            # Add var to scope
            currscope.add_var(newobj)
            
            # New object property? Also add var to parent scope (if not exist)
            if type(node.node) is phpast.ObjectProperty:
                root_scope = currscope.get_root_scope()._parent_scope
                if not root_scope.get_var(var_name): 
                    # create object var 
                    property = VariableDef(var_name, varnode.lineno, currscope, ast_node=node.expr)
                    property.parent = newobj
                    root_scope.add_var(property)

            # Overwrite object property
            if type(node.node) is phpast.ObjectProperty:
                # link this var to object property
                root_scope = currscope.get_root_scope()
                if type(root_scope._ast_node) is phpast.Method:
                    # link this var to property
                    root_scope._parent_scope.get_var(var_name).parent = newobj
            
            # Object creation
            if type(node.expr) is phpast.New and node.expr.name in self._classes:
                # Start ast travel class Node
                class_node = self._classes[node.expr.name]
                class_node._object = True
                class_node._object_var = newobj # pass this var to object
                class_node.accept(self._visitor)

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
        
        elif nodety is phpast.Class:
            # global parent scope
            parentscope = locatescope()
            
            if not getattr(node, '_object', False):
                # Start traveling node when instance is created
                node._parent_scope = parentscope
                self._classes[node.name] = node
                stoponthis = True
            else:
                # new instance has been created
                # Create new Scope and push it onto the stack
                newscope = Scope(node, parent_scope=parentscope, is_root=True)
                
                # add builtins to scope
                newscope._builtins = dict(
                        ((uv, VariableDef(uv, -1, newscope)) for uv in VariableDef.USER_VARS))
                                
                self._scopes.append(newscope)
                
                newobj = Obj(node.name, node.lineno, newscope, node._object_var, ast_node=node)
                
                # create $this var for internal method calling
                this_var = VariableDef('$this', node.lineno, newscope)
                this_var._obj_def = newobj
                newscope.add_var(this_var)
                
                # add ObjDef to VarDef, this way we can trace method call back to the correct instance
                node._object_var._obj_def = newobj            
                
                node._scope = newscope
                self._objects[node._object_var.name] = node._object_var
            
        elif nodety is phpast.Method:
            # Methodes are not traveled untill called, this enables us to call methods from within methods
            method = node._parent_node._object_var._obj_def.get_method(node.name)
            if method:
                # Method object was already created, travel the children           
                self._scopes.append(method._scope)
            else:
                # Create method so we can travel childres nodes when called
                parentscope = locatescope() 
                # Create new Scope and push it onto the stack
                newscope = Scope(node, parent_scope=parentscope, is_root=True)
                # node seen
                node._seen = True
                # add builtins to scope
                newscope._builtins = dict(
                        ((uv, VariableDef(uv, -1, newscope)) for uv in VariableDef.USER_VARS))            
                # Don't trigger vulnerabilities in this scope untill code is no longer dead
                newscope._dead_code = True
                
                self._scopes.append(newscope)
                
                newobj = Method(node.name, node.lineno, newscope, ast_node=node)
                
                node._scope = newscope
                
                # add this method to object
                node._parent_node._object_var._obj_def.add_method(newobj)
                
                # Stop parsing children nodes
                stoponthis = True
        
        elif nodety is phpast.ClassVariables:
            '''
            Node: ClassVariables(['private'], [ClassVariable('$prop', 'property')])
            node.modifiers: ['private']
            node.nodes[0]: ClassVariable('$prop', 'property')
            '''
            currscope = locatescope()
            variable = node.nodes[0]
            # set var name to $this->property
            name = '$this->' + variable.name[1:]
            newobj = VariableDef(name, node.lineno, currscope, ast_node = variable)
            currscope.add_var(newobj)
        
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
           
            # create Function object
            newobj = Function(node.name, node.lineno, newscope, ast_node=node)
            
            # Store custom function
            self._functionsDec[node.name] = newobj         

        
        elif nodety is phpast.FormalParameter:
            currscope = locatescope()
            newobj = VariableDef(node.name, node.lineno, currscope, ast_node = node)
            currscope.add_var(newobj)
            
            # If method add
            if type(node._parent_node) is phpast.Method:
                method_name = node._parent_node.name
                object_var = node._parent_node._parent_node._object_var
                object_var._obj_def.get_method(method_name).add_formal_param(newobj)
            # Function
            elif type(node._parent_node) is phpast.Function:
                function_name = node._parent_node.name
                self._functionsDec[function_name].add_formal_param(newobj)
        
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
                if getattr(varnode,'_parent_node', None) and type(varnode._parent_node) is phpast.ObjectProperty and varnode.name == '$this':
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
        return "<Var %s definition at line %s>" % (self.name, self.lineno)
    
    def __str__(self):
        return ("Line %(lineno)s. Declaration of variable '%(name)s'."
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
    
    def set_clean(self):
        self._controlled_by_user = None
        self._taint_source = None
        self._is_root = True        

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

class Function(NodeRep):
    def __init__(self, name, lineno, scope, ast_node=None):
        NodeRep.__init__(self, name, lineno, ast_node=ast_node)
        
        self._scope = scope
        self._formal_params = []

    def add_formal_param(self, var):
        self._formal_params.append(var)

    def get_formal_param(self, index):
        return self._formal_params[index]
    
    def get_formal_params(self):
        return self._formal_params  


class FuncCall(NodeRep):
    '''
    Representation for FunctionCall AST node.
    '''
    
    # Potentially Vulnerable Functions Database
    PVFDB = {
        'OS_COMMANDING':
            ('system', 'exec', 'shell_exec'),
        'XSS':
            ('echo', 'print', 'printf', 'header'),
        'FILE_INCLUDE':
            ('include', 'require'),
        'FILE_DISCLOSURE':
            ('file_get_contents', 'file', 'fread', 'finfo_file'),
        'SQL_INJECTION':
            ('mysql_query', 'mysqli_query'),
        }
    # Securing Functions Database
    SFDB = {
        'OS_COMMANDING':
            ('escapeshellarg', 'escapeshellcmd'),
        'XSS':
            ('htmlentities', 'htmlspecialchars'),
        'SQL_INJECTION':
            ('addslashes', 'mysql_real_escape_string', 'mysqli_escape_string',
             'mysqli_real_escape_string')
        }
    
    
    def __init__(self, name, lineno, ast_node, scope, parent_obj = None):
        NodeRep.__init__(self, name, lineno, ast_node=ast_node)
        self._scope = scope
        self._parent_obj = parent_obj        
        self._params = self._parse_params()
        # Funccall can be called multiple times (in custom function or method)
        self._vulntraces = []
    
    def get_vulntraces(self):
        return self._vulntraces
    
    def add_vulntrace(self, vulntype = None, trace = None):
        if vulntype:
            trace = [vulntype[0]]
            trace.append(self)
            for p in self._params:
                if p.var and p.var.taint_source:
                    # Add param to trace
                    var = p.var
                    trace.append(var)
                    # Add all vars to trace
                    while var.parent.taint_source:
                        trace.append(var.parent)
                        var = var.parent
            self._vulntraces.append(trace)
            
        elif trace:
            trace.insert(1, self)
            self._vulntraces.append(trace) 
    
    def is_vulnerable_for(self):
        vulntys = []
        possvulnty = FuncCall.get_vulnty_for(self.name)            
        if possvulnty:
            for v in (p.var for p in self._params if p.var):
                if v.controlled_by_user and v.is_tainted_for(possvulnty):
                    root_scope = v._scope.get_root_scope()
                    if root_scope._dead_code == False:
                        vulntys.append(possvulnty)
        return vulntys
                
    @property
    def vulntypes(self):
        vulntys = []
        map(vulntys.append, (trace[0] for trace in self.get_vulntraces()))
        return vulntys
    
    @property
    def vulnsources(self):
        vulnsrcs = []
        map(vulnsrcs.append, (trace[-1].taint_source for trace in self.get_vulntraces()))
        return vulnsrcs
    
    @property
    def params(self):
        return self._params
    
    def get_class(self):
        if type(self.ast_node) is not phpast.MethodCall:
            return None
        var_name = self.ast_node.node.name
        var = self._scope.get_var(var_name)
        class_name = var.ast_node.name
        return class_name
    
    @staticmethod
    def get_vulnty_for(fname):
        '''
        Return the vuln type for the given function name `fname`. Return None
        if no vuln type is associated.
        
        @param fname: Function name
        '''
        for vulnty, pvfnames in FuncCall.PVFDB.iteritems():
            if any(fname == pvfn for pvfn in pvfnames):
                return vulnty
        return None
    
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
            if nodety in (phpast.FunctionCall, phpast.MethodCall):
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
        ast_node = self._ast_node
        nodeparams = getattr(ast_node, attrname(ast_node), [])

        # Set al formal params to clean state
        # Custom function
        if type(ast_node) is phpast.FunctionCall and getattr(ast_node, '_function', None):
            functionObj = ast_node._function
            for param_var in functionObj.get_formal_params():
                param_var.set_clean()
        
        # Method
        elif type(ast_node) is phpast.MethodCall:
            # get object name (for example $obj1)
            object_name = self._ast_node.node.name
            # get object var
            object_var = self._scope.get_var(object_name)
            method_name = self.name            
            method = object_var._obj_def.get_method(method_name)
            for param_var in method.get_formal_params():
                param_var.set_clean
        
        if nodeparams and type(nodeparams) is not list:
            nodeparams = [nodeparams]
        
        # Create params
        for par_index, par in enumerate(nodeparams):

            # All nodes should have parents?
            par._parent_node = ast_node
            param = Param(par, self._scope, self)
            params.append(param)
            
            # links params to formal params
            # Methods call
            if type(ast_node) is phpast.MethodCall and param.var:
                formal_param = method.get_formal_param(par_index)
                formal_param._controlled_by_user = None
                formal_param.is_root = False
                formal_param.parent = param.var
            
            # Custom function calls
            elif type(ast_node) is phpast.FunctionCall and param.var and getattr(ast_node, '_function', None):
                formal_param = functionObj.get_formal_param(par_index)
                formal_param._controlled_by_user = None
                formal_param.is_root = False
                formal_param.parent = param.var
          
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
        self._functions = []
        self._method_calls = []
    
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
    
    def get_var(self, varname):
        var = self._vars.get(varname, None) or self._builtins.get(varname)

        # Don't look in parent node for var
        if self._is_root and type(self._ast_node) is not phpast.Method:
            return var
        
        # look in parent parent scope
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
    
    def get_root_obj(self):
        while getattr(self, '_parent_obj', None):
            self = self._parent_obj
        return self
            
    
    def _parse_me(self, node, scope):
        '''
        Traverse this AST subtree until either a Variable or FunctionCall node
        is found...
        '''  
        vardef = None

        for node in NodeRep.parse(node):

            if type(node) is phpast.Variable:

                # object properties are stored as $this->property
                varname = node.name
                if type(node._parent_node) is phpast.ObjectProperty:
                    varname = node._parent_node.node.name + '->' + node._parent_node.name 
                
                vardef = VariableDef(varname + '__$temp_anon_var$_', node.lineno, scope)
                vardef.var_node = node
                # add type
                vardef._anon_var = True
                # get and set parent
                scopevar = scope.get_var(varname)
                vardef.parent = scopevar
                # add Param to VarDef
                vardef._parent_obj = self
                # add var to current scope
                scope.add_var(vardef)
                
                # TODO: remove this break to parse rest of param
                # $foo = htmlspecialchars($_GET[1]) . $_GET[2]
                break
            
            elif type(node) is phpast.FunctionCall:
 
                vardef = VariableDef(node.name + '_funvar', node.lineno, scope)

                fc = FuncCall(node.name, node.lineno, node, scope, self)
                
                # Add vulntrace
                vulntype = fc.is_vulnerable_for()              
                if vulntype and 'FILE_DISCLOSURE' in vulntype and self._parent_obj.name in FuncCall.PVFDB['XSS']: 
                    # Add vulntrace to parent call with pending trace
                    fc.add_vulntrace(vulntype)
                    self._parent_obj._pending_trace = fc.get_vulntraces()[-1]
                    vardef._safe_for.append('XSS')
                    vardef.set_clean()
                
                elif vulntype:
                    fc.add_vulntrace(vulntype)
                    # Keep track of thin funccal
                    self.get_root_obj()._functions.append(fc)
                    vardef.set_clean()
      
                # TODO: So far we only work with the first parameter.
                # IMPROVE THIS!!!
                vardef.parent = fc.params and fc.params[0].var or None
    
                # Securing function?
                vulnty = FuncCall.get_vulnty_for_sec(fc.name)
                if vulnty:
                    vardef._safe_for.append(vulnty)
                break

        return vardef
