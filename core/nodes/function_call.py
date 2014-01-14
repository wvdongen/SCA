'''
function_call.py

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
from core.nodes.parameter import Param
from core.vulnerabilities.definitions import get_vulnty_for


class FuncCall(NodeRep):
    '''
    Representation for FunctionCall AST node.
    '''    
    
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
        
        # Recursively walk parents
        def walk(vars, level = 0, prevlevel = 0, trace = None):
            for i, var in enumerate(vars):
                if var.taint_source:
                    
                    if i+1 < len(vars):                    
                        copy = list(trace)
                        copy.append(var) 
                        walk(var.parents, level + 1, 0, copy)
                        self._vulntraces.append(copy)
                    else:
                        trace.append(var) 
                        walk(var.parents, level + 1, 0, trace)
            if level == 0:
                self._vulntraces.append(trace)
        
        if vulntype:
            for param in self._params:
                for var in param.vars:
                    if var.controlled_by_user and var.is_tainted_for(vulntype[0]):
                        trace = [vulntype[0]]
                        trace.append(self)        

                        # Add param to trace
                        trace.append(var)
                        
                        # Add all vars to trace
                        if var.parents:
                            walk(var.parents, 0, 0, trace)
                            
                        #self._vulntraces.append(trace)
        
        elif trace:
            trace.insert(1, self)
            self._vulntraces.append(trace)
    
    def is_vulnerable_for(self):
        vulntys = []
        possvulnty = get_vulnty_for(self.name)
        if possvulnty:
            for vars in (p.vars for p in self._params if p.vars):
                for v in vars:
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
        return [item for sublist in vulnsrcs for item in sublist]
    
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
        
    def __repr__(self):
        return "<'%s' call at line %s in '%s'>" % (self._name, self._lineno, self.get_file_name())
    
    def __str__(self):
        return "Line %s in '%s'. '%s' function call. Vulnerable%s" % \
            (self.lineno, self.get_file_name(), self.name, self.vulntypes and 
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
            if isinstance(par, phpast.Node):
                par._parent_node = ast_node
            param = Param(par, self._scope, self)
            params.append(param)
            
            # links params to formal params
            # Methods call
            if type(ast_node) is phpast.MethodCall and param.vars:
                formal_param = method.get_formal_param(par_index)
                formal_param._controlled_by_user = None
                formal_param.is_root = False
                formal_param.parents = param.vars
            
            # Custom function calls
            elif type(ast_node) is phpast.FunctionCall and param.vars and getattr(ast_node, '_function', None):
                formal_param = functionObj.get_formal_param(par_index)
                formal_param._controlled_by_user = None
                formal_param.is_root = False
                formal_param.parents = param.vars
          
        return params