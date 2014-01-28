'''
sca_core.py

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
import phply.phpast as phpast
# Slight modification to original 'accept' method.
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


from core.visitors.assignment_visitor import AssignmentVisitor 
from core.visitors.class_variables_visitor import ClassVariablesVisitor
from core.visitors.class_visitor import ClassVisitor
from core.visitors.flow_control_visitor import FlowControlVisitor
from core.visitors.formal_parameter_visitor import FormalParameterVisitor
from core.visitors.function_call_visitor import FunctionCallVisitor
from core.visitors.function_visitor import FunctionVisitor
from core.visitors.method_visitor import MethodVisitor
from core.visitors.method_call_visitor import MethodCallVisitor
from core.visitors.return_visitor import ReturnVisitor
from core.visitors.vulnerable_func_visitor import VulnerableFuncVisitor


from core.state import State


class PhpSCA(object):
    '''
    PHP Static Code Analyzer class. Intended to detect and report code
    vulnerabilities given an php source input.
    '''
    
    DEBUG = False
    
    def __init__(self, code=None, infile=None):
        if not code and not infile:
            raise ValueError, ("Invalid arguments. Either parameter 'code' or "
                               "'file' should not be None.")
        if infile:
            with open(infile, 'r') as f:
                code = f.read()

        # Define the initial state that contains variables, functions, classes,
        # etc. that then updated by visiting each AST node
        self.state = State(code, (infile or None))
        
        # Init all the visitors, which will be the ones responsible for analyzing
        # each AST node and changing the state 
        self.VISITORS = ( AssignmentVisitor(self._visitor) ,
                          ClassVariablesVisitor(self._visitor),
                          ClassVisitor(self._visitor),
                          FlowControlVisitor(self._visitor),
                          FormalParameterVisitor(self._visitor),
                          FunctionCallVisitor(self._visitor),
                          FunctionVisitor(self._visitor),
                          MethodVisitor(self._visitor),
                          MethodCallVisitor(self._visitor),
                          ReturnVisitor(self._visitor),
                          VulnerableFuncVisitor(self._visitor),
                          )
        
        self._start()
    
    def _start(self):
        '''
        Start AST traversal
        '''
        # Set parent to all nodes,
        for node in self.state.ast_code:
            node._parent_node = self.state.global_pnode
        
        # Start AST traversal!
        self.state.global_pnode.accept(self._visitor)
        
    def get_alerts(self):
        return self.state.alerts        
    
    def get_function_decl(self):
        return self.state.functions_declarations
    
    def get_vulns(self):
        '''
        Return a dict that maps vuln. types to FuncCall objects.
        
        Output example:
            {'XSS': [<'system' call at line 2>, <'echo' call at line 4>],
             'OS_COMMANDING': [<'system' call at line 6>]}
        '''
        resdict = {}
        for f in self.get_func_calls(vuln=True):
            for trace in f._vulntraces:
            #for vulnty in f.vulntypes:
                vulnty = trace[0]
                flist = resdict.setdefault(vulnty, [])
                flist.append(trace[1:])
        return resdict
    
    def get_vars(self, usr_controlled=False):
        filter_tainted = (lambda v: v.controlled_by_user) if usr_controlled \
                            else (lambda v: 1)
        all_vars = filter(filter_tainted, self.state.scopes[0].get_all_vars())
        
        return all_vars
    
    def get_objects(self):
        return self.state.objects
    
    def get_func_calls(self, vuln=False):
        filter_vuln = (lambda f: len(f._vulntraces)) if vuln \
                        else (lambda f: True)
        funcs = filter(filter_vuln, self.state.functions)
        return funcs
    
    def _visitor(self, node):
        '''
        Visitor method for AST traversal. Used as arg for AST nodes' 'accept'
        method (Visitor Design Pattern)
        '''
        nodety = type(node)
        
        for visitor in self.VISITORS:
            if visitor.should_visit(nodety, node, self.state):
                
                newobj, stoponthis = visitor.visit(node, self.state)
                
                self.debug(newobj)
                    
                return stoponthis
        else:
            self.debug('There is no visitor for "%s"' % node)
            
        return False
    
    def debug(self, newobj):
        if self.DEBUG and newobj:
            print newobj
        