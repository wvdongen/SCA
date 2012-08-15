'''
vulnerable_func_visitor.py

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
import os

from phply import phplex
from phply.phpparse import parser
import phply.phpast as phpast

from core.visitors.base_visitor import BaseVisitor
from core.nodes.variable_def import VariableDef
from core.nodes.function_call import FuncCall
from core.scope import Scope

class VulnerableFuncVisitor(BaseVisitor):
    '''
    Create FuncCall nodes. 
    PHP special functions: echo, print, include, require
    '''

    def __init__(self, main_visitor_method):
        super(VulnerableFuncVisitor, self).__init__(main_visitor_method)
    
    def should_visit(self, nodety, node, state):
        return nodety in (phpast.FunctionCall, phpast.Echo, phpast.Print, 
                          phpast.Include, phpast.Require)
        
    def parse_include_require(self, node, state, currentscope):
        # TO DO: Smarter filename detection. For example if file is set in variable.
        # Open file
        infile = os.path.join(state.path, str(node.expr))
        try:
            f = open(infile, 'r')
        except IOError as e:
            return

        code = f.read()
        
        # Lexer instance
        sublexer = phplex.lexer.clone()
        
        # Code AST
        try:
            new_ast_code = parser.parse(code, lexer=sublexer)
        except SyntaxError, se:
            state.alerts.append("Error while parsing the code of include file '%s', syntax error: '%s'" % (infile, se))
            return
    
        # Convenient definition of new node type
        GlobalParentNodeType = phpast.node('GlobalParentNodeType',
                                           ['name', 'children', '_parent_node'])
        
        new_pnode = GlobalParentNodeType(infile, new_ast_code, None)
        
        # Set parent to all nodes,
        for n in new_ast_code:
            n._parent_node = node           
        
        # Create scope
        newscope = Scope(new_pnode, parent_scope=currentscope)     
        state.scopes.append(newscope)
        
        # Start AST travel
        new_pnode.accept(self._main_visitor_method)

    def visit(self, node, state):
        currentscope = self.locate_scope(node, state)
        name = getattr(node, 'name', node.__class__.__name__.lower())

        # Don't process custom functions until function call
        if name not in state.functions_declarations:
            
            # new function call
            newobj = FuncCall(name, node.lineno, node, currentscope, self)
            state.functions.append(newobj)
            
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
            
            # Travel other files if include or require
            if type(node) in (phpast.Include, phpast.Require):
                self.parse_include_require(node, state, currentscope)            
            
            # Stop parsing children nodes
            stoponthis = True
        
        return newobj, True

        