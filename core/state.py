'''
state.py

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

from phply import phplex
from phply.phpparse import parser 

from core.scope import Scope
from core.nodes.variable_def import VariableDef
from core.exceptions.syntax_error import CodeSyntaxError


class State(object):
    '''
    This class represents the static code analyzer state, which at least contains:
        * Defined variables
        * Defined functions
        * Defined methods
        * Defined attributes
    '''
    def __init__(self, code):
        #
        #    Init internal variables that hold most information
        #
        # FuncCall nodes
        self.functions = []
        # FunctionDeclarations
        self.functions_declarations = {}
        # class node to create new instances
        self.classes = {}
        # variableDefs that are objects
        self.objects = {}
        # used for method traveling
        self.methods_deep = []
        
        # Lexer instance
        lexer = phplex.lexer.clone()
        # Code AST
        try:
            self.ast_code = parser.parse(code, lexer=lexer)
        except SyntaxError, se:
            raise CodeSyntaxError, "Error while parsing the code, syntax error: '%s'" % se
        
        # Convenient definition of new node type
        GlobalParentNodeType = phpast.node('GlobalParentNodeType',
                                           ['name', 'children', '_parent_node'])
        ## Instantiate it and self-assign it as root node
        self.global_pnode = GlobalParentNodeType('dummy', self.ast_code, None)
                
        # Define scope
        scope = Scope(self.global_pnode, parent_scope=None, is_root=True)
        scope._builtins = dict(
            ((uv, VariableDef(uv, -1, scope)) for uv in VariableDef.USER_VARS))
        
        self.scopes = [scope]