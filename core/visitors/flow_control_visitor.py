'''
flow_control_visitor.py

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

from core.visitors.base_visitor import BaseVisitor
from core.scope import Scope


class FlowControlVisitor(BaseVisitor):
    '''
    Create new Scopes
    '''

    def __init__(self, main_visitor_method):
        super(FlowControlVisitor, self).__init__(main_visitor_method)
    
    def should_visit(self, nodety, node, state):
        return nodety in (phpast.Block, phpast.If, phpast.Else, phpast.ElseIf,
                          phpast.While, phpast.DoWhile, phpast.For,
                          phpast.Foreach)

    def visit(self, node, state):
        nodety = type(node)
        parentscope = self.locate_scope(node, state)
        # Use 'If's parent scope
        if nodety in (phpast.Else, phpast.ElseIf):
            parentscope = parentscope._parent_scope
        # Create new Scope and push it onto the stack
        newscope = Scope(node, parent_scope=parentscope)
        state.scopes.append(newscope)

        return None, False

        