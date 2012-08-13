'''
class_variables_visitor.py

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
from core.nodes.variable_def import VariableDef


class ClassVariablesVisitor(BaseVisitor):
    '''
    Node: ClassVariables(['private'], [ClassVariable('$prop', 'property')])
    node.modifiers: ['private']
    node.nodes[0]: ClassVariable('$prop', 'property')
    '''
    def __init__(self, main_visitor_method):
        super(ClassVariablesVisitor, self).__init__(main_visitor_method)
    
    def should_visit(self, nodety, node, state):
        return nodety is phpast.ClassVariables

    def visit(self, node, state):
        currscope = self.locate_scope(node, state)
        variable = node.nodes[0]
        # set var name to $this->property
        name = '$this->' + variable.name[1:]
        newobj = VariableDef(name, node.lineno, currscope, ast_node = variable)
        currscope.add_var(newobj)

        return newobj, False

        