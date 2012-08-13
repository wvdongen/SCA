'''
class_visitor.py

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
from core.nodes.obj import Obj
from core.scope import Scope


class ClassVisitor(BaseVisitor):
    '''
    Create new Scopes
    '''

    def __init__(self, main_visitor_method):
        super(ClassVisitor, self).__init__(main_visitor_method)
    
    def should_visit(self, nodety, node, state):
        return nodety is phpast.Class

    def visit(self, node, state):
        stoponthis = False
        newobj = None
        
        # global parent scope
        parentscope = self.locate_scope(node, state)
        
        if not getattr(node, '_object', False):
            # Start traveling node when instance is created
            node._parent_scope = parentscope
            state.classes[node.name] = node
            stoponthis = True
        else:
            # new instance has been created
            # Create new Scope and push it onto the stack
            newscope = Scope(node, parent_scope=parentscope, is_root=True)
            
            # add builtins to scope
            newscope._builtins = dict(
                    ((uv, VariableDef(uv, -1, newscope)) for uv in VariableDef.USER_VARS))
                            
            state.scopes.append(newscope)
            
            newobj = Obj(node.name, node.lineno, newscope, node._object_var, ast_node=node)
            
            # create $this var for internal method calling
            this_var = VariableDef('$this', node.lineno, newscope)
            this_var._obj_def = newobj
            newscope.add_var(this_var)
            
            # add ObjDef to VarDef, this way we can trace method call back to the correct instance
            node._object_var._obj_def = newobj            
            
            node._scope = newscope
            state.objects[node._object_var.name] = node._object_var

        return newobj, stoponthis

        