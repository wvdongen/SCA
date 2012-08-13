'''
test_basic_ast_features.py

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

from pymock import PyMockTestCase
from core.sca_core import PhpSCA
from core.exceptions.syntax_error import CodeSyntaxError


class TestPHPSCA(PyMockTestCase):
    '''
    Test unit for PHP Static Code Analyzer
    '''
    
    def setUp(self):
        PyMockTestCase.setUp(self)

    def test_var_comp_operators(self):
        code = '''
        <?php
            $var0 = 'bleh';
            $var1 = $_GET['param'];
            $var2 = 'blah';
        ?>
        '''
        analyzer = PhpSCA(code)
        vars = analyzer.get_vars(usr_controlled=False)
        
        code2 = '''
        <?php
            $var0 = 'bleh';
            
            $var1 = 'blah';
            if ($x){
                $var2 = $_POST['param2'];
            }
            else{
                $var2 = 'blah'.'blah'; 
            }
        ?>
        '''
        analyzer = PhpSCA(code2)
        vars2 = analyzer.get_vars(usr_controlled=False)
        
        c1_var0 = vars[0]
        c2_var0 = vars2[0]
        c1_var0._scope = c2_var0._scope
        self.assertTrue(c2_var0 == c1_var0)
        
        c1_var1 = vars[1]
        c2_var1 = vars2[1]
        c2_var1._scope = c1_var1._scope
        self.assertTrue(c2_var1 > c1_var1)
        
        c1_var2 = vars[2]
        c2_var2 = vars2[2]
        self.assertTrue(c2_var2 > c1_var2)
    
    def test_syntax_error(self):
        invalidcode = '''
        <?php
          $var1 == escapeshellarg($_ GET['param']);
        ?>
        '''
        self.assertRaises(CodeSyntaxError, PhpSCA, invalidcode)

