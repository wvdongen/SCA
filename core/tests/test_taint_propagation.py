'''
test_taint_propagation.py

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


class TestTaintPropagation(PyMockTestCase):
    '''
    Test unit for PHP Static Code Analyzer
    '''
    
    def setUp(self):
        PyMockTestCase.setUp(self)

    def test_vars(self):
        code = '''
            <?
              $foo = $_GET['bar'];
              $spam = $_POST['blah'];
              $eggs = 'blah' . 'blah';
              if ($eggs){
                  $xx = 'waka-waka';
                  $yy = $foo;
              }
            ?>
            '''
        analyzer = PhpSCA(code)
        # Get all vars
        vars = analyzer.get_vars(usr_controlled=False)
        self.assertEquals(5, len(vars))
        # Get user controlled vars
        usr_cont_vars = analyzer.get_vars(usr_controlled=True)
        self.assertEquals(3, len(usr_cont_vars))
        # Test $foo
        foovar = usr_cont_vars[0]
        self.assertEquals('$foo', foovar.name)
        self.assertTrue(foovar.controlled_by_user)
        self.assertFalse(foovar.is_root)
        self.assertTrue(foovar.parents)
        # Test $spam
        spamvar = usr_cont_vars[1]
        self.assertEquals('$spam', spamvar.name)
        # Test $spam
        yyvar = usr_cont_vars[2]
        self.assertEquals('$yy', yyvar.name)
    
    def test_override_var(self):
        code = '''
        <?php
            $var1 = $_GET['param'];
            $var1 = 'blah';
            $var2 = escapeshellarg($_GET['param2']);
            $var3 = 'blah';
            if ($x){
                $var3 = $_POST['param2'];
            }
            else{
                $var3 = 'blah'.'blah'; 
            }
        ?>
        '''
        analyzer = PhpSCA(code)
        vars = analyzer.get_vars(usr_controlled=False)
        
        # 'var1' is safe
        var1 = vars[0]
        self.assertFalse(var1.controlled_by_user)

        # 'var2' is controlled by the user but is safe for OS-Commanding
        var2 = vars[1]
        self.assertTrue(var2.controlled_by_user)
        self.assertFalse(var2.is_tainted_for('OS_COMMANDING'))
        
        # 'var3' must still be controllable by user
        var3 = vars[2]
        self.assertTrue(var3.controlled_by_user)
    
    def test_vars_dependencies(self):
        code = '''
        <?
          $x1 = 'waca-waka';
          $x2 = '#!~?#*' + $x1;
          $x3 = func($x2);
          $y = $_COOKIES['1'];
          $y2 = 'ls ' . $y;
          $z = $x2 + $x3;
        ?>
        '''
        analyzer = PhpSCA(code)
        vars = analyzer.get_vars(usr_controlled=False)
        vars.sort(cmp=lambda x, y: cmp(x.lineno, y.lineno))
        x1deps, x2deps, x3deps, ydeps, y2deps, zdeps = \
                            [[vd.name for vd in v.deps()] for v in vars]

        self.assertEquals([], x1deps)
        self.assertEquals(['$x1'], x2deps)
        self.assertEquals(['$x2', '$x1'], x3deps)
        self.assertEquals(['$_COOKIES'], ydeps)
        self.assertEquals(['$y', '$_COOKIES'], y2deps)
        self.assertEquals(['$x2', '$x3', '$x1'], zdeps)

    def test_variable_no_taint_taint(self):
        code = '''
        <?
          $foo = htmlspecialchars($_GET[1]) . $_GET[2];
        ?>
        '''
        analyzer = PhpSCA(code)
        vars = analyzer.get_vars()
        
        foo_var = vars[0]
        self.assertTrue(foo_var.controlled_by_user)
        self.assertTrue(foo_var.is_tainted_for('XSS'), code)
        
    def test_variable_taint_no_taint(self):
        code = '''
        <?
          $foo = $_GET[2] . htmlspecialchars($_GET[1]);
        ?>
        '''
        analyzer = PhpSCA(code)
        vars = analyzer.get_vars()
        
        foo_var = vars[0]
        self.assertTrue(foo_var.controlled_by_user)
        self.assertTrue(foo_var.is_tainted_for('XSS'))

        
    def test_variable_taint_taint(self):
        code = '''
        <?
          $foo = $_GET[2] .$_GET[1];
        ?>
        '''
        analyzer = PhpSCA(code)
        vars = analyzer.get_vars()
        
        foo_var = vars[0]
        self.assertTrue(foo_var.controlled_by_user)
        self.assertTrue(foo_var.is_tainted_for('XSS'))

    def test_variable_no_taint_no_taint(self):
        code = '''
        <?
          $foo = htmlspecialchars($_GET[2]) . htmlspecialchars($_GET[1]);
        ?>
        '''
        analyzer = PhpSCA(code)
        vars = analyzer.get_vars()
        
        foo_var = vars[0]
        self.assertTrue(foo_var.controlled_by_user)
        self.assertFalse(foo_var.is_tainted_for('XSS'))

    def test_variable_no_taint_taint_no_taint_same(self):
        code = '''
        <?
          $foo = htmlspecialchars($_GET[1]) . $_GET[1] . htmlspecialchars($_GET[1]);
        ?>
        '''
        analyzer = PhpSCA(code)
        vars = analyzer.get_vars()
        
        foo_var = vars[0]
        self.assertTrue(foo_var.controlled_by_user)
        self.assertTrue(foo_var.is_tainted_for('XSS'), code)

    def test_variable_no_taint_taint_no_taint_diff(self):
        code = '''
        <?
          $foo = htmlspecialchars($_GET[1]) . $_GET[2] . htmlspecialchars($_GET[3]);
        ?>
        '''
        analyzer = PhpSCA(code)
        vars = analyzer.get_vars()
        
        foo_var = vars[0]
        self.assertTrue(foo_var.controlled_by_user)
        self.assertTrue(foo_var.is_tainted_for('XSS'), code)
