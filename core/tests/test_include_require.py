'''
test_scope.py

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
import os
from pymock import PyMockTestCase
from core.sca_core import PhpSCA
from core.scope import Scope

class TestScope(PyMockTestCase):
    
    TEST_DIR = os.path.join('core','tests','test_include_require')
    
    def setUp(self):
        PyMockTestCase.setUp(self)
        self.scope = Scope(None, parent_scope=None)
    
    def test_has_builtin_container(self):
        self.assertEquals(
                    dict, type(getattr(self.scope, '_builtins', None)))
    
    def test_add_var(self):
        self.assertRaises(ValueError, self.scope.add_var, None)
    
    def test_include_require_1(self):
        
        analyzer = PhpSCA(infile = os.path.join(self.TEST_DIR, '1', 'a.php'))
        
        echo = analyzer.get_func_calls()[1]
        self.assertTrue('XSS' in echo.vulntypes)
        #self.assertEquals('core/tests/test_include_require/1/a.php', echo.get_file_name())
        self.assertEquals('core' + os.sep + 'tests' + os.sep + 'test_include_require' + os.sep + '1' + os.sep + 'a.php', echo.get_file_name())
        
        vulns = analyzer.get_vulns()
        self.assertEquals('core' + os.sep + 'tests' + os.sep + 'test_include_require' + os.sep + '1' + os.sep + 'b.php', vulns['XSS'][0][-1].get_file_name())
        self.assertEquals(2, vulns['XSS'][0][-1].lineno)
    
    def test_include_require_2(self):
        
        analyzer = PhpSCA(infile = os.path.join(self.TEST_DIR, '2', 'a.php'))
        
        echo = analyzer.get_func_calls()[1]
        self.assertTrue('XSS' in echo.vulntypes)
        self.assertEquals('core' + os.sep + 'tests' + os.sep + 'test_include_require' + os.sep + '2' + os.sep + 'b.php', echo.get_file_name())
        
        vulns = analyzer.get_vulns()
        self.assertEquals('core' + os.sep + 'tests' + os.sep + 'test_include_require' + os.sep + '2' + os.sep + 'a.php', vulns['XSS'][0][-1].get_file_name())
        self.assertEquals(2, vulns['XSS'][0][-1].lineno)
        