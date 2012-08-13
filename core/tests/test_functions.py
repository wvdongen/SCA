'''
test_functions.py

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


class TestClasses(PyMockTestCase):
    '''
    Test unit for PHP Static Code Analyzer
    '''
    
    def setUp(self):
        PyMockTestCase.setUp(self)
    
    def test_function(self):
        code = '''
        <?php
        $outside = $_GET[1];
        
        function test($var1, $var2, $var3 = 'foo') {
            echo $_GET['var'];
            echo $var1;
            
            $a = $var2;
            $b = $a;
            if ($spam == $eggs) {
                system($b);
            }
            echo $var3;
            echo $outside;
            $inside = $_GET[1];
        }  
        function dead_code($var1, $var2) {
            echo $_GET[1];
        }
        $foo = $_POST['something'];
        test($foo, $outside, $_GET[1]);
        test($_GET[1], 'param2');
        echo $inside;
        ?>'''
        analyzer = PhpSCA(code)
        
        vulns = analyzer.get_vulns()
        self.assertEquals(5, len(vulns['XSS']))
        self.assertEquals(1, len(vulns['OS_COMMANDING']))
        
        echo_GET, echo_var1, sys_b, echo_var3, echo_outside, echo_dead_var1, echo_inside = analyzer.get_func_calls()
        
        # Function test
        
        # Direct $_GET - 2 vulnerabilities
        self.assertEquals(2, len(echo_GET._vulntraces))    
        self.assertEquals('XSS', echo_GET._vulntraces[0][0]) #first function call
        self.assertEquals('XSS', echo_GET._vulntraces[1][0]) #second function call
        self.assertTrue('XSS' in echo_GET.vulntypes) # Last traveled call (that is the second function call)      
        
        # echo $var1 - 2 vulnerabilities with trace
        self.assertEquals(2, len(echo_var1._vulntraces))
        self.assertEquals('XSS', echo_var1._vulntraces[0][0])
        self.assertEquals('$foo', echo_var1._vulntraces[0][-1].name)
        self.assertEquals(21, echo_var1._vulntraces[0][-1].lineno)
        self.assertEquals('XSS', echo_var1._vulntraces[1][0])
        self.assertEquals('$_GET__$temp_anon_var$_', echo_var1._vulntraces[1][-1].name)
        self.assertEquals(23, echo_var1._vulntraces[1][-1].lineno)
        
        # system call - 1 trace
        self.assertEquals(1, len(sys_b._vulntraces))
        self.assertEquals('OS_COMMANDING', sys_b._vulntraces[0][0])
        self.assertEquals('$outside', sys_b._vulntraces[0][-1].name)
        self.assertEquals(3, sys_b._vulntraces[0][-1].lineno)
        
        # echo var3 - 1 trace
        self.assertTrue(1, len(echo_var3._vulntraces))
        self.assertTrue('XSS', echo_var3._vulntraces[0][0])
        self.assertTrue('$_GET__$temp_anon_var$_', echo_var3._vulntraces[0][-1].name)
        self.assertTrue(22, echo_var3._vulntraces[0][-1].lineno)
        
        # echo $outside - outside scope, not vulnerable
        self.assertEquals(0, len(echo_outside._vulntraces))
        
        # Function dead - Scope is inactive (dead code), no vulnerabilities
        self.assertTrue(analyzer.get_function_decl()['dead_code']._scope._dead_code)
        self.assertEquals(0, len(echo_dead_var1._vulntraces))
        
        # Inside var - function scope test
        self.assertEquals(0, len(echo_inside._vulntraces)) 
