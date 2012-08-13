'''
test_classes.py

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

    
    def test_classes_1(self):
        code = '''
        <?php
        class A {
            private $prop1 = 'ok';
            
            function foo($var1) {
                echo $_GET[1];
                $this->prop1 = $var1;
            }
            
            function bar($prop2 = 'default') {
                echo $this->prop1;
                $this->prop2 = $prop2;
            }
            
            function baz() {
                if (1) {
                    system($this->prop2);
                }
            }
        }
        
        $obj1 = new A();
        $obj1->foo($_GET[1]); #XSS
        $obj1->bar(); #XSS
        $obj1->baz();
        
        $awsome = $_POST[1];
        $obj2 = new A();
        $obj2->foo('test'); #XSS
        $obj2->bar($awsome);
        $obj2->baz(); #OS COMMANDING
        
        $obj1->bar(); #XSS again
        ?>'''
        analyzer = PhpSCA(code)
        vulns = analyzer.get_vulns()
        
        self.assertEquals(4, len(vulns['XSS']))
        self.assertEquals(1, len(vulns['OS_COMMANDING']))
        
        self.assertEquals(18, vulns['OS_COMMANDING'][0][0].lineno)
        self.assertEquals('$awsome', vulns['OS_COMMANDING'][0][-1].name)
        self.assertEquals(28, vulns['OS_COMMANDING'][0][-1].lineno)
        
        objects = analyzer.get_objects();
        self.assertTrue('$obj1' and '$obj2' in objects)

    def test_classes_2(self):
        code = '''
        <?php
        class A {
        
            function foo($var) {
                $this->prop = $var;
                $this->baz();
            }
            
            function bar() {
                include($this->prop);
            }
            
            function baz() {
                $this->bar();
                echo $_GET[1];
            }
        }
        
        $obj1 = new A();
        $obj1->foo($_GET[1]); # XSS, FILE
        $obj1->bar('clean'); # FILE
        
        $obj2 = new A();
        $obj2->bar(); # Clean
        $obj2->baz(); # XSS
        ?>
        '''

        analyzer = PhpSCA(code)
        vulns = analyzer.get_vulns()
                            
        self.assertEquals(2, len(vulns['XSS']))
        self.assertEquals(2, len(vulns['FILE_INCLUDE']))
    
    def test_classes_3(self):
        code = '''
        <?php
        
        class A {
        
            function foo($var) {
                $this->prop = $var;
            }
            
            function bar() {
                $var = 'bla' . somefunc($this->prop);
                echo $var;
            }
            
        }
        
        $obj1 = new A();
        $obj1->foo($_GET[1]);
        $obj1->bar();
        ?>
        '''
        # Poperty to var test
        analyzer = PhpSCA(code)
        vulns = analyzer.get_vulns() 
        self.assertEquals(1, len(vulns['XSS']))   
