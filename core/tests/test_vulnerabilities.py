'''
test_vulnerabilities.py

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


class TestVulnerabilities(PyMockTestCase):
    '''
    Test unit for PHP Static Code Analyzer
    '''
    
    def setUp(self):
        PyMockTestCase.setUp(self)

    def test_vuln_func_get_sources_1(self):
        code = '''
        <?
            $eggs = $_GET['bar'];
            $foo = func($eggs);
            $a = 'ls ' . $foo; 
            exec($a);
        ?>
        '''
        analyzer = PhpSCA(code)
        execfunc = analyzer.get_func_calls(vuln=True)[0]
        self.assertTrue(
            len(execfunc.vulnsources) == 1 and 'bar' in execfunc.vulnsources)
    
    def test_vuln_func_get_sources_2(self):
        code = '''<? echo file_get_contents($_REQUEST['file']); ?>'''
        analyzer = PhpSCA(code)
        execfunc = analyzer.get_func_calls(vuln=True)[0]
        self.assertTrue(
            len(execfunc.vulnsources) == 1 and 'file' in execfunc.vulnsources)
    
    def test_vuln_func_get_sources_3(self):
        code = '''<? system($_GET['foo']); ?>'''
        analyzer = PhpSCA(code)
        execfunc = analyzer.get_func_calls(vuln=True)[0]
        self.assertTrue(
            len(execfunc.vulnsources) == 1 and 'foo' in execfunc.vulnsources)
    
    def test_vuln_functions_1(self):
        code = '''
        <?php
          $var = $_GET['bleh'];
          if ($x){
              $var = 2;
              // not vuln!
              system($var);
          }
          // vuln for OS COMMANDING!
          system($var);
        ?>
        '''
        analyzer = PhpSCA(code)
        sys1, sys2 = analyzer.get_func_calls()
        # First system call
        self.assertEquals(0, len(sys1.vulntypes))
        # Second system call
        self.assertTrue('OS_COMMANDING' in sys2.vulntypes)
    
    def test_vuln_functions_2(self):
        code = '''
        <?
          $foo = $_GET['bar'];
          system('ls ' . $foo);
          echo file_get_contents($foo);
        ?>
        '''
        analyzer = PhpSCA(code)
        syscall, echocall = analyzer.get_func_calls()
        self.assertTrue('OS_COMMANDING' in syscall.vulntypes)
        self.assertTrue('FILE_DISCLOSURE' in echocall.vulntypes)
    
    def test_vuln_functions_3(self):
        code = '''
        <?php
          $var1 = escapeshellarg($_GET['param']);
          system($var1);
          system(escapeshellarg($_GET['param']));
          system(myfunc(escapeshellarg($_GET['param'])));
        ?>
        '''
        analyzer = PhpSCA(code)
        escapecall, syscall1, syscall2, syscall3 = analyzer.get_func_calls()
        # Both must be SAFE!
        self.assertEquals(0, len(syscall1.vulntypes))
        self.assertEquals(0, len(syscall2.vulntypes))
        self.assertEquals(0, len(syscall3.vulntypes))
    
    def test_vuln_functions_4(self):
        code = '''
        <?
        $foo = $_GET['foo'];
        if ( $spam == $eggs ){
             $foo = 'ls';
             system($foo);
        }
        else{
             echo $foo;
             system($foo);
        }
        ?>
        '''
        analyzer = PhpSCA(code)
        sys1, echo, sys2 = analyzer.get_func_calls()
        self.assertEquals([], sys1.vulntypes)
        self.assertTrue('XSS' in echo.vulntypes)
        self.assertTrue('OS_COMMANDING' in sys2.vulntypes)
    
    def test_vuln_functions_5(self):
        code = '''<?
        $foo = 1;
        if ( $spam == $eggs ){
             $foo = $_GET['foo'];
        }
        else{
             $foo = 1;
        }
        include($foo);
        ?>'''
        inccall = PhpSCA(code).get_func_calls()[0]
        self.assertTrue('FILE_INCLUDE' in inccall.vulntypes)
        
    def test_assignment_sqli(self):
        code = '''
        <?php
        $q = $_POST['q'];
        $result = mysql_query("SELECT * FROM books WHERE Author = '$q'");
        ?>'''
        self.assertTrue('SQL_INJECTION' in PhpSCA(code).get_vulns())
        
    def test_multiple_parents_vuln_trace(self):
        code = '''<?php
        $a = htmlspecialchars($_GET[1]) . $_GET[1];
        echo $_GET[2] . $a;
        ?>'''
        vulns = PhpSCA(code).get_vulns()
        self.assertEquals(2, len(vulns['XSS']))
        self.assertEquals(3, vulns['XSS'][0][-1].lineno)
        self.assertEquals(2, vulns['XSS'][1][-1].lineno)
        