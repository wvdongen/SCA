'''
test_samate.py

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
from lxml import etree
from pymock import PyMockTestCase
from core.sca_core import PhpSCA


class TestSamate(object):
    '''
    Based on http://samate.nist.gov/SRD/view.php?tsID=31
    
    Test Suite #31: Web Applications in PHP
    
        Created by Romain Gaucher on 2006-10-24
        Size: 15 test cases
        Description: The PHP Test cases
    '''
    SAMATE_TEST_DIR = os.path.join('core','tests','samate')
    SAMATE_MANIFEST = os.path.join('core','tests','samate','manifest.xml')
    
    def _from_xml_get_test_cases(self):
        xp = XMLParser()
        parser = etree.XMLParser(target=xp)
        test_cases = etree.fromstring(file(self.SAMATE_MANIFEST).read(), parser)
        return test_cases
    
    def test_samate_generator(self):
        for test_case in self._from_xml_get_test_cases():
            yield self.analyze_, test_case
    
    def analyze_(self, test_case):
        for input_file_obj in test_case.files:
            input_file_name = os.path.join(self.SAMATE_TEST_DIR, input_file_obj.file)
            analyzer = PhpSCA(infile=input_file_name)
            
            identified_vulns = []
            
            for vuln_type in analyzer.get_vulns():
                for vuln_func_call in analyzer.get_vulns()[vuln_type]:
                    identified_vulns.append((vuln_type, vuln_func_call[0]._lineno))
            
            expected_vulns = []
            for flaw in input_file_obj.flaws:
                sca_name = SAMATE_TO_SCA[flaw.vuln_name]
                expected_vulns.append((sca_name, int(flaw.vuln_line_no)))
            
            #print set(expected_vulns), set(identified_vulns)
            assert set(expected_vulns) == set(identified_vulns)

class XMLTestCase(object):
    files = []
    
    def __init__(self, test_id):
        self.test_id = test_id
        self.files = []
    
    def __repr__(self):
        return 'XMLTestCase for id %s' % self.test_id

class TestFile(object):
    flaws = []
    
    def __init__(self, file_name):
        self.file = file_name
        self.flaws = []
    
class Flaw(object):
    def __init__(self, vuln_name, vuln_line_no):
        self.vuln_name = vuln_name
        self.vuln_line_no = vuln_line_no

    def __str__(self):
        return '%s at line number %s' % (self.vuln_name, self.vuln_line_no)
    
class XMLParser:
    tests = []
    def start(self, tag, attrib):
        '''
        <testcase id="1938">
            <file path="000/001/938/xss_lod1.phps" language="PHP">
                <flaw line="19" name="CWE-079: Failure to Sanitize Directives in a Web Page (Cross-site scripting XSS)"/>
                <flaw line="21" name="CWE-079: Failure to Sanitize Directives in a Web Page (Cross-site scripting XSS)"/>
            </file>
        </testcase>
        '''
        if tag == 'testcase':
            self.current_test_case = XMLTestCase(attrib['id'])
            self.tests.append(self.current_test_case)
            
        elif tag == 'file':
            self.current_file = TestFile(attrib['path'])
            self.current_test_case.files.append(self.current_file)
            
        elif tag == 'flaw':
            vuln_name = attrib['name']
            vuln_line_no = attrib['line']
            flaw = Flaw(vuln_name, vuln_line_no)
            self.current_file.flaws.append(flaw)
    
    def close(self):
        return list(set(self.tests))

SAMATE_TO_SCA = {
                 'CWE-079: Failure to Sanitize Directives in a Web Page (Cross-site scripting XSS)':'XSS',
                 'CWE-089: Failure to Sanitize Data within SQL Queries (SQL injection)':'SQL_INJECTION',
                 'CWE-326: Weak Encryption':'WEAK_CRYPTO',
                 'CWE-098: Insufficient Control of Filename for Include/Require Statement in PHP Program (PHP File Inclusion)':'FILE_INCLUDE',
                 }