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


class TestSamate(PyMockTestCase):
    '''
    Based on http://samate.nist.gov/SRD/view.php?tsID=31
    
    Test Suite #31: Web Applications in PHP
    
        Created by Romain Gaucher on 2006-10-24
        Size: 15 test cases
        Description: The PHP Test cases
    '''
    SAMATE_TEST_DIR = os.path.join('core','tests','samate')
    SAMATE_MANIFEST = os.path.join('core','tests','samate','manifest.xml')
    
    def setUp(self):
        PyMockTestCase.setUp(self)
    
    def _from_xml_get_test_cases(self):
        xp = XMLParser()
        parser = etree.XMLParser(target=xp)
        test_cases = etree.fromstring(file(self.SAMATE_MANIFEST).read(), parser)
        return test_cases
    
    def test_samate(self):
        for test_case in self._from_xml_get_test_cases():
            vuln_file = os.path.join(self.SAMATE_TEST_DIR, test_case.vuln_file)
            analyzer = PhpSCA(infile=vuln_file)
            print analyzer.get_vulns()

class XMLTestCase(object):
    vuln_type = None
    vuln_line_no = None
    vuln_file = None

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
        if tag == 'file':
            self.vuln_file = attrib['path']
        elif tag == 'flaw':
            xtc = XMLTestCase()
            xtc.vuln_name = attrib['name']
            xtc.vuln_line_no = attrib['line']
            xtc.vuln_file = self.vuln_file
            self.tests.append(xtc)
    
    def close(self):
        return self.tests  