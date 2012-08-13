'''
definitions.py

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

# Potentially Vulnerable Functions Database
SENSITIVE_FUNCTIONS = {
    'OS_COMMANDING':
        ('system', 'exec', 'shell_exec'),
    'XSS':
        ('echo', 'print', 'printf', 'header'),
    'FILE_INCLUDE':
        ('include', 'require'),
    'FILE_DISCLOSURE':
        ('file_get_contents', 'file', 'fread', 'finfo_file'),
    'SQL_INJECTION':
        ('mysql_query', 'mysqli_query'),
    }

# Securing Functions Database
VALIDATION_FUNCTIONS = {
    'OS_COMMANDING':
        ('escapeshellarg', 'escapeshellcmd'),
    'XSS':
        ('htmlentities', 'htmlspecialchars'),
    'SQL_INJECTION':
        ('addslashes', 'mysql_real_escape_string', 'mysqli_escape_string',
         'mysqli_real_escape_string')
    }

def get_vulnty_for(fname):
    '''
    Return the vuln type for the given function name `fname`. Return None
    if no vuln type is associated.
    
    @param fname: Function name
    '''
    for vulnty, pvfnames in SENSITIVE_FUNCTIONS.iteritems():
        if any(fname == pvfn for pvfn in pvfnames):
            return vulnty
    return None

def get_vulnty_for_sec(sfname):
    '''
    Return the the vuln. type secured by securing function `sfname`.
    
    @param sfname: Securing function name 
    '''
    for vulnty, sfnames in VALIDATION_FUNCTIONS.iteritems():
        if any(sfname == sfn for sfn in sfnames):
            return vulnty
    return None
