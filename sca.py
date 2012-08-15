#!/usr/bin/env python
import sys
import getopt

from core.sca_core import PhpSCA

usage_doc = '''sca - PHP static code analyzer

Usage:

    ./sca.py -h
    ./sca.py -i <input_file_1.php],[input_file_n.php]>

Options:

    -h or --help
        Display this help message.
        
    -i or --input-files=
        Input files to analyze for vulnerabilities.

For more info visit https://github.com/wvdongen/SCA
'''

def usage():
    print usage_doc

def main():
    try:
        long_options = ['help', 'input-files=']
        opts, _ = getopt.getopt(sys.argv[1:], "hi:", long_options)
    except getopt.GetoptError:
        # print help information and exit:
        usage()
        return -3
    
    input_file_list = None
    
    for o, a in opts:
        if o in ('-h', '--help'):
            usage()
            return 0
        if o in ('-i', '--input-files='):
            input_file_list = a.split(',')
    
    if input_file_list is None:
        usage()
        return -3
                
    for input_file in input_file_list:
        analyzer = PhpSCA(infile=input_file)
        
        for vulnerability_type in analyzer.get_vulns():
            print vulnerability_type
            for vulnerability in analyzer.get_vulns()[vulnerability_type]:
                print '    ', vulnerability
        
        if len(analyzer.get_alerts()) > 0:
            print ''
            print 'Alerts:'
            for alert in analyzer.get_alerts():
                print alert

if __name__ == "__main__":
    err_code = main()
    sys.exit(err_code)
    

