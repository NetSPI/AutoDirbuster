#!/usr/bin/env python3

# dirbust_read.py - Pretty print OWASP Dirbuster results

# Imports
import sys

# Print results
def getResults(output):
    start = False
    stop = False
    target = ''
    with open(output,'r') as data:
        for line in data:
            line = line.rstrip()
            if 'Errors encountered during testing:' in line:
                stop = True
            if line.startswith('http'):
                if '://' in line:
                    if 'http://www.owasp.org/index.php/Category:OWASP_DirBuster_Project' != line:
                        target = line.strip()
                        start = True
            if start:
                if not stop:
                    if line != '--------------------------------':
                        print('\t| '+str(line))
                        if target in line:
                            print('\t| '+str('--------------------------------'))
            if 'Note that dirbust was automatically ended after user specified timeout of' in line:
                if stop:
                    print('\t| '+str(line))

try:
    getResults(sys.argv[1])
except IndexError:
    print(' [*] Usage: dirbust_read.py <Dirbuster report file>')
