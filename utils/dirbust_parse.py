#!/usr/bin/env python3

# dirbust_parse.py - Parse OWASP Dirbuster results into a CSV file

# Imports
import sys

# Print results
def getResults(output):

    # Variables
    start = False
    stop = False
    target = ''
    response_code = ''
    csv_headers = 'Response,Found'
    results = []

    # Parse results
    print('[*] Parsing',output)
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
                        if 'found with a ' in line:
                            if (' response:') or (' responce:') in line:
                                response_code = line.split('found with a ')[1]
                                if ' response:' in response_code:
                                    response_code = response_code.split(' response:')[0]
                                elif ' responce:' in response_code:
                                    response_code = response_code.split(' responce:')[0]
                        else:
                            if response_code:
                                if len(line) > 0:
                                    if 'Files found during testing:' not in line:
                                        results.append([response_code,str(line.rstrip())])

    # Sort results
    results.sort(reverse=False, key=lambda found: found[1])
    results.sort(reverse=False, key=lambda response: response[0])

    # Write results to disk
    with open(output+'.csv','w') as output_file:
        output_file.write(csv_headers)
        output_file.write('\n')
        for result in results:
            output_file.write(','.join(result))
            output_file.write('\n')

    # Print number of results
    print('[*] Wrote results to',output+'.csv')
    print('    [*] Found',len(results),'results')

# Validate arguments
try:
    getResults(sys.argv[1])
except IndexError:
    print(' [*] Usage: dirbust_parse.py <Dirbuster report file>')
