#!/usr/bin/env python3

# AutoDirbuster - Automatically run and save Dirbuster scans for multiple IPs

# Imports
import argparse
import sys
import socket
import requests
import subprocess
import signal
import os
import dns.resolver
import dns.reversename
from requests.packages.urllib3.exceptions import InsecureRequestWarning


# Configure requests to suppress SSL validation warning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


# Control application flow
def main(input_file, gnmap, wordlist, extensions, threads, recursive, startpoint, dns, single_target_mode, dirbust_timeout, verbose, dirbuster_directory, force, debug, keep):
    # Variables
    targets = []
    open_targets = []
    closed_targets = []
    timedout_targets = []
    target_files = []
    target_status_count = 0

    # Get list of IP:port
    if gnmap:
        targets = gnmapToIPport(input_file)
    elif single_target_mode:
        targets.append(input_file)
    else:
        with open(input_file, 'r') as data:
            line_count = 0
            for line in data:
                line_count += 1
                line = line.rstrip().lstrip()
                if ':' in line:
                    try:
                        int(line.split(':')[1])
                        targets.append(line)
                    except ValueError:
                        print(sys.argv[0], ': error: Incorrectly formatted line on '+str(input_file)+':'+str(line_count))
                else:
                    print(sys.argv[0], ': error: Incorrectly formatted line on '+str(input_file)+':'+str(line_count))

    # Resolve IP to hostname if applicable
    if dns:
        resolved_targets = []
        for target in targets:
            host = target.split(':')[0]
            port = target.split(':')[1]
            print('[*] Resolving '+str(host)+' '*25, end='\r')
            try:
                socket.inet_aton(host)
                host = resolveHostname(host)
            except OSError:
                pass
            resolved_targets.append(str(host)+':'+str(port))
        targets = resolved_targets

    # Determine if port is open and if service is HTTP or HTTPS, then run Dirbuster
    for target in targets:
        # Local variables
        target_status_count += 1
        target_output = ''
        file_exists = False

        # Test if port is open
        print('['+str(target_status_count)+'/'+str(len(targets))+'] '+str(target)+' '*25)
        status = isPortOpen(target)
        if status:

            # Test if service is HTTP/HTTPS
            proto = serviceQuery(target, verbose)
            if proto:
                open_targets.append(target)

                # Configure params for dirbuster launch
                scan_success = False
                url_target = str(proto)+"://"+str(target)
                output = 'DirBuster-Report-'+str(target.replace(':', '-')+'.txt')
                csv_output = output.replace('.txt', '.csv')
                dirbust_command = [ 'java',
                                    '-jar',
                                    str(dirbuster_directory)+'/DirBuster.jar',
                                    '-H',
                                    '-t',
                                    str(threads),
                                    '-l',
                                    wordlist,
                                    '-u',
                                    str(url_target)+'/',
                                    '-e',
                                    str(extensions),
                                    '-r',
                                    str(output)
                                  ]
                if not recursive:
                    dirbust_command.append('-R')
                if startpoint != '/':
                    dirbust_command.append('-s')
                    dirbust_command.append('"'+str(startpoint)+'"')

                # Check if file exists
                # Dirbuster will do this check anyway and not checking here causes script to crash
                if force:
                    if os.path.isfile(output):
                        os.remove(output)
                    if os.path.isfile(csv_output):
                        os.remove(csv_output)
                else:
                    file_exists = os.path.isfile(output) + os.path.isfile(csv_output)

                # Launch Dirbuster
                if debug:
                    print('[DEBUG] Subprocess command:', ' '.join(dirbust_command),'\n')
                if not file_exists:
                    # Scan timeout
                    if dirbust_timeout:
                        # Start process
                        proc = subprocess.Popen(dirbust_command, stderr=subprocess.DEVNULL)
                        try:
                            # Set timeout value
                            try:
                                outs, errs = proc.communicate(timeout=dirbust_timeout)
                            except KeyboardInterrupt:
                                # Detect OS and use appropriate signal
                                if os.name == 'posix':
                                    proc.send_signal(signal.SIGINT)
                                elif os.name == 'nt':
                                    proc.send_signal(signal.CTRL_C_EVENT)
                        except subprocess.TimeoutExpired:
                            print('[!] Timeout value of '+str(int(dirbust_timeout/60))+' minutes reached, killing scan')
                            try:
                                # Detect OS and use appropriate signal
                                if os.name == 'posix':
                                    proc.send_signal(signal.SIGINT)
                                elif os.name == 'nt':
                                    proc.send_signal(signal.CTRL_C_EVENT)
                            except KeyboardInterrupt:
                                pass
                            try:
                                outs, errs = proc.communicate()
                            except KeyboardInterrupt:
                                pass
                            # Set script vars based on timeout
                            scan_success = False
                            timedout_targets.append(target)
                            # Append timed out target to file
                            with open('timedout_targets.txt', 'a') as timed_file:
                                timed_file.write('\n'+str(target))
                            # Specify in results file that dirbust was incomplete
                            with open(output, 'a') as dirbust_output:
                                dirbust_output.write('\n\n')
                                dirbust_output.write('--------------------------------\n')
                                dirbust_output.write('Note that dirbust was automatically ended after user specified timeout of ' + str(int(dirbust_timeout/60)) + ' minutes\n\n')
                        scan_success = True
                    # No scan timeout
                    else:
                        # Start process
                        proc = subprocess.Popen(dirbust_command, stderr=subprocess.DEVNULL)
                        try:
                            outs, errs = proc.communicate()
                        except KeyboardInterrupt:
                            pass
                        scan_success = True
                    # Parse results file into CSV
                    try:
                        parseResults(output, keep)
                    except IOError:
                        pass
                    except FileNotFoundError:
                        pass
                    target_files.append(output)
                    print('\n')
                # Error handling
                else:
                    print('Report file already exists, skipping target\n\n')
            # Service is not HTTP based
            else:
                closed_targets.append(target)
                print('Service not HTTP, skipping target\n\n')
        # Port detected as closed
        else:
            closed_targets.append(target)
            print('Port detected as closed, skipping target\n\n')

    # Append newline to timed out targets file
    with open('timedout_targets.txt','a') as timed_file:
        timed_file.write('\n')


# Resolve IP to hostname
def resolveHostname(target):
    try:
        qname = dns.reversename.from_address(target)
        answer = dns.resolver.query(qname, 'PTR')
        if answer:
            return str(answer[0])[:-1]
        else:
            return target
    except dns.exception.DNSException:
        return target


# Determine if service is HTTP and if SSL is required
def serviceQuery(target, verbose):
    # Local variables
    connect = False
    success_proto = ''
    user_agent = {'User-Agent' : 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:61.0) Gecko/20100101 Firefox/61.0'}
    ssl_error_strings = [  "Reason: You're speaking plain HTTP to an SSL-enabled server port.",
                            "It looks like you are trying to access MongoDB over HTTP on the native driver port.",
                            "The plain HTTP request was sent to HTTPS port",
                            "Client sent an HTTP request to an HTTPS server.",
                            "This combination of host and port requires TLS."
                        ]

    # Test if HTTP and if SSL
    if verbose:
        print('Querying service')
    for proto in ['http', 'https']:
        try:
            if verbose:
                print('    Trying:', proto)

            # 5 second timeout seems to be a good balance; any longer and target
            # likely won't respond well to dirbusting, any shorter and a valid
            # target might be unintentionally marked as offline
            req = requests.get(proto + '://' + target, verify=False, timeout=5, headers=user_agent, allow_redirects=False)

            # If no connection exception is thrown
            connect = True
            success_proto = proto

            # If SSL error is given from web server (eg: Nginx)
            if proto == 'http':
                for message in ssl_error_strings:
                    if message in req.text:
                        if verbose:
                            print('      [!] Fail, SSL exception:',message)
                        connect = False
                        success_proto = ''

            # Verbose status
            if connect:
                if verbose:
                    print('      [+] Success with',proto)
        except requests.exceptions.RequestException as e:
            if verbose:
                print('      [!] Fail, caught exception:',e)
            pass

    # Return status
    if verbose:
        print()
    if connect:
        return success_proto
    else:
        return None


# Gnmap to IP:port
def gnmapToIPport(gnmap_file):

    # Local variables
    prelim_results = []
    results = []
    ports_total = []

    # Get relevant lines from file
    with open(gnmap_file,'r') as source_data:
        for line in source_data:
            if 'Ports' in line:
                prelim_results.append(line.rstrip())

    # Data processing
    for line in prelim_results:
        ports = []
        if line[0] != '#':
            ip = line.split(' ')[1].strip()
            port_string = line.split('Ports: ')[1].split('\t')[0]
            for x in range(0, int(port_string.count(', '))+1):
                temp = port_string.split(', ')[x].strip()
                if '/open/' in temp:
                    ports.append(int(temp.split('/')[0]))
            if ports:
                for port in ports:
                    if port not in ports_total:
                        ports_total.append(int(port))
                for port in ports:
                    results.append(ip+':'+str(port))
    return results


# TCP connect to determine if IP:port is open
def isPortOpen(target):
    try:
        host = target.split(':')[0]
        port = int(target.split(':')[1])
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        result = sock.connect_ex((host, port))
        sock.close()
        if result == 0:
            return True
        else:
            return False
    except socket.gaierror:
        return False


# Parse text results file into a CSV
def parseResults(results_file, keep_file):
    # Variables
    start = False
    stop = False
    target = ''
    response_code = ''
    csv_headers = 'Response,Found'
    results = []

    # Configure CSV output file name
    parsed_output = results_file.replace('.txt','.csv')
    if not parsed_output.endswith('.csv'):
        parsed_output = results_file + '.csv'

    # Parse results
    print('Parsing' ,results_file)
    with open(results_file, 'r') as data:
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
                                        if 'Note that dirbust was automatically ended after user specified timeout' not in line:
                                            results.append([response_code,str(line.rstrip())])

    # Sort results
    results.sort(reverse=False, key=lambda found: found[1])
    results.sort(reverse=False, key=lambda response: response[0])

    # Write results to disk
    with open(parsed_output, 'w') as output_file:
        output_file.write(csv_headers)
        output_file.write('\n')
        for result in results:
            output_file.write(','.join(result))
            output_file.write('\n')

    # Print number of results
    print('Wrote', len(results), 'results to', parsed_output)

    # Delete text file, if applicable
    if not keep_file:
        os.remove(results_file)
        print('Removed TXT results file', results_file)


# Print custom usage output
def getUsage():
    path = ''
    if os.name == 'posix':
        path = str(os.getcwd()).replace('\\', '/')+'/DirBuster/'
    elif os.name == 'nt':
        path = str(os.getcwd()).replace('/', '\\')+'\\DirBuster\\'
    return'''
     ___         __        ____  _      __               __
    /   | __  __/ /_____  / __ \(_)____/ /_  __  _______/ /____  _____
   / /| |/ / / / __/ __ \/ / / / / ___/ __ \/ / / / ___/ __/ _ \/ ___/
  / ___ / /_/ / /_/ /_/ / /_/ / / /  / /_/ / /_/ (__  ) /_/  __/ /
 /_/  |_\__,_/\__/\____/_____/_/_/  /_.___/\__,_/____/\__/\___/_/

%s [options] {target file}
    Automatically run and save Dirbuster scans for multiple IPs

Positional arguments:
    {target} Target file; list of IP:port, one per line

Optional arguments:
    Common Options:
    -g        Gnmap mode; provide a Nmap .gnmap file instead of an IP:port file
                  as a positional argument
    -st       Single target mode, positional argument is target in IP:port format
    -to       Set a timeout value in minutes for each host; default is None
    -v        Verbose mode; print service query status updates
    -f        Force mode; don't check if DirBuster report file exists, this will
                  result in previous reports being overwritten
    -k        Don't delete the text results file after converting it to a CSV
                  result file
    -h        Print this help message
    --dns     Automatically resolve IP address to hostname to use during dirbust

    Dirbuster Options:
    -d        Full path of directory that contains DirBuster.jar; default is
                  %s
    -l        Wordlist to use for list based brute force; default is OWASP's
                  directory-list-2.3-small.txt
    -e        File Extension list (e.g.: "asp,aspx"); default is None
    -t        Number of connection threads to use; default is 350
    -r        Recursive mode; default is False
    -s        Start point of the scan; default is "/"

Examples:
    python AutoDirbuster.py ip_port_list.txt
    python AutoDirbuster.py -g Nmap_results.gnmap -to 15
    python AutoDirbuster.py -g Nmap_results.gnmap -r -e "php,html" --dns\n\r
''' % (sys.argv[0], path)


# Launch program
if __name__ == '__main__':
    # Parse arguments
    parser = argparse.ArgumentParser(description='Automatically run and save Dirbuster scans for multiple IPs', add_help=False, usage=getUsage())
    parser.add_argument('target', help='Target file with IP:port or Gnmap file if --gnmap is used')
    parser.add_argument('-g', '--gnmap', help='Gnmap mode; provide a Nmap .gnmap file instead of an IP:port file as a positional argument', action='store_true')
    parser.add_argument('-st', '--single-target', help='Single target mode, positional argment is target in IP:port format', action='store_true')
    parser.add_argument('-to', '--timeout', help='Set a timeout value for each host; default is None')
    parser.add_argument('-v', '--verbose', help='Verbose mode; print service query status updates', action='store_true')
    parser.add_argument('-f', '--force', help='Force mode; don\'t check if DirBuster report file exists, this will result in previous reports being overwritten', action='store_true')
    parser.add_argument('-k', '--keep', help='Don\'t delete the text results file after converting it to a CSV result file', action='store_true')
    parser.add_argument('--dns', help='Automatically resolve IP address to hostname to use during dirbust', action='store_true')
    parser.add_argument('-d', '--directory', help='Full path of directory that contains DirBuster.jar; default is ./DirBuster/')
    parser.add_argument('-l', '--wordlist', help='Wordlist to use for list based brute force; default is OWASP\'s directory-list-2.3-small.txt')
    parser.add_argument('-e', '--extensions', help='File Extention list (e.g.: "asp,aspx"); default is None')
    parser.add_argument('-t', '--threads', help='Number of connection threads to use; default is 350')
    parser.add_argument('-r', '--recursive', help='Recursive mode; default is False', action='store_true')
    parser.add_argument('-s', '--start-point', help='Start point of the scan; default is "/"')
    parser.add_argument('--debug', help='Print the Subprocess command used to launch Dirbuster', action='store_true')
    args = parser.parse_args()
    arg_target = args.target
    arg_gnmap = args.gnmap
    arg_single_target = args.single_target
    arg_timeout = args.timeout
    arg_verbose = args.verbose
    arg_force = args.force
    arg_keep = args.keep
    arg_dns = args.dns
    arg_dirbuster_directory = args.directory
    arg_wordlist = args.wordlist
    arg_extensions = args.extensions
    arg_threads = args.threads
    arg_recursive = args.recursive
    arg_startpoint = args.start_point
    arg_debug = args.debug

    # Validate arguments
    ## Dirbuster directory
    if arg_dirbuster_directory:
        if arg_dirbuster_directory[-1] == '/':
            arg_dirbuster_directory = arg_dirbuster_directory[:-1]
        if arg_dirbuster_directory[-1] == '\\':
            arg_dirbuster_directory = arg_dirbuster_directory[:-1]
    else:
        arg_dirbuster_directory = str(os.getcwd())+'/DirBuster'
    ## Check if Java JAR is in dirbuster directory
    if not os.path.isfile(arg_dirbuster_directory+'/DirBuster.jar'):
        print(sys.argv[0], ': error: Incorrect DirBuster directory of "'+str(arg_dirbuster_directory)+'" provided, "'+arg_dirbuster_directory+'/DirBuster.jar" does not exist.')
        print(sys.argv[0], ': error: Make sure to provide full path of the directory that contains DirBuster.jar (eg: C:\DirBuster or /opt/DirBuster)')
        sys.exit()
    ## Wordlist
    default_wordlist = 'directory-list-2.3-small.txt'
    if not arg_wordlist:
        arg_wordlist = arg_dirbuster_directory+'/'+default_wordlist
    else:
        if args.directory:
            arg_wordlist = arg_dirbuster_directory+'/'+arg_wordlist
        else:
            arg_wordlist = arg_wordlist
    if not os.path.isfile(arg_wordlist):
        print(sys.argv[0], ': error: Wordlist file "'+arg_wordlist+'" does not exist. Make sure to provide full or relative path with filename')
        print(sys.argv[0], ': error: If wordlist argument was not passed, ensure that the DirBust directory of "'+arg_dirbuster_directory+' contains the default wordlist "'+default_wordlist+'"')
        sys.exit()
    ## Extensions
    if not arg_extensions:
        arg_extensions = '""'
    ## Threads
    if arg_threads:
        try:
            int(arg_threads)
        except ValueError:
            print(sys.argv[0], ': error: Provided value for threads must be an integer')
            sys.exit()
    else:
        arg_threads = 350
    ## Start point
    if arg_startpoint:
        if arg_startpoint[0] != '/':
            arg_startpoint = '/'+arg_startpoint
    else:
        arg_startpoint = '/'
    ## Timeout
    if arg_timeout:
        try:
            arg_timeout = int(arg_timeout)*60
        except ValueError:
            print(sys.argv[0], ': error: Provided value for timeout must be an integer')
            sys.exit()
    ## Single target
    if arg_single_target:
        if ':' in arg_target:
            try:
                int(arg_target.split(':')[1])
            except ValueError:
                print(sys.argv[0], ': Incorrectly formatted target: "'+str(arg_target)+'". Format: host:port (eg: 127.0.0.1:80 or example.com:80)')
                sys.exit()
        else:
            print(sys.argv[0], ': Incorrectly formatted target: "'+str(arg_target)+'". Format: host:port (eg: 127.0.0.1:80 or example.com:80)')
            sys.exit()

    # Launch script
    main(arg_target, arg_gnmap, arg_wordlist, arg_extensions, arg_threads, arg_recursive, arg_startpoint, arg_dns, arg_single_target, arg_timeout, arg_verbose, arg_dirbuster_directory, arg_force, arg_debug, arg_keep)
