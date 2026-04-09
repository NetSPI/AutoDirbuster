#!/usr/bin/env python3

# AutoDirbuster - Automatically run and save ffuf scans for multiple IPs

# Imports
import argparse
import sys
import socket
import subprocess
import os
import json
import shutil
import traceback
import ssl
import time
import requests
from requests.adapters import HTTPAdapter
import dns.resolver
import dns.reversename
from urllib3 import disable_warnings, exceptions

# Configure requests to suppress SSL validation warning
disable_warnings(exceptions.InsecureRequestWarning)

# Force line buffering so status output is visible when stdout is a pipe
sys.stdout.reconfigure(line_buffering=True)

SSL_ERROR_STRINGS = (
    "You're speaking plain HTTP to an SSL-enabled server port",
    "trying to access MongoDB over HTTP on the native driver port",
    "The plain HTTP request was sent to HTTPS port",
    "Client sent an HTTP request to an HTTPS server",
    "This combination of host and port requires TLS",
)

USER_AGENT = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                  'AppleWebKit/537.36 (KHTML, like Gecko) '
                  'Chrome/146.0.0.0 Safari/537.36'
}

VALID_OUTPUT_FORMATS = ('json', 'csv', 'ejson', 'html', 'md', 'ecsv', 'all')


def _make_lenient_ssl_context():
    """Build a maximally permissive TLS context for servers with broken TLS.

    Handles targets that fail with errors like TLSV1_ALERT_INTERNAL_ERROR,
    UNSUPPORTED_PROTOCOL, SSLV3_ALERT_HANDSHAKE_FAILURE, etc.
    Used only as a fallback after the normal verify=False context fails.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    for flag in ("OP_NO_SSLv3", "OP_NO_TLSv1", "OP_NO_TLSv1_1"):
        bit = getattr(ssl, flag, 0)
        if bit:
            ctx.options &= ~bit

    try:
        ctx.options |= 0x4  # SSL_OP_LEGACY_SERVER_CONNECT
    except (AttributeError, ValueError):
        pass

    for ciphers in (
        "ALL:COMPLEMENTOFALL:@SECLEVEL=0",
        "ALL:@SECLEVEL=0",
        "DEFAULT:@SECLEVEL=1",
        "DEFAULT",
    ):
        try:
            ctx.set_ciphers(ciphers)
            break
        except ssl.SSLError:
            continue

    ctx.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
    ctx.maximum_version = ssl.TLSVersion.MAXIMUM_SUPPORTED

    return ctx


def _is_ssl_error(exc):
    """Walk the exception chain looking for ssl.SSLError."""
    current = exc
    while current is not None:
        if isinstance(current, ssl.SSLError):
            return True
        current = current.__cause__ or current.__context__
    return False


class LenientSSLAdapter(HTTPAdapter):
    """requests HTTPAdapter that uses a maximally permissive TLS context."""

    def __init__(self, **kwargs):
        self._ssl_context = _make_lenient_ssl_context()
        super().__init__(**kwargs)

    def init_poolmanager(self, *args, **kwargs):
        kwargs['ssl_context'] = self._ssl_context
        return super().init_poolmanager(*args, **kwargs)


class AutoDirbuster:
    """Automatically run and save ffuf scans for multiple IPs"""

    def __init__(self, args: dict):
        """Initialize attributes for AutoDirbuster instance"""
        self.__version__ = '2.2.0'
        self.args = args
        self.targets = []
        self.report_files = []

    def main(self):
        """Coordinate runtime activities"""
        self.get_targets()
        if not self.targets:
            print('[*] No valid targets found, exiting')
            return
        self.resolve_hostnames()
        self.run_engine()
        if self.args['combine']:
            self.combine_results()

    def get_targets(self):
        """Assign target object to either single URL or IP:port from provided filename"""
        if self.args['url']:
            self.targets.append(self.args['target'])
        else:
            seen = set()
            with open(self.args['target'], 'r', encoding='utf-8') as data:
                for line_count, line in enumerate(data, start=1):
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue

                    # Strip URL schemes and trailing slashes
                    for scheme in ('https://', 'http://'):
                        if line.lower().startswith(scheme):
                            line = line[len(scheme):]
                            break
                    line = line.rstrip('/')

                    if ':' not in line:
                        print(sys.argv[0], f': error: Incorrectly formatted line on '
                                           f'{self.args["target"]}:{line_count}')
                        continue

                    try:
                        host, port_str = line.rsplit(':', 1)
                        port = int(port_str)
                    except ValueError:
                        print(sys.argv[0], f': error: Incorrectly formatted line on '
                                           f'{self.args["target"]}:{line_count}')
                        continue

                    if not (1 <= port <= 65535):
                        print(sys.argv[0], f': error: Port {port} out of range (1-65535) on '
                                           f'{self.args["target"]}:{line_count}')
                        continue

                    key = (host.lower(), port)
                    if key in seen:
                        continue
                    seen.add(key)
                    self.targets.append(f'{host}:{port}')

    def resolve_hostnames(self):
        """Resolve IP to hostname if applicable"""
        if self.args['dns']:
            resolved_targets = []
            for target in self.targets:
                host = target.split(':')[0]
                port = target.split(':')[1]
                print('[*] Resolving ' + str(host) + ' ' * 25, end='\r')
                try:
                    socket.inet_aton(host)
                    host = self.ip_to_hostname(host)
                except OSError:
                    pass
                resolved_targets.append(str(host) + ':' + str(port))
            self.targets = resolved_targets
            print(' ' * 50, end='\r')

    def run_engine(self):
        """Determine if service is HTTP or HTTPS, then run ffuf"""
        target_status_count = 0
        print()
        for target in self.targets:
            # Local variables
            target_status_count += 1
            file_exists = False

            # Test if service is HTTP/HTTPS (serves as connectivity check)
            print(f'[{target_status_count}/{len(self.targets)}] {target}' + ' ' * 25)
            proto = self.service_query(target)
            if proto:

                # Configure params for ffuf launch
                url_target = str(proto) + "://" + str(target) + self.args['startpoint'] + 'FUZZ'
                output_name = f'ffuf-report-{proto}_{target.replace(":", "_")}'
                if self.args['output_format'] != 'all':
                    output_name = output_name + '.' + self.args['output_format']

                # Track CSV path for --combine
                if self.args['combine']:
                    if self.args['output_format'] == 'all':
                        self.report_files.append(output_name + '.csv')
                    elif self.args['output_format'] in ('csv', 'ecsv'):
                        self.report_files.append(output_name)

                ffuf_command = ['ffuf',
                                '-w',
                                str(self.args['wordlist']),
                                '-u',
                                str(url_target),
                                '-X',
                                str(self.args['method']),
                                '-o',
                                str(output_name),
                                '-of',
                                str(self.args['output_format']),
                                '-mc',
                                str(','.join(self.args['match_codes']))
                                ]
                if self.args['extensions']:
                    ffuf_command.append('-e')
                    ffuf_command.append(str(self.args['extensions']))
                if self.args['threads']:
                    ffuf_command.append('-t')
                    ffuf_command.append(str(self.args['threads']))
                if self.args['rate']:
                    ffuf_command.append('-rate')
                    ffuf_command.append(str(self.args['rate']))
                if self.args['recursive']:
                    ffuf_command.append('-recursion')
                if self.args['follow_redirects']:
                    ffuf_command.append('-r')
                if self.args['timeout']:
                    ffuf_command.append('-maxtime')
                    ffuf_command.append(str(self.args['timeout']))
                if self.args['header']:
                    ffuf_command.append('-H')
                    ffuf_command.append(str(self.args['header']))
                if not self.args['no_auto_calibrate']:
                    ffuf_command.append('-ac')
                # Custom args
                if self.args['custom_option']:
                    for custom_option in self.args['custom_option']:
                        option_key = '-'+str(custom_option[0])
                        option_value = custom_option[1]
                        ffuf_command.append(option_key)
                        if option_value:
                            ffuf_command.append(str(option_value))

                # Check if file exists
                if self.args['force']:
                    if self.args['output_format'] == 'all':
                        for ext in VALID_OUTPUT_FORMATS:
                            test_file_name = output_name + '.' + ext
                            if os.path.isfile(test_file_name):
                                os.remove(test_file_name)
                    else:
                        test_file_name = output_name
                        if os.path.isfile(test_file_name):
                            os.remove(test_file_name)
                else:
                    if self.args['output_format'] == 'all':
                        all_file_exists = []
                        for ext in VALID_OUTPUT_FORMATS:
                            test_file_name = output_name + '.' + ext
                            all_file_exists.append(os.path.isfile(test_file_name))
                        file_exists = all(all_file_exists)
                    else:
                        test_file_name = output_name
                        file_exists = os.path.isfile(test_file_name)

                # Launch ffuf
                if self.args['debug']:
                    print('[DEBUG] Subprocess command:', ' '.join(ffuf_command), '\n')
                if not file_exists:
                    # Start process
                    proc = subprocess.Popen(ffuf_command)
                    try:
                        proc.wait()
                    except KeyboardInterrupt:
                        proc.terminate()
                        proc.wait()
                        print('\n[*] Skipping to next target\n')
                    except Exception:
                        print('[ERROR] Uncaught exception:')
                        print(traceback.format_exc())
                    if self.args['debug']:
                        print(f'[DEBUG] Report written to {output_name}')
                    print()

                # Report file already exists
                else:
                    print('Report file already exists, skipping target\n\n')

            # Target not reachable or not HTTP
            else:
                print('Target not reachable or not HTTP, skipping\n\n')

    def combine_results(self):
        """Combine individual CSV report files into a single results file."""
        if not self.report_files:
            print('[*] No report files to combine')
            return

        # Determine file extension
        ext = 'ecsv' if self.args['output_format'] == 'ecsv' else 'csv'

        # Determine output filename, append epoch if file already exists
        combined_name = f'autodirbuster_combined_results.{ext}'
        if os.path.isfile(combined_name):
            combined_name = f'autodirbuster_combined_results_{int(time.time())}.{ext}'

        # Filter to files that actually exist on disk
        available = []
        for filepath in self.report_files:
            if os.path.isfile(filepath):
                available.append(filepath)
            else:
                print(f'[WARN] Report file not found, skipping: {filepath}')

        if not available:
            print('[*] No report files found on disk to combine')
            return

        # Read header from first available file
        with open(available[0], 'r', encoding='utf-8') as f:
            header = f.readline()

        if not header.strip():
            print('[*] First report file is empty, cannot combine')
            return

        # Write combined file: header once, then data rows from all files
        with open(combined_name, 'w', encoding='utf-8') as out:
            out.write(header)
            for filepath in available:
                with open(filepath, 'r', encoding='utf-8') as f:
                    f.readline()  # Skip header
                    for line in f:
                        out.write(line)

        print(f'[*] Combined {len(available)} report files into {combined_name}')

    def service_query(self, target: str):
        """Determine if service is HTTP and if TLS is required.

        Probes HTTPS first (with lenient TLS fallback), then plain HTTP.
        The HTTP request itself serves as the connectivity test — no
        separate TCP port scan is needed.
        """
        if self.args['debug']:
            print('Querying service')

        # --- HTTPS with standard verify=False context ---
        https_ssl_error = False
        try:
            if self.args['debug']:
                print('    Trying: https')
            requests.get(f'https://{target}',
                         verify=False,
                         timeout=5,
                         headers=USER_AGENT,
                         allow_redirects=False)
            if self.args['debug']:
                print('      [+] Success with https')
                print()
            return 'https'
        except requests.exceptions.RequestException as e:
            if self.args['debug']:
                print(f'      [!] Fail, caught exception: {e}')
            https_ssl_error = _is_ssl_error(e)
        except Exception:
            print('[ERROR] Uncaught exception:')
            print(traceback.format_exc())

        # --- HTTPS with lenient TLS context (only if prior failure was TLS-related) ---
        if https_ssl_error:
            try:
                if self.args['debug']:
                    print('    Retrying: https (lenient TLS context)')
                with requests.Session() as session:
                    session.mount('https://', LenientSSLAdapter())
                    session.get(f'https://{target}',
                                timeout=5,
                                headers=USER_AGENT,
                                allow_redirects=False)
                if self.args['debug']:
                    print('      [+] Success with https (lenient)')
                    print()
                return 'https'
            except requests.exceptions.RequestException as e:
                if self.args['debug']:
                    print(f'      [!] Fail, caught exception: {e}')
            except Exception:
                print('[ERROR] Uncaught exception:')
                print(traceback.format_exc())

        # --- Plain HTTP ---
        try:
            if self.args['debug']:
                print('    Trying: http')
            req = requests.get(f'http://{target}',
                               timeout=5,
                               headers=USER_AGENT,
                               allow_redirects=False)
            body = req.text[:4096]
            if any(msg in body for msg in SSL_ERROR_STRINGS):
                if self.args['debug']:
                    print('      [!] Fail, SSL redirect detected in response body')
                    print()
                return None
            if self.args['debug']:
                print('      [+] Success with http')
                print()
            return 'http'
        except requests.exceptions.RequestException as e:
            if self.args['debug']:
                print(f'      [!] Fail, caught exception: {e}')
        except Exception:
            print('[ERROR] Uncaught exception:')
            print(traceback.format_exc())

        if self.args['debug']:
            print()
        return None

    @staticmethod
    def ip_to_hostname(target):
        """Resolve IP to hostname"""
        try:
            qname = dns.reversename.from_address(target)
            answer = dns.resolver.resolve(qname, 'PTR')
            if answer:
                return str(answer[0]).rstrip('.')
            else:
                return target
        except dns.exception.DNSException:
            return target
        except Exception:
            print('[ERROR] Uncaught exception:')
            print(traceback.format_exc())
            return target

    @staticmethod
    def is_port_open(target: str):
        """TCP connect to determine if IP:port is open"""
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
        except Exception:
            print('[ERROR] Uncaught exception:')
            print(traceback.format_exc())
            return False


# Print custom usage output
def get_usage():
    return r'''
     ___         __        ____  _      __               __
    /   | __  __/ /_____  / __ \(_)____/ /_  __  _______/ /____  _____
   / /| |/ / / / __/ __ \/ / / / / ___/ __ \/ / / / ___/ __/ _ \/ ___/
  / ___ / /_/ / /_/ /_/ / /_/ / / /  / /_/ / /_/ (__  ) /_/  __/ /
 /_/  |_\__,_/\__/\____/_____/_/_/  /_.___/\__,_/____/\__/\___/_/

%s [options] {target file}

Automatically run and save ffuf scans for multiple IPs

options:
  -h, --help            show this help message and exit

AutoDirbuster options:
  target                Target file with IP:port, one per line
  -u, --url             Single target mode, positional argument is target in IP:port
                        format
  -f, --force           Force mode; don't check if report file exists, this will result in
                        previous reports being overwritten
  --dns                 Automatically resolve IP address to hostname to use during dirbust
  --debug               Show debugging information
  --combine             Combine all CSV results into a single file after scanning

ffuf options:
  -w WORDLIST, --wordlist WORDLIST
                        Wordlist to use for list based brute force
  -X METHOD, --method METHOD
                        HTTP method to use; default=GET
  -e EXTENSIONS, --extensions EXTENSIONS
                        File extension list (e.g.: ".asp,.aspx"), ensure that a period is
                        before the provided extension; default is None
  -t THREADS, --threads THREADS
                        Override the default number of ffuf threads
  --rate RATE           Rate of requests per second
  -to TIMEOUT, --timeout TIMEOUT
                        Set a timeout value for each host in minutes; default is None
  -fr, --follow-redirects
                        Follow redirects; default is False
  -r, --recursive       Recursive mode; default is False
  -s STARTPOINT, --startpoint STARTPOINT
                        Start point of the scan; default=/
  -of OUTPUT_FORMAT, --output-format OUTPUT_FORMAT
                        Output format to write results to; default=csv
  -mc MATCH_CODES, --match-codes MATCH_CODES
                        Match HTTP status codes;
                        default=200,204,301,302,307,401,403,405,500
  -nac, --no-auto-calibrate
                        Do not automatically calibrate filtering options
  -H HEADER, --header HEADER
                        HTTP header "Name: Value", separated by colon
  --custom-option CUSTOM_OPTION [CUSTOM_OPTION ...]
                        Specify ffuf option that AutoDirbuster doesn't support by default.
                        Argument should be a key/value pair separated by a comma with no
                        leading '-', example: --custom-option=ml,1. If the provided
                        argument is a boolean, provide an empty value: --custom-option=sa,

Examples:
    python AutoDirbuster.py ip_port_list.txt -w my_wordlist.txt
    python AutoDirbuster.py -st example.com:80 -w my_wordlist.txt -mc 200,500
    python AutoDirbuster.py ip_port_list.txt -w my_wordlist.txt -r -e ".php,.html" --dns
    
''' % sys.argv[0]


# Launch program
if __name__ == '__main__':
    """Run from CLI"""

    # Defaults
    default_method = 'GET'
    default_startpoint = '/'
    default_output_format = 'csv'
    default_status_codes = '200,204,301,302,307,401,403,405,500'
    default_custom_args_enabled = True

    # Parse arguments
    parser = argparse.ArgumentParser(description='Automatically run and save ffuf scans for multiple IPs',
                                     add_help=False,
                                     usage=get_usage())

    autodirbuster_option = parser.add_argument_group('AutoDirbuster options')
    autodirbuster_option.add_argument('target',
                                      help='Target file with IP:port, one per line',
                                      type=str)
    autodirbuster_option.add_argument('-u', '--url',
                                      help='Single target mode, positional argument is target in IP:port format',
                                      action='store_true')
    autodirbuster_option.add_argument('-f', '--force',
                                      help="Force mode; don't check if report file exists, this will result in "
                                           "previous reports being overwritten",
                                      action='store_true')
    autodirbuster_option.add_argument('--dns', help='Automatically resolve IP address to hostname to use during '
                                                    'dirbust',
                                      action='store_true')
    autodirbuster_option.add_argument('--debug',
                                      help='Show debugging information',
                                      action='store_true')
    autodirbuster_option.add_argument('--combine',
                                      help='Combine all CSV results into a single file after scanning',
                                      action='store_true')
    autodirbuster_option.add_argument('-h', '--help',
                                      help='Show this help message and exit',
                                      action='store_true')

    ffuf_options = parser.add_argument_group('ffuf options')
    ffuf_options.add_argument('-w', '--wordlist',
                              help='Wordlist to use for list based brute force',
                              required=True)
    ffuf_options.add_argument('-X', '--method',
                              help=f'HTTP method to use; default={default_method}',
                              type=str,
                              default=default_method)
    ffuf_options.add_argument('-e', '--extensions',
                              help='File extension list (e.g.: ".asp,.aspx"), ensure that a period is before the '
                                   'provided extension; default is None',
                              type=str)
    ffuf_options.add_argument('-t', '--threads',
                              help='Override the default number of ffuf threads',
                              type=int)
    ffuf_options.add_argument('--rate',
                              help='Rate of requests per second',
                              type=int)
    ffuf_options.add_argument('-to', '--timeout',
                              help='Set a timeout value for each host in minutes; default is None',
                              type=int)
    ffuf_options.add_argument('-fr', '--follow-redirects',
                              help='Follow redirects; default is False',
                              action='store_true')
    ffuf_options.add_argument('-r', '--recursive',
                              help='Recursive mode; default is False',
                              action='store_true')
    ffuf_options.add_argument('-s', '--startpoint',
                              help=f'Start point of the scan; default={default_startpoint}',
                              type=str,
                              default=default_startpoint)
    ffuf_options.add_argument('-of', '--output-format',
                              help=f'Output format to write results to; default={default_output_format}',
                              type=str,
                              default=default_output_format)
    ffuf_options.add_argument('-mc', '--match-codes',
                              help=f'Match HTTP status codes; default={default_status_codes}',
                              type=str,
                              default=default_status_codes)
    ffuf_options.add_argument('-nac', '--no-auto-calibrate',
                              help='Do not automatically calibrate filtering options',
                              action='store_true')
    ffuf_options.add_argument('-H', '--header',
                              help='HTTP header "Name: Value", separated by colon',
                              type=str)
    if default_custom_args_enabled:
        ffuf_options.add_argument('--custom-option',
                                  help="Specify ffuf option that AutoDirbuster doesn't support by default. Argument "
                                       "should be a key/value pair separated by a comma with no leading '-', example: "
                                       "--custom-option=ml,1. If the provided argument is a boolean, provide an empty "
                                       "value: --custom-option=sa,",
                                  type=str,
                                  nargs='+',
                                  action='append')

    # Parse arguments
    raw_args = parser.parse_args()
    arguments = raw_args.__dict__

    # Print help
    if arguments['help']:
        print(get_usage())
        sys.exit()

    # Validate arguments
    # URL
    if arguments['url']:
        if 'FUZZ' in arguments['target']:
            parser.error('Provided URL cannot contain the string "FUZZ"')
    # Start point
    if arguments['startpoint'][0] != '/':
        arguments['startpoint'] = '/' + arguments['startpoint']
    if arguments['startpoint'][-1] != '/':
        arguments['startpoint'] = arguments['startpoint'] + '/'
    # Single target
    if arguments['url']:
        if ':' in arguments['target']:
            try:
                int(arguments['target'].rsplit(':', 1)[1])
            except ValueError:
                parser.error(f': Incorrectly formatted target: "{arguments["target"]}". Format: host:port '
                             f'(eg: 127.0.0.1:80 or example.com:80)')
        else:
            parser.error(f': Incorrectly formatted target: "{arguments["target"]}". Format: host:port '
                         f'(eg: 127.0.0.1:80 or example.com:80)')
    # Output formats
    if arguments['output_format']:
        if arguments['output_format'] not in VALID_OUTPUT_FORMATS:
            parser.error(
                f'Provided output format "{arguments["output_format"]}" is not a valid output format. '
                f'One of the following values can be used: {",".join(VALID_OUTPUT_FORMATS)}')
    # Combine
    if arguments['combine']:
        if arguments['output_format'] not in ('csv', 'ecsv', 'all'):
            parser.error('--combine requires a CSV-compatible output format (csv, ecsv, or all)')
    # Status codes
    if arguments['match_codes']:
        status_codes = []
        comma_count = arguments['match_codes'].count(',')
        for x in range(0, comma_count + 1):
            code = arguments['match_codes'].split(',')[x].lower()
            try:
                code = int(code)
                if code < 100 or code > 999:
                    parser.error('Status codes need to be an integer between 100-999')
                else:
                    status_codes.append(str(code))
            except ValueError:
                parser.error('Status codes need to be an integer between 100-999')
        arguments['match_codes'] = status_codes
    # Timeout
    if arguments['timeout']:
        arguments['timeout'] = arguments['timeout'] * 60
    # Custom options
    if default_custom_args_enabled:
        if arguments['custom_option']:
            custom_options_args = []
            for option_list in arguments['custom_option']:
                if ',' not in option_list[0]:
                    parser.error('Custom option requires a key/value pair separated by a comma, example: '
                                 '--custom-option=ml,1')
                else:
                    key, value = option_list[0].split(',', 1)
                    if len(value) == 0:
                        value = None
                    if key[0] == '-':
                        key = key[1:]
                    custom_options_args.append((key, value))
            arguments['custom_option'] = custom_options_args
    else:
        arguments['custom_option'] = None
    # Target file
    if not arguments['url']:
        if not os.path.isfile(arguments['target']):
            parser.error(f'Target file "{arguments["target"]}" does not exist')
    # Wordlist
    if not os.path.isfile(arguments['wordlist']):
        parser.error(f'Wordlist file "{arguments["wordlist"]}" does not exist')

    # Debug
    if arguments['debug']:
        print('[DEBUG] Arguments:')
        print(json.dumps(arguments, indent=4, default=str))
        print()

    # Confirm that ffuf binary is in path
    ffuf_binary_name = 'ffuf'
    ffuf_repo = 'https://github.com/ffuf/ffuf'
    in_path = shutil.which(ffuf_binary_name)
    if not in_path:
        parser.error(
            f'ffuf binary "{ffuf_binary_name}" is not in system path. '
            f'Please ensure that ffuf is installed and in your system path. Instructions can be found at {ffuf_repo}')

    # Launch AutoDirbuster
    adb = AutoDirbuster(arguments)
    adb.main()
 