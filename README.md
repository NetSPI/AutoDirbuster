```
                         ___         __        ____  _      __               __
                        /   | __  __/ /_____  / __ \(_)____/ /_  __  _______/ /____  _____
                       / /| |/ / / / __/ __ \/ / / / / ___/ __ \/ / / / ___/ __/ _ \/ ___/
                      / ___ / /_/ / /_/ /_/ / /_/ / / /  / /_/ / /_/ (__  ) /_/  __/ /
                     /_/  |_\__,_/\__/\____/_____/_/_/  /_.___/\__,_/____/\__/\___/_/
```

### Automatically run and save ffuf scans for multiple IPs

## Contents
  * [Quick Run](#quick-run)
  * [FAQ](#faq)
    * [Why?](#why)
    * [What is the recommended usage?](#what-is-the-recommended-usage)
    * [What data does this need?](#what-data-does-this-need)
    * [How does this script work?](#how-does-this-script-work)
    * [This program isn't working](#this-program-isnt-working)
  * [Usage](#usage)

## Quick Run
```
git clone https://github.com/NetSPI/AutoDirbuster.git
cd AutoDirbuster && pip3 install -r requirements.txt
python AutoDirbuster.py ip_port_list.txt -w my_wordlist.txt
```

## FAQ
### Why?
Ffuf is a great directory buster but running it against multiple IPs and ports is a very manual process with a lot of downtime between scans. This script attempts to automate that process and eliminates downtime between scans.

### What is the recommended usage?
**If attacking multiple targets:**
* Run Nmap and find open ports
* Review the Nmap results and create an IP:port list, one per line
* Run AutoDirbuster against the open ports
* AutoDirbuster will determine if the provided port is open and if the service is HTTP based

  * `python AutoDirbuster.py ip_port_list.txt -w my_wordlist.txt`

**If attacking a single target:**

* `python AutoDirbuster.py -u example.com:80 -w my_wordlist.txt`

**Useful options include:**

| Option          | Purpose                                                           |
|-----------------|-------------------------------------------------------------------|
| --dns           | Resolve IPs to hostnames                                          |
| --extensions    | File extensions to use when scanning                              |
| --rate          | Rate of requests per second                                       |
| --timeout       | Set a timeout value for each host in minutes                      |
| --match-codes   | Match provided HTTP status codes                                  |
| --custom-option | Specify ffuf option that AutoDirbuster doesn't support by default |

Specify the `--help` flag for a full list of options.

### What data does this need?
The program can take two data sources:
1. List of IP:port or hostname:port, one per line

* `python AutoDirbuster.py ip_port_list.txt -w my_wordlist.txt`

2. Single target

* `python AutoDirbuster.py -u example.com:80 -w my_wordlist.txt`

### How does this script work?
* A list of targets is provided
* A TCP connect scan is done on the target port to test if it's open
* If the port open, HTTP and HTTPS requests are sent to determine if the service is HTTP-based and whether it requires TLS
* If the service is HTTP, a check is done to determine if a previous report file is in the same directory
  * Report files follow the format: `ffuf-report-{proto}_{target}_{port}'`
* ffuf is run using Python's `subprocess.Popen()`
* The next IP:port goes through the same process (TCP connect, HTTP service query, dirbust)

### This program isn't working
Ensure the following:
* Are all the dependencies listed in `requirements.txt` installed?
* Is `ffuf` installed and in your system path?
  * Try running `ffuf -V`
  * Installation instructions can be found on the [ffuf GitHub repository page](https://github.com/ffuf/ffuf)
* You may need to use Python 3.11+
  * Version information can be obtained by running `python -V`

## Usage
```
# python AutoDirbuster.py --help
usage:
     ___         __        ____  _      __               __
    /   | __  __/ /_____  / __ \(_)____/ /_  __  _______/ /____  _____
   / /| |/ / / / __/ __ \/ / / / / ___/ __ \/ / / / ___/ __/ _ \/ ___/
  / ___ / /_/ / /_/ /_/ / /_/ / / /  / /_/ / /_/ (__  ) /_/  __/ /
 /_/  |_\__,_/\__/\____/_____/_/_/  /_.___/\__,_/____/\__/\___/_/

AutoDirbuster.py [options] {target file}

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

ffuf options:
  -w WORDLIST, --wordlist WORDLIST
                        Wordlist to use for list based brute force
  -X METHOD, --method METHOD
                        HTTP method to use; default=GET
  -e EXTENSIONS, --extensions EXTENSIONS
                        File extension list (e.g.: "asp,aspx"); default is None
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
    python AutoDirbuster.py ip_port_list.txt -w my_wordlist.txt -r -e "php,html" --dns
```
