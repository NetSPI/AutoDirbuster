# AutoDirbuster
By Alex Poorman

## Purpose
Automatically run and save Dirbuster scans for multiple IPs

## Quick Run
```
git clone https://github.com/NetSPI/AutoDirbuster.git
cd AutoDirbuster && pip3 install -r requirements.txt
python AutoDirbuster.py ip_port_list.txt
```

## FAQ
### Why?
OWASP Dirbuster is a great directory buster but running it against multiple IPs and ports is a very manual process with a lot of downtime between scans. This script attempts to automate that process and eliminates downtime between scans.

### What is the recommended usage?
If attacking multiple targets:
* Run Nmap and find open ports, outputting the results with `-oG` or `-oA`
* Run AutoDirbuster with the Nmap results and a timeout (closed ports or non-HTTP based services are ignored)

  * `python AutoDirbuster.py -g Nmap_results.gnmap -to 15`

* As the pentest progresses, periodically review the Dirbust results using `dirbust_read.py`, which will ignore all Dirbuster error lines and only print the found directories and files

If attacking a single target:

* `python AutoDirbuster.py -st example.com:80`

### What data does this need?
The script can take three data sources:
1. List of IP:port or hostname:port, one per line

* `python AutoDirbuster.py ip_port_list.txt`

2. An Nmap Gnmap result file

* `python AutoDirbuster.py -g Nmap_results.gnmap`

3. A single target

* `python AutoDirbuster.py -st example.com:80`

### How does this script work?
* A list of targets is provided
* A TCP connect scan is done on the target port to test if it's open
* If it's open, HTTP and HTTPS requests are sent to determine if the service is HTTP-based and whether it requires SSL
* If the service is HTTP, a check is done to determine if a previous report file is in the same directory. Report files follow the format: `DirBuster-Report-IP-port.txt`
* Dirbuster is run using Python's `subprocess.Popen()`. If a timeout is specified, then after the timeout period, a `SIGINT` signal is sent to Dirbuster so it can safely shutdown and write results to disk. A note is added to the report indicating that the scan timed out.
* The next IP:port goes through the same process (TCP connect, HTTP service query, dirbust)

### This script isn't working
Ensure the following
* Are all of the dependencies listed in `requirements.txt` installed?
* Is there a directory called "DirBuster" inside the same directory as AutoDirbuster.py?
* Does this "DirBuster" directory contain the Dirbuster JAR file named "DirBuster.jar"?
* Is "DirBuster.jar" version 0.12?
* Does this "DirBuster" directory contain a file called "directory-list-2.3-small.txt" (the default wordlist)?
* Does this "DirBuster" directory contain a subdirectory called "lib" with the default 13 required Dirbuster JAR dependencies?
* Is Java installed?
* Is Java in your path?
* Run AutoDirbuster with the `--debug` flag to view the subprocess command that AutoDirbuster is using to launch Dirbuster. Run this command from the terminal to view standard error as AutoDirbuster is configured to send subprocess standard error to /dev/null

## Usage
```
root@kali:~# python AutoDirbuster.py -h
     ___         __        ____  _      __               __
    /   | __  __/ /_____  / __ \(_)____/ /_  __  _______/ /____  _____
   / /| |/ / / / __/ __ \/ / / / / ___/ __ \/ / / / ___/ __/ _ \/ ___/
  / ___ / /_/ / /_/ /_/ / /_/ / / /  / /_/ / /_/ (__  ) /_/  __/ /
 /_/  |_\__,_/\__/\____/_____/_/_/  /_.___/\__,_/____/\__/\___/_/

AutoDirbuster.py [options] {target file}
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
    -h        Print this help message
    --dns     Automatically resolve IP address to hostname to use during dirbust

    Dirbuster Options:
    -d        Full path of directory that contains DirBuster.jar; default is
                  /path/of/AutoDirbuster/DirBuster/
    -l        Full file path of wordlist to use for list based brute force;
                  default is OWASP's directory-list-2.3-small.txt
    -e        File Extension list (e.g.: "asp,aspx"); default is None
    -t        Number of connection threads to use; default is 350
    -r        Recursive mode; default is False
    -s        Start point of the scan; default is "/"

Examples:
    python AutoDirbuster.py ip_port_list.txt
    python AutoDirbuster.py -g Nmap_results.gnmap -to 15
    python AutoDirbuster.py -g Nmap_results.gnmap -r -e "php,html" --dns

```

## Dependencies
Run `pip3 install <module name>` on the following modules:
* dnspython

Alternatively, you can run `pip3 install -r requirements.txt`
