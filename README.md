# Spymap
is a high-speed, passive reconnaissance tool designed for mapping open ports and ASN information for a list of domains using Shodan and DNS resolution. It leverages multithreading to process multiple domains concurrently, enhancing efficiency and speed.

## Features

* High Speed: Utilizes multithreading to quickly process large lists of domains.
* Passive Reconnaissance: Gathers information without active probing, reducing the risk of detection.
* Domain Resolution: Resolves domain names to IP addresses using Google's DNS resolver.
* Shodan Integration: Fetches open port information and ASN data for IP addresses from Shodan.
* Port Filtering: Allows exclusion of specified ports.
* Flexible Output: Outputs results to a specified file or standard output.
* Shodan IP Download: Can download IP addresses directly from Shodan search queries.
* Verbose Mode: Optional detailed output for each domain processed.

## Installation

- Clone the repository `git clone https://github.com/Vulnpire/Spymap`
- Change the directory: `cd Spymap`
- Make the script executable: `chmod +x spymap`
- Move the spymap script to a directory in your PATH (e.g., /usr/bin/): `mv spymap /usr/bin/`
- Install the required Python packages:Install the required Python packages: `pip3 install requests beautifulsoup4`

## Usage

python3 spymap `<options>`

Note: Spymap can function without a Shodan API key. However, to unlock its full potential and achieve better results, I highly recommend using a free tier Shodan API key.

Options

* `-c`: Number of threads to use (default: 8)
* `--asn`: Show ASN in the output
* `--ip`: Show IP address in the output
* `--exclude-ports`: Exclude specific ports (comma-separated)
* `-o`: Output file (default: stdout)
* `-v`: Print current version
* `-s`: Shodan API key
* `--dl`: Shodan search query to download IPs
* `--ipv4-only`: Download only IPv4 addresses
* `--file`: File containing search queries
* `--verbose`: Print verbose output

## Examples

* Download IPs from Shodan using a query

`$ spymap --dl "apache" -s YOUR_SHODAN_API_KEY`

---
```
$ head -n5 ips.txt                                             
77.87.181.152
181.87.6.12
45.171.220.6
213.211.51.64
142.44.170.124
```

* Download IPs from Shodan using a recent CVE query

`$ spymap --dl '"Server: Check Point SVN" "X-UA-Compatible: IE=EmulateIE7"' --ipv4-only`

---
```
$ head -n5 ips.txt
49.248.144.74
2.33.1.203
2.82.75.28
2.119.27.163
2.119.27.164
```

# Process domains from a file containing search queries

```
$ cat << EOF > wildcards.txt 
heredoc> intigriti.com       
heredoc> spotify.com                  
heredoc> bugcrowd.com 
heredoc> bitdefender.com
heredoc> EOF
```

* Download IPs from Shodan using a query

```
$ spymap --file wildcards.txt -c 50 -s YOUR_SHODAN_API_KEY --ipv4-only
IPs downloaded and saved to ips.txt

---

$ head -n5 ips.txt
34.117.157.56
35.186.224.24
128.245.226.55
188.226.189.229
213.219.170.117
```

* Resolve domains from stdin and fetch open ports

```
$ time cat wildcards.txt | spymap -c 100 -s YOUR_SHODAN_API_KEY
spotify.com:80
spotify.com:443
bitdefender.com:8080
bitdefender.com:2082
bitdefender.com:2083
bitdefender.com:2086
bitdefender.com:2087
bitdefender.com:80
bitdefender.com:8880
bitdefender.com:8443
bitdefender.com:443
intigriti.com:80
intigriti.com:443
bugcrowd.com:80
bugcrowd.com:443

real    0,97s
```
