# VAULT
#### Swiss army knife for hackers

[![Codacy Badge](https://api.codacy.com/project/badge/Grade/740204dd950c4e49841c94f2c32af78a)](https://app.codacy.com/app/abhisharma404/vault_scanner?utm_source=github.com&utm_medium=referral&utm_content=abhisharma404/vault_scanner&utm_campaign=Badge_Grade_Dashboard)
[![GitHub](https://img.shields.io/github/license/mashape/apistatus.svg)](https://github.com/abhisharma404/vault_scanner)
[![Join the chat at https://gitter.im/vault_scanner/kwoc](https://badges.gitter.im/vault_scanner/Lobby.svg)](https://gitter.im/vault_scanner/Lobby?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge) ![Python](https://img.shields.io/badge/python-%3E%3D3-brightgreen.svg)
![version](https://img.shields.io/badge/version-0.1.0-yellow.svg)
![support](https://img.shields.io/badge/OS-Linux-orange.svg)
[![Documentation Status](https://readthedocs.org/projects/vault-scanner/badge/?version=latest)](https://vault-scanner.readthedocs.io/en/latest/?badge=latest)


## Table of contents
- [Getting Started](#getting-started)
- [Features](#features)
- [Usage](#usage)
- [Screenshot](#screenshot)
- [Contributing](#contributing)
- [License](#license)

## Getting Started

#### Steps to setup :

1. `git clone <your-fork-url>`
2. `cd vault`
3. `sudo apt-get install python3-pip`
4. `sudo pip3 install virtualenv`
5. `virtualenv venv`
6. `source venv/bin/activate`
7. `pip3 install -r requirements.txt`

#### Starting Vault :

1. `cd vault/src`
2. `python3 vault.py`

## Features
* #### Scan website for the following vulnerabilities
- [x] XSS
- [x] LFI
- [ ] RFI
- [ ] SQLi

* #### Scanner
- [x] Port scanning : ACK, FIN, NULL, XMAS
- [x] IP scanning : Ping Sweep, ARP
- [x] SSL vulnerability scan
- [x] OS scan
- [x] Hash scanner : MD5, SHA1, SHA224, SHA256, SHA512

* #### Others
- Information Gathering
  - [x] Clickjacking
  - [x] jQuery version checking
  - [x] Insecure cookie flags
  - [x] Testing HTTP methods
  - [x] Insecure headers
  - [x] Header/banner grabbing
  - Finder
    - [x] Find comments in source code
    - [x] Find e-mails in source code
- [ ] Session fixation through cookie injection
- [x] Brute force login through authorization headers
- [x] URL Fuzzer
- [x] WHOIS Lookup
- [x] Google Dork
- [ ] Error handler checker
- [x] Admin panel finder
- [x] Open redirect vulnerability
- [x] CMS Detection
- [x] Detect Honeypots
- [ ] Detect DDoS attack
- [ ] Detect De-authentication attack
- [ ] Detect ARP spoof attack

* #### Crawling
- [x] Crawl a website and collect all the links
- [x] Crawl and scrape the website for images

* #### Attacks
- [x] DDoS Attack
- [x] ARP Spoofer
- [ ] DNS Spoofer
- [x] De-authentication attack
- [ ] Network disassociation attack
- [X] Ping of death
- [x] MAC Flood attack

* #### Utilities
- [ ] Generate customized backdoor
- [ ] Data monitoring
- [X] Keylogger
- [ ] SSH Tunelling
- [ ] Generate sitemap
- [x] MAC address changer
- [ ] Trace route

## Usage

```
usage: vault.py [-h] [-u URL] [-p PORT] [-sp START_PORT] [-ep END_PORT] [-ssl]
                [-info] [-comment] [-email] [-fuzz] [-ip IP] [-t THREADS]
                [-i INTERFACE] [-source_port SOURCE_PORT] [-fin] [-null]
                [-ack] [-xmas] [-os_scan] [-xss] [-this] [-ping_sweep] [-arp]
                [-ip_start_range IP_START_RANGE] [-ip_end_range IP_END_RANGE]
                [-lfi] [-whois] [-o OUTPUT] [-d DORK] [-ddos] [-mac_flood]
                [-interval INTERVAL] [-cr] [-cri] [-all] [-exclude EXCLUDE]
                [-admin] [-orv] [-keylogger] [-host HOST] [-username USERNAME]
                [-password PASSWORD] [-sender SENDER]
                [-destination DESTINATION] [-arp_spoof] [-jquery]
                [-ping_death] [-bruteforce] [-hash] [-md5] [-sha1] [-sha224]
                [-sha256] [-sha512] [-dir DIR] [-detect_cms] [-change_mac]
                [-mac MAC] [-honey] [-target_bssid TARGET_BSSID] [-deauth]

VAULT

optional arguments:
  -h, --help            show this help message and exit
  -u URL, --url URL     URL for scanning
  -p PORT, --port PORT  Single port for scanning
  -sp START_PORT, --start_port START_PORT
                        Start port for scanning
  -ep END_PORT, --end_port END_PORT
                        End port for scanning
  -ssl                  perform SSL scan
  -info                 Gather information
  -comment              Finding comments
  -email                Finding emails
  -fuzz                 Fuzzing URL
  -ip IP, --ip IP       IP address for port scanning
  -t THREADS, --threads THREADS
                        Number of threads to use
  -i INTERFACE, --interface INTERFACE
                        Networking Interface to use
  -source_port SOURCE_PORT
                        Source port for sending packets
  -fin                  Perform FIN Scan
  -null                 Perform NULL Scan
  -ack                  Perform TCP ACK Scan
  -xmas                 Perform XMAS Scan
  -os_scan              Perform OS Scan
  -xss                  Scan for XSS vulnerabilities
  -this                 Only scan the given URL, do not crawl
  -ping_sweep           ICMP ECHO request
  -arp                  ARP Scan
  -ip_start_range IP_START_RANGE
                        Start range for scanning IP
  -ip_end_range IP_END_RANGE
                        End range for scanning IP
  -lfi                  Scan for LFI vulnerabilities
  -whois                perform a whois lookup of a given IP
  -o OUTPUT, --output OUTPUT
                        Output all data
  -d DORK, --dork DORK  Perform google dorking
  -ddos                 Perform DDoS attack
  -mac_flood            Perform MAC Flooding attack
  -interval INTERVAL    Interval time for sending packets
  -cr                   For extracting links from a web page
  -cri                  For extracting images from a Web page
  -all                  Run all scans
  -exclude EXCLUDE      Scans to exclude
  -admin                Find admin panel on a given domain
  -orv                  Test for open redirection Vulnerability
  -keylogger            Capture keystrokes and send them by email
  -host HOST            SMTP Host to use
  -username USERNAME    Username to login
  -password PASSWORD    Password to login
  -sender SENDER        Email to send from
  -destination DESTINATION
                        Email to send to
  -arp_spoof            ARP Spoofing
  -jquery               Check jQuery version and get vulnerabilities
  -ping_death           Perform ping of death attack
  -bruteforce           Perform brute force attack through
                        Authorizationheaders
  -hash                 Start hash scan
  -md5                  Scan MD5
  -sha1                 Scan SHA1
  -sha224               Scan SHA224
  -sha256               Scan SHA256
  -sha512               Scan SHA512
  -dir DIR              Directory to scan
  -detect_cms           Perform CMS Detection
  -change_mac           Chnage MAC address
  -mac MAC              New MAC address
  -honey                Detect honeypot
  -target_bssid TARGET_BSSID
                        Target BSSID
  -deauth               De-authentication attack
```

Example Usage : `python3 vault.py -u 'http://url' -info -comment -ssl -fuzz`

## Screenshot
![](logo/Initial_Setup.png)

## Contributing
Any and all contributions, [new-issues](https://github.com/abhisharma404/vault/issues/new/choose), [features](https://github.com/abhisharma404/vault/issues/new?template=feature_request.md) and tips are welcome.
Please refer to [`CONTRIBUTING.md`](https://github.com/abhisharma404/vault/blob/master/CONTRIBUTING.md) for more details.

## License
[![GitHub](https://img.shields.io/github/license/mashape/apistatus.svg)](https://github.com/abhisharma404/vault/blob/master/LICENSE.txt)

### This project is currently a part of IIT KWoC 2018.
