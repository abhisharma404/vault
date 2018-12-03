# VAULT Scanner

[![GitHub](https://img.shields.io/github/license/mashape/apistatus.svg)](https://github.com/abhisharma404/vault_scanner) [![Join the chat at https://gitter.im/vault_scanner/kwoc](https://badges.gitter.im/vault_scanner/Lobby.svg)](https://gitter.im/vault_scanner/Lobby?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge) ![Python](https://img.shields.io/badge/python-%3E%3D3-brightgreen.svg)

Vault Scanner can be used for:

* Scan a website for the following:
      - [XSS](https://www.owasp.org/index.php/Cross-site_Scripting_(XSS))
      - [LFI](https://en.wikipedia.org/wiki/File_inclusion_vulnerability#Local_File_Inclusion)
      - [RFI](https://en.wikipedia.org/wiki/File_inclusion_vulnerability#Remote_File_Inclusion)
      - [SQLi](https://en.wikipedia.org/wiki/SQL_injection)

* Common header erros:
      - Clickjacking
      - jQuery
      - Insecure cookie flags
      - Session fixation through a cookie injection
      - Spoofing Agents
      - Brute force login through authorization header
      - Testing http methods
      - Insecure headers

* Collecting data:
      - Port scanning
      - Header grabbing
      - Banner grabbing
      - Finding comments in source code
      - Smartwhois scan
      - Check if error handling is done or not and extract the site data using that information.
      - OS scanning.

* SSL scanner.

* Crawl a website and collect all the url related fields.

* Scrape a website and collect all the images.

* [URL fuzzing](https://en.wikipedia.org/wiki/Fuzzing).

* [Shellshock](https://en.wikipedia.org/wiki/Shellshock_(software_bug)) checking.

# Getting Started

Steps to setup :

1. `git clone <your-fork-url>`
2. `cd vault_scanner`
3. `sudo apt-get install python3-pip`
4. `sudo pip3 install virtualenv`
5. `virtualenv venv`
6. `source venv/bin/activate`
7. `pip3 install -r requirements.txt`

Starting Vault :

1. `cd vault_scanner/src`
2. `python3 vault.py`

# Usage

```
usage: vault.py [-h] [-u URL] [-p] [-sp] [-ep] [-ssl] [-info] [-comment]
                [-fuzz]

optional arguments:
  -h, --help         show this help message and exit
  -u URL, --url URL  URL for scanning
  -p, --port         Port for scanning
  -sp, --start_port  Start port for scanning
  -ep, --end_port    End port for scanning
  -ssl               perform SSL scan
  -info              Gather information
  -comment           Finding comments
  -fuzz              Fuzzing URL
```

Example Usage :

`python3 vault.py -u 'http://url' -info -comment -ssl -fuzz`
