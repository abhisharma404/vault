# VAULT Scanner

[![GitHub](https://img.shields.io/github/license/mashape/apistatus.svg)](https://github.com/abhisharma404/vault_scanner) [![Join the chat at https://gitter.im/vault_scanner/kwoc](https://badges.gitter.im/vault_scanner/Lobby.svg)](https://gitter.im/vault_scanner/Lobby?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge) ![Python](https://img.shields.io/badge/python-%3E%3D3-brightgreen.svg)

Vault Scanner can be used for:

1. Scan a website for the following - 1. XSS
                                        2. LFI
                                        3. RFI
                                        4. SQLi

  2. Common header erros : 1. Clickjacking
                           2. jQuery
                           3. Insecure cookie flags
                           4. Session fixation through a cookie injection
                           5. Spoofing Agents
                           6. Brute force login through authorization header
                           7. Testing http methods
                           8. Insecure headers

  3. Collecting data 1. Port scanning
                     2. Header grabbing
                     3. Banner grabbing
                     4. Finding comments in source code
                     5. Smartwhois scan
                     6. Check if error handling is done or not and extract the site data using that information
                     7. OS scanning

  4. SSL scanner

  5. Crawl a website and collect all the url related fields

  6. Scrap a website and collect all the images

  7. URL fuzzing

  8. Shellsock checking
  
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
