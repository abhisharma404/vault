Parameters
===========

* ``-u`` or ``--url``
    This argument is to provide the URL that is to be tested.
    Ex: ``python vault.py -u http://example.com``

* ``-ip`` or ``--ip``
    This argument can used to provide ip that is to be scanned.
    Ex: ``python vault.py -ip 127.0.0.1``

* ``-source_port``
    Specifiy the source port that should be used for sending all the packets.

* ``-t`` or ``--threads``
    This argument can be used to define the number of threads to be used while performing all the checks.

*  ``-interval``
    This argument is used to give an interval of specific time for sending packets.

* ``-mac_flood``
    This argument can be used to change the mac address of the given interface.

* ``-all``
    This argument is used to run all the scan that are available in Vault.

Arguments that can only be used with -u or -url
************************************************

* ``-ssl``
    This argument can be used to perform SSL scan.
    This let you scan the target and list all SSL protocols and will show you if the target is vulnerable to any of SSL vulnerabilities

* ``-info``
    This argument will perform basic information gathering checks on the given target.
    The output from this can include HTTP methods used, Check if any insecure cookies are used or any insecure headers are present.

* ``-comment``
    This argument can be used to check if there are any comments present on the given URL.

* ``-fuzz``
    This argument can be used to peform fuzzing on the given URL.
    For fuzzing the payloads are used from the `fuzz_payloads.txt <https://github.com/abhisharma404/vault/tree/master/src/paylods/fuzz_payloads.txt>`_ file and that can be updated with custom payloads.

* ``-email``
    This argument can be used to check if any related email can be found.

* ``-xss``
    This argument is used to scan the target for XSS vulnerabilties.
    All the XSS payloads that are used during the scan are present in `xss_payloads.txt <https://github.com/abhisharma404/vault/tree/master/src/paylods/xss_payloads.txt>`_.

* ``-lfi``
    This argument is used to Scan target for any LFI vulnerabilties.
    All the LFI payloads that are used during the scan are present in `lfi_payloads.txt <https://github.com/abhisharma404/vault/tree/master/src/paylods/lfi_payloads.json>`_.

* ``-admin``
    This argument is used to find admin panel on the given target. This scan use predefined locations to check for admin panel.
    All the location used during the scan are present in `admin_payloads.txt <https://github.com/abhisharma404/vault/tree/master/src/paylods/admin_payload.txt>`_.

* ``-orv``
    This argument is used to find the open redirect vulnerability in the given target.
    Payload used for the scan is present in `orv_payloads.txt <https://github.com/abhisharma404/vault/tree/master/src/paylods/ORV_payload.txt>`_.

* ``-jqeury``
    This argument is used to check the jQuery version used on the given target and list out all the vulnerabilities related to that version, if any.

* ``-bruteforce``
    This argument is used to bruteforce logins on the given tagret. With this  ``-username`` argument has to be provided.
    The passwords used for brute force are taken from `10k-most-common-passwords.txt <../payloads/10k-most-common-passwords.txt>`_.

* ``cr``
    This argument is used to extract all the link from a webpage

* ``cri``
    This argument is used to extract all the images from a webpage

* ``-detect_cms``
    This argument is used to detect the CMS version the given target is running.


Arguments that can only be used with -ip
*****************************************

* ``-p`` or ``--port``
    This can used to provide a single port for port scanning.

* ``-sp`` or ``--start_port`` and ``-ep`` or ``--end_port``
    These arguments can be used to define the range of port for scanning.
    Ex: ``python vault.py -ip 127.0.0.1 -sp 9000 -ep 10000``

* ``whois``
    This can be used to perform a basic whois scan on the given IP.
    Ex: ``python vault.py -ip 127.0.0.1 -whois``

* ``-ping_sweep``
    This argument is used for performing `ping sweeps <https://en.wikipedia.org/wiki/Ping_sweep>`_ to map  s.

* ``-honey``
    This argument is used to check if the given IP is a honeypot or not.
    Ex: ``python vault.py -ip 127.0.0.1 -honey``

Arguments that can be used when the tool is used with SUDO privileages
***********************************************************************

* ``-xmas``
    This argument can be used to perform `xmas scan <https://en.wikipedia.org/wiki/Christmas_tree_packet>`_ on the given IP

* ``-fin``
    This argument can be used to perform `fin scan <https://security.stackexchange.com/questions/81486/fin-attack-what-is-this-type-of-attack-really/81496#81496>`_ on the given IP

* ``-null``
    This argument can be used to perform `null scan <https://capec.mitre.org/data/definitions/304.html>`_ on the given IP

* ``-ack``
    This argument can be used to perform `ack scan <https://nmap.org/book/scan-methods-ack-scan.html>`_ on the given IP

Attacks
********

* ``-arp``
    This argument can be used to perform `arp spoofing <https://en.wikipedia.org/wiki/ARP_spoofing>`_

    Required argument: ``-ip``

* ``-ping_death``
    This argument is used to perform the `ping of death <https://en.wikipedia.org/wiki/Ping_of_death>`_ attack.

    Required arguments: This attack works with both ``-ip`` or ``-u`` arguments.

* ``-deauth``
    This argument is used to perform the `deauthentication attack <https://en.wikipedia.org/wiki/Wi-Fi_deauthentication_attack>`_.

    Optional arguments:

        - ``-i`` or ``--interface``
        - ``-target_bssid``

* ``-ddos``
    This argument is used to perform `DDOS attack <https://en.wikipedia.org/wiki/Denial-of-service_attack>`_.

    Required argument: ``-ip`` or ``-u``

    Optional arguments:
        - ``-sp``
        - ``-ep``
        - ``-t``
        - ``-interval``

