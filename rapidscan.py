#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#                               __         __
#                              /__)_   '_/(  _ _
#                             / ( (//)/(/__)( (//)
#                                  /
#
# Author     : Shankar Narayana Damodaran
# Tool       : RapidScan v1.2
# Usage      : python3 rapidsan.py example.com
# Description: This scanner automates the process of security scanning by using a
#              multitude of available linux security tools and some custom scripts.
#

# Importing the libraries
import sys
import argparse
import subprocess
import os
import time
import random
import threading
import re
import random
from urllib.parse import urlsplit


CURSOR_UP_ONE = '\x1b[1A' 
ERASE_LINE = '\x1b[2K'

# Scan Time Elapser
intervals = (
    ('h', 3600),
    ('m', 60),
    ('s', 1),
    )
def display_time(seconds, granularity=3):
    result = []
    seconds = seconds + 1
    for name, count in intervals:
        value = seconds // count
        if value:
            seconds -= value * count
            result.append("{}{}".format(value, name))
    return ' '.join(result[:granularity])


def terminal_size():
    try:
        rows, columns = subprocess.check_output(['stty', 'size']).split()
        return int(columns)
    except subprocess.CalledProcessError as e:
        return int(20)
    


def url_maker(url):
    if not re.match(r'http(s?)\:', url):
        url = 'http://' + url
    parsed = urlsplit(url)
    host = parsed.netloc
    if host.startswith('www.'):
        host = host[4:]
    return host

def check_internet():
    os.system('ping -c1 github.com > rs_net 2>&1')
    if "0% packet loss" in open('rs_net').read():
        val = 1
    else:
        val = 0
    os.system('rm rs_net > /dev/null 2>&1')
    return val


# Initializing the color module class
class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    BADFAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

    BG_ERR_TXT  = '\033[41m' # For critical errors and crashes
    BG_HEAD_TXT = '\033[100m'
    BG_ENDL_TXT = '\033[46m'
    BG_CRIT_TXT = '\033[45m'
    BG_HIGH_TXT = '\033[41m'
    BG_MED_TXT  = '\033[43m'
    BG_LOW_TXT  = '\033[44m'
    BG_INFO_TXT = '\033[42m'

    BG_SCAN_TXT_START = '\x1b[6;30;42m'
    BG_SCAN_TXT_END   = '\x1b[0m'


# Classifies the Vulnerability's Severity
def vul_info(val):
    result =''
    if val == 'c':
        result = bcolors.BG_CRIT_TXT+" critical "+bcolors.ENDC
    elif val == 'h':
        result = bcolors.BG_HIGH_TXT+" high "+bcolors.ENDC
    elif val == 'm':
        result = bcolors.BG_MED_TXT+" medium "+bcolors.ENDC
    elif val == 'l':
        result = bcolors.BG_LOW_TXT+" low "+bcolors.ENDC
    else:
        result = bcolors.BG_INFO_TXT+" info "+bcolors.ENDC
    return result

# Legends
proc_high = bcolors.BADFAIL + "●" + bcolors.ENDC
proc_med  = bcolors.WARNING + "●" + bcolors.ENDC
proc_low  = bcolors.OKGREEN + "●" + bcolors.ENDC

# Links the vulnerability with threat level and remediation database
def vul_remed_info(v1,v2,v3):
    print(bcolors.BOLD+"Vulnerability Threat Level"+bcolors.ENDC)
    print("\t"+vul_info(v2)+" "+bcolors.WARNING+str(tool_resp[v1][0])+bcolors.ENDC)
    print(bcolors.BOLD+"Vulnerability Definition"+bcolors.ENDC)
    print("\t"+bcolors.BADFAIL+str(tools_fix[v3-1][1])+bcolors.ENDC)
    print(bcolors.BOLD+"Vulnerability Remediation"+bcolors.ENDC)
    print("\t"+bcolors.OKGREEN+str(tools_fix[v3-1][2])+bcolors.ENDC)


# RapidScan Help Context
def helper():
        print(bcolors.OKBLUE+"Information:"+bcolors.ENDC)
        print("------------")
        print("\t./rapidscan.py example.com: Scans the domain example.com.")
        print("\t./rapidscan.py example.com --skip dmitry --skip theHarvester: Skip the 'dmitry' and 'theHarvester' tests.")
        print("\t./rapidscan.py example.com --nospinner: Disable the idle loader/spinner.")
        print("\t./rapidscan.py --update   : Updates the scanner to the latest version.")
        print("\t./rapidscan.py --help     : Displays this help context.")
        print(bcolors.OKBLUE+"Interactive:"+bcolors.ENDC)
        print("------------")
        print("\tCtrl+C: Skips current test.")
        print("\tCtrl+Z: Quits RapidScan.")
        print(bcolors.OKBLUE+"Legends:"+bcolors.ENDC)
        print("--------")
        print("\t["+proc_high+"]: Scan process may take longer times (not predictable).")
        print("\t["+proc_med+"]: Scan process may take less than 10 minutes.")
        print("\t["+proc_low+"]: Scan process may take less than a minute or two.")
        print(bcolors.OKBLUE+"Vulnerability Information:"+bcolors.ENDC)
        print("--------------------------")
        print("\t"+vul_info('c')+": Requires immediate attention as it may lead to compromise or service unavailability.")
        print("\t"+vul_info('h')+"    : May not lead to an immediate compromise, but there are considerable chances for probability.")
        print("\t"+vul_info('m')+"  : Attacker may correlate multiple vulnerabilities of this type to launch a sophisticated attack.")
        print("\t"+vul_info('l')+"     : Not a serious issue, but it is recommended to tend to the finding.")
        print("\t"+vul_info('i')+"    : Not classified as a vulnerability, simply an useful informational alert to be considered.\n")


# Clears Line
def clear():
        sys.stdout.write("\033[F")
        sys.stdout.write("\033[K") #clears until EOL

# RapidScan Logo
def logo():
    print(bcolors.WARNING)
    logo_ascii = """
                                  __         __
                                 /__)_  """+bcolors.BADFAIL+" ●"+bcolors.WARNING+"""_/(  _ _
                                / ( (//)/(/__)( (//)
                                     /
                     """+bcolors.ENDC+"""(The Multi-Tool Web Vulnerability Scanner)

                     Check out our new software, """+bcolors.BG_LOW_TXT+"""NetBot"""+bcolors.ENDC+""" for simulating DDoS attacks - https://github.com/skavngr/netbot
    """
    print(logo_ascii)
    print(bcolors.ENDC)


# Initiliazing the idle loader/spinner class
class Spinner:
    busy = False
    delay = 0.005 # 0.05

    @staticmethod
    def spinning_cursor():
        while 1:
            #for cursor in '|/-\\/': yield cursor #←↑↓→
            #for cursor in '←↑↓→': yield cursor
            #for cursor in '....scanning...please..wait....': yield cursor
            for cursor in ' ': yield cursor
    def __init__(self, delay=None):
        self.spinner_generator = self.spinning_cursor()
        if delay and float(delay): self.delay = delay
        self.disabled = False

    def spinner_task(self):
        inc = 0
        try:
            while self.busy:
                if not self.disabled:
                    x = bcolors.BG_SCAN_TXT_START+next(self.spinner_generator)+bcolors.BG_SCAN_TXT_END
                    inc = inc + 1
                    print(x,end='')
                    if inc>random.uniform(0,terminal_size()): #30 init
                        print(end="\r")
                        bcolors.BG_SCAN_TXT_START = '\x1b[6;30;'+str(round(random.uniform(40,47)))+'m'
                        inc = 0
                    sys.stdout.flush()
                time.sleep(self.delay)
                if not self.disabled:
                    sys.stdout.flush()

        except (KeyboardInterrupt, SystemExit):
            print("\n\t"+ bcolors.BG_ERR_TXT+"RapidScan received a series of Ctrl+C hits. Quitting..." +bcolors.ENDC)
            sys.exit(1)

    def start(self):
        self.busy = True
        try:
            threading.Thread(target=self.spinner_task).start()
        except Exception as e:
            print("\n")
        
    def stop(self):
        try:
            self.busy = False
            time.sleep(self.delay)
        except (KeyboardInterrupt, SystemExit):
            print("\n\t"+ bcolors.BG_ERR_TXT+"RapidScan received a series of Ctrl+C hits. Quitting..." +bcolors.ENDC)
            sys.exit(1)

# End ofloader/spinner class

# Instantiating the spinner/loader class
spinner = Spinner()



# Scanners that will be used and filename rotation (default: enabled (1))
tool_names = [
                #1
                ["host","Host - Checks for existence of IPV6 address.","host",1],

                #2
                ["aspnet_config_err","ASP.Net Misconfiguration - Checks for ASP.Net Misconfiguration.","wget",1],

                #3
                ["wp_check","WordPress Checker - Checks for WordPress Installation.","wget",1],

                #4
                ["drp_check", "Drupal Checker - Checks for Drupal Installation.","wget",1],

                #5
                ["joom_check", "Joomla Checker - Checks for Joomla Installation.","wget",1],

                #6
                ["uniscan","Uniscan - Checks for robots.txt & sitemap.xml","uniscan",1],

                #7
                ["wafw00f","Wafw00f - Checks for Application Firewalls.","wafw00f",1],

                #8
                ["nmap","Nmap - Fast Scan [Only Few Port Checks]","nmap",1],

                #9
                ["theHarvester","The Harvester - Scans for emails using Google's passive search.","theHarvester",1],

                #10
                ["dnsrecon","DNSRecon - Attempts Multiple Zone Transfers on Nameservers.","dnsrecon",1],

                #11
                #["fierce","Fierce - Attempts Zone Transfer [No Brute Forcing]","fierce",1],

                #12
                ["dnswalk","DNSWalk - Attempts Zone Transfer.","dnswalk",1],

                #13
                ["whois","WHOis - Checks for Administrator's Contact Information.","whois",1],

                #14
                ["nmap_header","Nmap [XSS Filter Check] - Checks if XSS Protection Header is present.","nmap",1],

                #15
                ["nmap_sloris","Nmap [Slowloris DoS] - Checks for Slowloris Denial of Service Vulnerability.","nmap",1],

                #16
                ["sslyze_hbleed","SSLyze - Checks only for Heartbleed Vulnerability.","sslyze",1],

                #17
                ["nmap_hbleed","Nmap [Heartbleed] - Checks only for Heartbleed Vulnerability.","nmap",1],

                #18
                ["nmap_poodle","Nmap [POODLE] - Checks only for Poodle Vulnerability.","nmap",1],

                #19
                ["nmap_ccs","Nmap [OpenSSL CCS Injection] - Checks only for CCS Injection.","nmap",1],

                #20
                ["nmap_freak","Nmap [FREAK] - Checks only for FREAK Vulnerability.","nmap",1],

                #21
                ["nmap_logjam","Nmap [LOGJAM] - Checks for LOGJAM Vulnerability.","nmap",1],

                #22
                ["sslyze_ocsp","SSLyze - Checks for OCSP Stapling.","sslyze",1],

                #23
                ["sslyze_zlib","SSLyze - Checks for ZLib Deflate Compression.","sslyze",1],

                #24
                ["sslyze_reneg","SSLyze - Checks for Secure Renegotiation Support and Client Renegotiation.","sslyze",1],

                #25
                ["sslyze_resum","SSLyze - Checks for Session Resumption Support with [Session IDs/TLS Tickets].","sslyze",1],

                #26
                ["lbd","LBD - Checks for DNS/HTTP Load Balancers.","lbd",1],

                #27
                ["golismero_dns_malware","Golismero - Checks if the domain is spoofed or hijacked.","golismero",1],

                #28
                ["golismero_heartbleed","Golismero - Checks only for Heartbleed Vulnerability.","golismero",1],

                #29
                ["golismero_brute_url_predictables","Golismero - BruteForces for certain files on the Domain.","golismero",1],

                #30
                ["golismero_brute_directories","Golismero - BruteForces for certain directories on the Domain.","golismero",1],

                #31
                ["golismero_sqlmap","Golismero - SQLMap [Retrieves only the DB Banner]","golismero",1],

                #32
                ["dirb","DirB - Brutes the target for Open Directories.","dirb",1],

                #33
                ["xsser","XSSer - Checks for Cross-Site Scripting [XSS] Attacks.","xsser",1],

                #34
                ["golismero_ssl_scan","Golismero SSL Scans - Performs SSL related Scans.","golismero",1],

                #35
                ["golismero_zone_transfer","Golismero Zone Transfer - Attempts Zone Transfer.","golismero",1],

                #36
                ["golismero_nikto","Golismero Nikto Scans - Uses Nikto Plugin to detect vulnerabilities.","golismero",1],

                #37
                ["golismero_brute_subdomains","Golismero Subdomains Bruter - Brute Forces Subdomain Discovery.","golismero",1],

                #38
                ["dnsenum_zone_transfer","DNSEnum - Attempts Zone Transfer.","dnsenum",1],

                #39
                ["fierce_brute_subdomains","Fierce Subdomains Bruter - Brute Forces Subdomain Discovery.","fierce",1],

                #40
                ["dmitry_email","DMitry - Passively Harvests Emails from the Domain.","dmitry",1],

                #41
                ["dmitry_subdomains","DMitry - Passively Harvests Subdomains from the Domain.","dmitry",1],

                #42
                ["nmap_telnet","Nmap [TELNET] - Checks if TELNET service is running.","nmap",1],

                #43
                ["nmap_ftp","Nmap [FTP] - Checks if FTP service is running.","nmap",1],

                #44
                ["nmap_stuxnet","Nmap [STUXNET] - Checks if the host is affected by STUXNET Worm.","nmap",1],

                #45
                ["webdav","WebDAV - Checks if WEBDAV enabled on Home directory.","davtest",1],

                #46
                ["golismero_finger","Golismero - Does a fingerprint on the Domain.","golismero",1],

                #47
                ["uniscan_filebrute","Uniscan - Brutes for Filenames on the Domain.","uniscan",1],

                #48
                ["uniscan_dirbrute", "Uniscan - Brutes Directories on the Domain.","uniscan",1],

                #49
                ["uniscan_ministresser", "Uniscan - Stress Tests the Domain.","uniscan",1],

                #50
                ["uniscan_rfi","Uniscan - Checks for LFI, RFI and RCE.","uniscan",1],

                #51
                ["uniscan_xss","Uniscan - Checks for XSS, SQLi, BSQLi & Other Checks.","uniscan",1],

                #52
                ["nikto_xss","Nikto - Checks for Apache Expect XSS Header.","nikto",1],

                #53
                ["nikto_subrute","Nikto - Brutes Subdomains.","nikto",1],

                #54
                ["nikto_shellshock","Nikto - Checks for Shellshock Bug.","nikto",1],

                #55
                ["nikto_internalip","Nikto - Checks for Internal IP Leak.","nikto",1],

                #56
                ["nikto_putdel","Nikto - Checks for HTTP PUT DEL.","nikto",1],

                #57
                ["nikto_headers","Nikto - Checks the Domain Headers.","nikto",1],

                #58
                ["nikto_ms01070","Nikto - Checks for MS10-070 Vulnerability.","nikto",1],

                #59
                ["nikto_servermsgs","Nikto - Checks for Server Issues.","nikto",1],

                #60
                ["nikto_outdated","Nikto - Checks if Server is Outdated.","nikto",1],

                #61
                ["nikto_httpoptions","Nikto - Checks for HTTP Options on the Domain.","nikto",1],

                #62
                ["nikto_cgi","Nikto - Enumerates CGI Directories.","nikto",1],

                #63
                ["nikto_ssl","Nikto - Performs SSL Checks.","nikto",1],

                #64
                ["nikto_sitefiles","Nikto - Checks for any interesting files on the Domain.","nikto",1],

                #65
                ["nikto_paths","Nikto - Checks for Injectable Paths.","nikto",1],

                #66
                ["dnsmap_brute","DNSMap - Brutes Subdomains.","dnsmap",1],

                #67
                ["nmap_sqlserver","Nmap - Checks for MS-SQL Server DB","nmap",1],

                #68
                ["nmap_mysql", "Nmap - Checks for MySQL DB","nmap",1],

                #69
                ["nmap_oracle", "Nmap - Checks for ORACLE DB","nmap",1],

                #70
                ["nmap_rdp_udp","Nmap - Checks for Remote Desktop Service over UDP","nmap",1],

                #71
                ["nmap_rdp_tcp","Nmap - Checks for Remote Desktop Service over TCP","nmap",1],

                #72
                ["nmap_full_ps_tcp","Nmap - Performs a Full TCP Port Scan","nmap",1],

                #73
                ["nmap_full_ps_udp","Nmap - Performs a Full UDP Port Scan","nmap",1],

                #74
                ["nmap_snmp","Nmap - Checks for SNMP Service","nmap",1],

                #75
                ["aspnet_elmah_axd","Checks for ASP.net Elmah Logger","wget",1],

                #76
                ["nmap_tcp_smb","Checks for SMB Service over TCP","nmap",1],

                #77
                ["nmap_udp_smb","Checks for SMB Service over UDP","nmap",1],

                #78
                ["wapiti","Wapiti - Checks for SQLi, RCE, XSS and Other Vulnerabilities","wapiti",1],

                #79
                ["nmap_iis","Nmap - Checks for IIS WebDAV","nmap",1],

                #80
                ["whatweb","WhatWeb - Checks for X-XSS Protection Header","whatweb",1],

                #81
                ["amass","AMass - Brutes Domain for Subdomains","amass",1]
            ]


# Command that is used to initiate the tool (with parameters and extra params)
tool_cmd   = [
                #1
                ["host ",""],

                #2
                ["wget -O /tmp/rapidscan_temp_aspnet_config_err --tries=1 ","/%7C~.aspx"],

                #3
                ["wget -O /tmp/rapidscan_temp_wp_check --tries=1 ","/wp-admin"],

                #4
                ["wget -O /tmp/rapidscan_temp_drp_check --tries=1 ","/user"],

                #5
                ["wget -O /tmp/rapidscan_temp_joom_check --tries=1 ","/administrator"],

                #6
                ["uniscan -e -u ",""],

                #7
                ["wafw00f ",""],

                #8
                ["nmap -F --open -Pn ",""],

                #9
                ["theHarvester -l 50 -b censys -d ",""],

                #10
                ["dnsrecon -d ",""],

                #11
                #["fierce -wordlist xxx -dns ",""],

                #12
                ["dnswalk -d ","."],

                #13
                ["whois ",""],

                #14
                ["nmap -p80 --script http-security-headers -Pn ",""],

                #15
                ["nmap -p80,443 --script http-slowloris --max-parallelism 500 -Pn ",""],

                #16
                ["sslyze --heartbleed ",""],

                #17
                ["nmap -p443 --script ssl-heartbleed -Pn ",""],

                #18
                ["nmap -p443 --script ssl-poodle -Pn ",""],

                #19
                ["nmap -p443 --script ssl-ccs-injection -Pn ",""],

                #20
                ["nmap -p443 --script ssl-enum-ciphers -Pn ",""],

                #21
                ["nmap -p443 --script ssl-dh-params -Pn ",""],

                #22
                ["sslyze --certinfo=basic ",""],

                #23
                ["sslyze --compression ",""],

                #24
                ["sslyze --reneg ",""],

                #25
                ["sslyze --resum ",""],

                #26
                ["lbd ",""],

                #27
                ["golismero -e dns_malware scan ",""],

                #28
                ["golismero -e heartbleed scan ",""],

                #29
                ["golismero -e brute_url_predictables scan ",""],

                #30
                ["golismero -e brute_directories scan ",""],

                #31
                ["golismero -e sqlmap scan ",""],

                #32
                ["dirb http://"," -fi"],

                #33
                ["xsser --all=http://",""],

                #34
                ["golismero -e sslscan scan ",""],

                #35
                ["golismero -e zone_transfer scan ",""],

                #36
                ["golismero -e nikto scan ",""],

                #37
                ["golismero -e brute_dns scan ",""],

                #38
                ["dnsenum ",""],

                #39
                ["fierce --domain ",""],

                #40
                ["dmitry -e ",""],

                #41
                ["dmitry -s ",""],

                #42
                ["nmap -p23 --open -Pn ",""],

                #43
                ["nmap -p21 --open -Pn ",""],

                #44
                ["nmap --script stuxnet-detect -p445 -Pn ",""],

                #45
                ["davtest -url http://",""],

                #46
                ["golismero -e fingerprint_web scan ",""],

                #47
                ["uniscan -w -u ",""],

                #48
                ["uniscan -q -u ",""],

                #49
                ["uniscan -r -u ",""],

                #50
                ["uniscan -s -u ",""],

                #51
                ["uniscan -d -u ",""],

                #52
                ["nikto -Plugins 'apache_expect_xss' -host ",""],

                #53
                ["nikto -Plugins 'subdomain' -host ",""],

                #54
                ["nikto -Plugins 'shellshock' -host ",""],

                #55
                ["nikto -Plugins 'cookies' -host ",""],

                #56
                ["nikto -Plugins 'put_del_test' -host ",""],

                #57
                ["nikto -Plugins 'headers' -host ",""],

                #58
                ["nikto -Plugins 'ms10-070' -host ",""],

                #59
                ["nikto -Plugins 'msgs' -host ",""],

                #60
                ["nikto -Plugins 'outdated' -host ",""],

                #61
                ["nikto -Plugins 'httpoptions' -host ",""],

                #62
                ["nikto -Plugins 'cgi' -host ",""],

                #63
                ["nikto -Plugins 'ssl' -host ",""],

                #64
                ["nikto -Plugins 'sitefiles' -host ",""],

                #65
                ["nikto -Plugins 'paths' -host ",""],

                #66
                ["dnsmap ",""],

                #67
                ["nmap -p1433 --open -Pn ",""],

                #68
                ["nmap -p3306 --open -Pn ",""],

                #69
                ["nmap -p1521 --open -Pn ",""],

                #70
                ["nmap -p3389 --open -sU -Pn ",""],

                #71
                ["nmap -p3389 --open -sT -Pn ",""],

                #72
                ["nmap -p1-65535 --open -Pn ",""],

                #73
                ["nmap -p1-65535 -sU --open -Pn ",""],

                #74
                ["nmap -p161 -sU --open -Pn ",""],

                #75
                ["wget -O /tmp/rapidscan_temp_aspnet_elmah_axd --tries=1 ","/elmah.axd"],

                #76
                ["nmap -p445,137-139 --open -Pn ",""],

                #77
                ["nmap -p137,138 --open -Pn ",""],

                #78
                ["wapiti "," -f txt -o rapidscan_temp_wapiti"],

                #79
                ["nmap -p80 --script=http-iis-webdav-vuln -Pn ",""],
                
                #80
                ["whatweb "," -a 1"],

                #81
                ["amass enum -d ",""]
            ]


# Tool Responses (Begins) [Responses + Severity (c - critical | h - high | m - medium | l - low | i - informational) + Reference for Vuln Definition and Remediation]
tool_resp = [
    #1
    ["Tidak memiliki alamat IPv6. Sebaiknya memiliki satu.", "i", 1],

    #2
    ["ASP.Net salah dikonfigurasi sehingga menampilkan kesalahan server di layar.", "m", 2],

    #3
    ["Ditemukan instalasi WordPress. Periksa kerentanan yang sesuai dengan versi tersebut.", "i", 3],

    #4
    ["Ditemukan instalasi Drupal. Periksa kerentanan yang sesuai dengan versi tersebut.", "i", 4],

    #5
    ["Ditemukan instalasi Joomla. Periksa kerentanan yang sesuai dengan versi tersebut.", "i", 5],

    #6
    ["Ditemukan robots.txt/sitemap.xml. Periksa file tersebut untuk informasi sensitif.", "i", 6],

    #7
    ["Tidak ada Web Application Firewall yang terdeteksi.", "m", 7],

    #8
    ["Beberapa port terbuka. Lakukan pemindaian penuh secara manual.", "l", 8],

    #9
    ["Alamat email ditemukan.", "l", 9],

    #10
    ["Transfer zona berhasil menggunakan DNSRecon. Konfigurasikan ulang DNS segera.", "h", 10],

    #12
    ["Transfer zona berhasil menggunakan dnswalk. Konfigurasikan ulang DNS segera.", "h", 10],

    #13
    ["Informasi Whois tersedia untuk publik.", "i", 11],

    #14
    ["Filter perlindungan XSS dinonaktifkan.", "m", 12],

    #15
    ["Rentan terhadap serangan Slowloris Denial of Service.", "c", 13],

    #16
    ["Kerentanan HEARTBLEED ditemukan dengan SSLyze.", "h", 14],

    #17
    ["Kerentanan HEARTBLEED ditemukan dengan Nmap.", "h", 14],

    #18
    ["Kerentanan POODLE terdeteksi.", "h", 15],

    #19
    ["Injeksi OpenSSL CCS terdeteksi.", "h", 16],

    #20
    ["Kerentanan FREAK terdeteksi.", "h", 17],

    #21
    ["Kerentanan LOGJAM terdeteksi.", "h", 18],

    #22
    ["Respon OCSP tidak berhasil.", "m", 19],

    #23
    ["Server mendukung kompresi Deflate.", "m", 20],

    #24
    ["Renegosiasi aman yang dimulai oleh klien didukung.", "m", 21],

    #25
    ["Resumsi aman tidak didukung dengan (Session IDs/TLS Tickets).", "m", 22],

    #26
    ["Tidak ditemukan Load Balancer berbasis DNS/HTTP.", "l", 23],

    #27
    ["Domain telah dipalsukan/dibajak.", "h", 24],

    #28
    ["Kerentanan HEARTBLEED ditemukan dengan Golismero.", "h", 14],

    #29
    ["File terbuka ditemukan dengan BruteForce Golismero.", "m", 25],

    #30
    ["Direktori terbuka ditemukan dengan BruteForce Golismero.", "m", 26],

    #31
    ["Banner database diambil dengan SQLMap.", "l", 27],

    #32
    ["Direktori terbuka ditemukan dengan DirB.", "m", 26],

    #33
    ["XSSer menemukan kerentanan XSS.", "c", 28],

    #34
    ["Ditemukan kerentanan terkait SSL dengan Golismero.", "m", 29],

    #35
    ["Transfer zona berhasil dengan Golismero. Konfigurasikan ulang DNS segera.", "h", 10],

    #36
    ["Plugin Nikto Golismero menemukan kerentanan.", "m", 30],

    #37
    ["Subdomain ditemukan dengan Golismero.", "m", 31],

    #38
    ["Transfer zona berhasil menggunakan DNSEnum. Konfigurasikan ulang DNS segera.", "h", 10],

    #39
    ["Subdomain ditemukan dengan Fierce.", "m", 31],

    #40
    ["Alamat email ditemukan dengan DMitry.", "l", 9],

    #41
    ["Subdomain ditemukan dengan DMitry.", "m", 31],

    #42
    ["Layanan Telnet terdeteksi.", "h", 32],

    #43
    ["Layanan FTP terdeteksi.", "c", 33],

    #44
    ["Rentan terhadap STUXNET.", "c", 34],

    #45
    ["WebDAV diaktifkan.", "m", 35],

    #46
    ["Ditemukan beberapa informasi melalui Fingerprinting.", "l", 36],

    #47
    ["File terbuka ditemukan dengan Uniscan.", "m", 25],

    #48
    ["Direktori terbuka ditemukan dengan Uniscan.", "m", 26],

    #49
    ["Rentan terhadap pengujian stres.", "h", 37],

    #50
    ["Uniscan mendeteksi kemungkinan LFI, RFI, atau RCE.", "h", 38],

    #51
    ["Uniscan mendeteksi kemungkinan XSS, SQLi, atau BSQLi.", "h", 39],

    #52
    ["Header Apache Expect XSS tidak ada.", "m", 12],

    #53
    ["Subdomain ditemukan dengan Nikto.", "m", 31],

    #54
    ["Server web rentan terhadap bug Shellshock.", "c", 40],

    #55
    ["Server web membocorkan IP internal.", "l", 41],

    #56
    ["Metode HTTP PUT DEL diaktifkan.", "m", 42],

    #57
    ["Beberapa header rentan terpapar.", "m", 43],

    #58
    ["Server web rentan terhadap MS10-070.", "h", 44],

    #59
    ["Beberapa masalah ditemukan pada server web.", "m", 30],

    #60
    ["Server web sudah usang.", "h", 45],

    #61
    ["Beberapa masalah ditemukan dengan opsi HTTP.", "l", 42],

    #62
    ["Direktori CGI ditemukan.", "l", 26],

    #63
    ["Kerentanan dilaporkan dalam pemindaian SSL.", "m", 29],

    #64
    ["File menarik terdeteksi.", "m", 25],

    #65
    ["Jalur yang dapat diinjeksi terdeteksi.", "l", 46],

    #66
    ["Subdomain ditemukan dengan DNSMap.", "m", 31],

    #67
    ["Layanan database MS-SQL terdeteksi.", "l", 47],

    #68
    ["Layanan database MySQL terdeteksi.", "l", 47],

    #69
    ["Layanan database ORACLE terdeteksi.", "l", 47],

    #70
    ["Server RDP terdeteksi melalui UDP.", "h", 48],

    #71
    ["Server RDP terdeteksi melalui TCP.", "h", 48],

    #72
    ["Port TCP terbuka.", "l", 8],

    #73
    ["Port UDP terbuka.", "l", 8],

    #74
    ["Layanan SNMP terdeteksi.", "m", 49],

    #75
    ["Elmah dikonfigurasi.", "m", 50],

    #76
    ["Port SMB terbuka melalui TCP.", "m", 51],

    #77
    ["Port SMB terbuka melalui UDP.", "m", 51],

    #78
    ["Wapiti menemukan berbagai kerentanan.", "h", 30],

    #79
    ["IIS WebDAV diaktifkan.", "m", 35],

    #80
    ["X-XSS Protection tidak ada.", "m", 12],

    #81
    ["Subdomain ditemukan dengan AMass.", "m", 31]
]

# Tool Responses (Ends)



# Tool Status (Response Data + Response Code (if status check fails and you still got to push it + Legends + Approx Time + Tool Identification + Bad Responses)
tool_status = [
                #1
                ["has IPv6",1,proc_low," < 15s","ipv6",["not found","has IPv6"]],

                #2
                ["Server Error",0,proc_low," < 30s","asp.netmisconf",["unable to resolve host address","Connection timed out"]],

                #3
                ["wp-login",0,proc_low," < 30s","wpcheck",["unable to resolve host address","Connection timed out"]],

                #4
                ["drupal",0,proc_low," < 30s","drupalcheck",["unable to resolve host address","Connection timed out"]],

                #5
                ["joomla",0,proc_low," < 30s","joomlacheck",["unable to resolve host address","Connection timed out"]],

                #6
                ["[+]",0,proc_low," < 40s","robotscheck",["Use of uninitialized value in unpack at"]],

                #7
                ["No WAF",0,proc_low," < 45s","wafcheck",["appears to be down"]],

                #8
                ["tcp open",0,proc_med," <  2m","nmapopen",["Failed to resolve"]],

                #9
                ["No emails found",1,proc_med," <  3m","harvester",["No hosts found","No emails found"]],

                #10
                ["[+] Zone Transfer was successful!!",0,proc_low," < 20s","dnsreconzt",["Could not resolve domain"]],

                #11
                #["Whoah, it worked",0,proc_low," < 30s","fiercezt",["none"]],

                #12
                ["0 errors",0,proc_low," < 35s","dnswalkzt",["!!!0 failures, 0 warnings, 3 errors."]],

                #13
                ["Admin Email:",0,proc_low," < 25s","whois",["No match for domain"]],

                #14
                ["XSS filter is disabled",0,proc_low," < 20s","nmapxssh",["Failed to resolve"]],

                #15
                ["VULNERABLE",0,proc_high," < 45m","nmapdos",["Failed to resolve"]],

                #16
                ["Server is vulnerable to Heartbleed",0,proc_low," < 40s","sslyzehb",["Could not resolve hostname"]],

                #17
                ["VULNERABLE",0,proc_low," < 30s","nmap1",["Failed to resolve"]],

                #18
                ["VULNERABLE",0,proc_low," < 35s","nmap2",["Failed to resolve"]],

                #19
                ["VULNERABLE",0,proc_low," < 35s","nmap3",["Failed to resolve"]],

                #20
                ["VULNERABLE",0,proc_low," < 30s","nmap4",["Failed to resolve"]],

                #21
                ["VULNERABLE",0,proc_low," < 35s","nmap5",["Failed to resolve"]],

                #22
                ["ERROR - OCSP response status is not successful",0,proc_low," < 25s","sslyze1",["Could not resolve hostname"]],

                #23
                ["VULNERABLE",0,proc_low," < 30s","sslyze2",["Could not resolve hostname"]],

                #24
                ["VULNERABLE",0,proc_low," < 25s","sslyze3",["Could not resolve hostname"]],

                #25
                ["VULNERABLE",0,proc_low," < 30s","sslyze4",["Could not resolve hostname"]],

                #26
                ["does NOT use Load-balancing",0,proc_med," <  4m","lbd",["NOT FOUND"]],

                #27
                ["No vulnerabilities found",1,proc_low," < 45s","golism1",["Cannot resolve domain name","No vulnerabilities found"]],

                #28
                ["No vulnerabilities found",1,proc_low," < 40s","golism2",["Cannot resolve domain name","No vulnerabilities found"]],

                #29
                ["No vulnerabilities found",1,proc_low," < 45s","golism3",["Cannot resolve domain name","No vulnerabilities found"]],

                #30
                ["No vulnerabilities found",1,proc_low," < 40s","golism4",["Cannot resolve domain name","No vulnerabilities found"]],

                #31
                ["No vulnerabilities found",1,proc_low," < 45s","golism5",["Cannot resolve domain name","No vulnerabilities found"]],

                #32
                ["FOUND: 0",1,proc_high," < 35m","dirb",["COULDNT RESOLVE HOST","FOUND: 0"]],

                #33
                ["Could not find any vulnerability!",1,proc_med," <  4m","xsser",["XSSer is not working propertly!","Could not find any vulnerability!"]],

                #34
                ["Occurrence ID",0,proc_low," < 45s","golism6",["Cannot resolve domain name"]],

                #35
                ["DNS zone transfer successful",0,proc_low," < 30s","golism7",["Cannot resolve domain name"]],

                #36
                ["Nikto found 0 vulnerabilities",1,proc_med," <  4m","golism8",["Cannot resolve domain name","Nikto found 0 vulnerabilities"]],

                #37
                ["Possible subdomain leak",0,proc_high," < 30m","golism9",["Cannot resolve domain name"]],

                #38
                ["AXFR record query failed:",1,proc_low," < 45s","dnsenumzt",["NS record query failed:","AXFR record query failed","no NS record for"]],

                #39
                ["Found 0 entries",1,proc_high," < 75m","fierce2",["Found 0 entries","is gimp"]],

                #40
                ["Found 0 E-Mail(s)",1,proc_low," < 30s","dmitry1",["Unable to locate Host IP addr","Found 0 E-Mail(s)"]],

                #41
                ["Found 0 possible subdomain(s)",1,proc_low," < 35s","dmitry2",["Unable to locate Host IP addr","Found 0 possible subdomain(s)"]],

                #42
                ["open",0,proc_low," < 15s","nmaptelnet",["Failed to resolve"]],

                #43
                ["open",0,proc_low," < 15s","nmapftp",["Failed to resolve"]],

                #44
                ["open",0,proc_low," < 20s","nmapstux",["Failed to resolve"]],

                #45
                ["SUCCEED",0,proc_low," < 30s","webdav",["is not DAV enabled or not accessible."]],

                #46
                ["No vulnerabilities found",1,proc_low," < 15s","golism10",["Cannot resolve domain name","No vulnerabilities found"]],

                #47
                ["[+]",0,proc_med," <  2m","uniscan2",["Use of uninitialized value in unpack at"]],

                #48
                ["[+]",0,proc_med," <  5m","uniscan3",["Use of uninitialized value in unpack at"]],

                #49
                ["[+]",0,proc_med," <  9m","uniscan4",["Use of uninitialized value in unpack at"]],

                #50
                ["[+]",0,proc_med," <  8m","uniscan5",["Use of uninitialized value in unpack at"]],

                #51
                ["[+]",0,proc_med," <  9m","uniscan6",["Use of uninitialized value in unpack at"]],

                #52
                ["0 item(s) reported",1,proc_low," < 35s","nikto1",["ERROR: Cannot resolve hostname","0 item(s) reported","No web server found","0 host(s) tested"]],

                #53
                ["0 item(s) reported",1,proc_low," < 35s","nikto2",["ERROR: Cannot resolve hostname","0 item(s) reported","No web server found","0 host(s) tested"]],

                #54
                ["0 item(s) reported",1,proc_low," < 35s","nikto3",["ERROR: Cannot resolve hostname","0 item(s) reported","No web server found","0 host(s) tested"]],

                #55
                ["0 item(s) reported",1,proc_low," < 35s","nikto4",["ERROR: Cannot resolve hostname","0 item(s) reported","No web server found","0 host(s) tested"]],

                #56
                ["0 item(s) reported",1,proc_low," < 35s","nikto5",["ERROR: Cannot resolve hostname","0 item(s) reported","No web server found","0 host(s) tested"]],

                #57
                ["0 item(s) reported",1,proc_low," < 35s","nikto6",["ERROR: Cannot resolve hostname","0 item(s) reported","No web server found","0 host(s) tested"]],

                #58
                ["0 item(s) reported",1,proc_low," < 35s","nikto7",["ERROR: Cannot resolve hostname","0 item(s) reported","No web server found","0 host(s) tested"]],

                #59
                ["0 item(s) reported",1,proc_low," < 35s","nikto8",["ERROR: Cannot resolve hostname","0 item(s) reported","No web server found","0 host(s) tested"]],

                #60
                ["0 item(s) reported",1,proc_low," < 35s","nikto9",["ERROR: Cannot resolve hostname","0 item(s) reported","No web server found","0 host(s) tested"]],

                #61
                ["0 item(s) reported",1,proc_low," < 35s","nikto10",["ERROR: Cannot resolve hostname","0 item(s) reported","No web server found","0 host(s) tested"]],

                #62
                ["0 item(s) reported",1,proc_low," < 35s","nikto11",["ERROR: Cannot resolve hostname","0 item(s) reported","No web server found","0 host(s) tested"]],

                #63
                ["0 item(s) reported",1,proc_low," < 35s","nikto12",["ERROR: Cannot resolve hostname","0 item(s) reported","No web server found","0 host(s) tested"]],

                #64
                ["0 item(s) reported",1,proc_low," < 35s","nikto13",["ERROR: Cannot resolve hostname","0 item(s) reported","No web server found","0 host(s) tested"]],

                #65
                ["0 item(s) reported",1,proc_low," < 35s","nikto14","ERROR: Cannot resolve hostname , 0 item(s) reported"],

                #66
                ["#1",0,proc_high," < 30m","dnsmap_brute",["[+] 0 (sub)domains and 0 IP address(es) found"]],

                #67
                ["open",0,proc_low," < 15s","nmapmssql",["Failed to resolve"]],

                #68
                ["open",0,proc_low," < 15s","nmapmysql",["Failed to resolve"]],

                #69
                ["open",0,proc_low," < 15s","nmaporacle",["Failed to resolve"]],

                #70
                ["open",0,proc_low," < 15s","nmapudprdp",["Failed to resolve"]],

                #71
                ["open",0,proc_low," < 15s","nmaptcprdp",["Failed to resolve"]],

                #72
                ["open",0,proc_high," > 50m","nmapfulltcp",["Failed to resolve"]],

                #73
                ["open",0,proc_high," > 75m","nmapfulludp",["Failed to resolve"]],

                #74
                ["open",0,proc_low," < 30s","nmapsnmp",["Failed to resolve"]],

                #75
                ["Microsoft SQL Server Error Log",0,proc_low," < 30s","elmahxd",["unable to resolve host address","Connection timed out"]],

                #76
                ["open",0,proc_low," < 20s","nmaptcpsmb",["Failed to resolve"]],

                #77
                ["open",0,proc_low," < 20s","nmapudpsmb",["Failed to resolve"]],

                #78
                ["Host:",0,proc_med," < 5m","wapiti",["none"]],

                #79
                ["WebDAV is ENABLED",0,proc_low," < 40s","nmapwebdaviis",["Failed to resolve"]],

                #80
                ["X-XSS-Protection[1",1,proc_med," < 3m","whatweb",["Timed out","Socket error","X-XSS-Protection[1"]],

                #81
                ["No names were discovered",1,proc_med," < 15m","amass",["The system was unable to build the pool of resolvers"]]



            ]

# Vulnerabilities and Remediation
tools_fix = [
    [1, "Bukan kerentanan, hanya peringatan informasi. Host tidak memiliki dukungan IPv6. IPv6 memberikan keamanan lebih karena IPSec (bertanggung jawab atas CIA - Confidentiality, Integrity, dan Availability) dimasukkan ke dalam model ini. Jadi, disarankan untuk memiliki dukungan IPv6.",
        "Disarankan untuk mengimplementasikan IPv6. Informasi lebih lanjut tentang cara mengimplementasikan IPv6 dapat ditemukan di sumber ini: https://www.cisco.com/c/en/us/solutions/collateral/enterprise/cisco-on-cisco/IPv6-Implementation_CS.html"],
    [2, "Kebocoran Informasi Sensitif Terdeteksi. Aplikasi ASP.Net tidak memfilter karakter ilegal dalam URL. Penyerang menyisipkan karakter khusus (%7C~.aspx) untuk membuat aplikasi menampilkan informasi sensitif tentang server.",
        "Disarankan untuk memfilter karakter khusus dalam URL dan mengatur halaman kesalahan khusus dalam situasi seperti itu daripada menampilkan pesan kesalahan default. Sumber ini membantu Anda mengatur halaman kesalahan khusus pada aplikasi Microsoft .Net: https://docs.microsoft.com/en-us/aspnet/web-forms/overview/older-versions-getting-started/deploying-web-site-projects/displaying-a-custom-error-page-cs"],
    [3, "Tidak buruk memiliki CMS seperti WordPress. Namun, ada kemungkinan versi tersebut mengandung kerentanan atau skrip pihak ketiga yang terkait dengannya memiliki kerentanan.",
        "Disarankan untuk menyembunyikan versi WordPress. Sumber ini berisi informasi lebih lanjut tentang cara mengamankan blog WordPress Anda: https://codex.wordpress.org/Hardening_WordPress"],
    [4, "Tidak buruk memiliki CMS seperti Drupal. Namun, ada kemungkinan versi tersebut mengandung kerentanan atau skrip pihak ketiga yang terkait dengannya memiliki kerentanan.",
        "Disarankan untuk menyembunyikan versi Drupal. Sumber ini berisi informasi lebih lanjut tentang cara mengamankan blog Drupal Anda: https://www.drupal.org/docs/7/site-building-best-practices/ensure-that-your-site-is-secure"],
    [5, "Tidak buruk memiliki CMS seperti Joomla. Namun, ada kemungkinan versi tersebut mengandung kerentanan atau skrip pihak ketiga yang terkait dengannya memiliki kerentanan.",
        "Disarankan untuk menyembunyikan versi Joomla. Sumber ini berisi informasi lebih lanjut tentang cara mengamankan blog Joomla Anda: https://www.incapsula.com/blog/10-tips-to-improve-your-joomla-website-security.html"],
    [6, "Kadang-kadang robots.txt atau sitemap.xml dapat berisi aturan yang memungkinkan akses ke tautan tertentu yang tidak seharusnya diakses atau diindeks oleh crawler dan mesin pencari. Mesin pencari mungkin melewati tautan tersebut, tetapi penyerang dapat mengaksesnya secara langsung.",
        "Disarankan untuk tidak menyertakan tautan sensitif dalam file robots atau sitemap."],
    [7, "Tanpa Web Application Firewall, penyerang dapat mencoba menyisipkan berbagai pola serangan baik secara manual maupun menggunakan pemindai otomatis. Pemindai otomatis dapat mengirimkan banyak vektor serangan untuk memvalidasi serangan, yang juga dapat menyebabkan aplikasi terkena serangan DoS (Denial of Service).",
        "Web Application Firewall menawarkan perlindungan yang baik terhadap serangan web umum seperti XSS, SQLi, dll. Mereka juga memberikan lapisan pertahanan tambahan untuk infrastruktur keamanan Anda. Sumber ini berisi informasi tentang firewall aplikasi web yang dapat sesuai dengan aplikasi Anda: https://www.gartner.com/reviews/market/web-application-firewall"],
    [8, "Port terbuka memberikan petunjuk kepada penyerang untuk mengeksploitasi layanan. Penyerang mencoba mengambil informasi banner melalui port dan memahami jenis layanan yang dijalankan host.",
        "Disarankan untuk menutup port layanan yang tidak digunakan dan menggunakan firewall untuk memfilter port jika diperlukan. Sumber ini dapat memberikan wawasan lebih lanjut: https://security.stackexchange.com/a/145781/6137"],
    [9, "Kemungkinan kecil untuk mengkompromikan target hanya dengan alamat email. Namun, penyerang dapat menggunakan ini sebagai data pendukung untuk mengumpulkan informasi tentang target. Penyerang dapat menggunakan nama pengguna pada alamat email untuk melakukan serangan brute-force pada server email atau panel lain seperti SSH, CMS, dll.",
        "Karena kemungkinan eksploitasi kecil, tidak perlu mengambil tindakan. Remediasi yang sempurna adalah memilih nama pengguna yang berbeda untuk layanan yang berbeda."],
    [10, "Transfer zona mengungkapkan informasi topologi kritis tentang target. Penyerang dapat melakukan query semua catatan dan memiliki pengetahuan yang hampir lengkap tentang host Anda.",
        "Praktik yang baik adalah membatasi transfer zona dengan memberi tahu Master IP mana yang dapat diberikan akses untuk query. Sumber ini memberikan informasi lebih lanjut: https://www.sans.org/reading-room/whitepapers/dns/securing-dns-zone-transfer-868"],
    
                    [11, "The email address of the administrator and other information (address, phone, etc) is available publicly. An attacker may use these information to leverage an attack. This may not be used to carry out a direct attack as this is not a vulnerability. However, an attacker makes use of these data to build information about the target.",
                            "Some administrators intentionally would have made this information public, in this case it can be ignored. If not, it is recommended to mask the information. This resource provides information on this fix. http://www.name.com/blog/how-tos/tutorial-2/2013/06/protect-your-personal-information-with-whois-privacy/"],
                    [12, "Karena target tidak memiliki header ini, browser lama rentan terhadap serangan Reflected XSS.",
        "Browser modern tidak menghadapi masalah dengan kerentanan ini (header yang hilang). Namun, sangat disarankan untuk memperbarui browser lama."],
    [13, "Serangan ini bekerja dengan membuka beberapa koneksi simultan ke server web dan menjaga koneksi tetap hidup selama mungkin dengan terus-menerus mengirimkan permintaan HTTP parsial yang tidak pernah selesai. Serangan ini dengan mudah melewati IDS dengan mengirimkan permintaan parsial.",
        "Jika Anda menggunakan Modul Apache, `mod_antiloris` dapat membantu. Untuk pengaturan lainnya, Anda dapat menemukan remediasi yang lebih rinci pada sumber ini: https://www.acunetix.com/blog/articles/slow-http-dos-attacks-mitigate-apache-http-server/"],
    [14, "Kerentanan ini secara serius membocorkan informasi pribadi dari host Anda. Penyerang dapat menjaga koneksi TLS tetap hidup dan dapat mengambil maksimum 64K data per heartbeat.",
        "PFS (Perfect Forward Secrecy) dapat diimplementasikan untuk membuat dekripsi menjadi sulit. Informasi remediasi lengkap tersedia di sini: http://heartbleed.com/"],
    [15, "Dengan mengeksploitasi kerentanan ini, penyerang dapat memperoleh akses ke data sensitif dalam sesi terenkripsi seperti ID sesi, cookie, dan dengan data tersebut, dapat menyamar sebagai pengguna tertentu.",
        "Ini adalah kelemahan dalam Protokol SSL 3.0. Remediasi yang lebih baik adalah menonaktifkan penggunaan protokol SSL 3.0. Untuk informasi lebih lanjut, periksa sumber ini: https://www.us-cert.gov/ncas/alerts/TA14-290A"],
    [16, "Serangan ini terjadi dalam Negosiasi SSL (Handshake) yang membuat klien tidak menyadari serangan tersebut. Dengan berhasil mengubah handshake, penyerang dapat mengintip semua informasi yang dikirim dari klien ke server dan sebaliknya.",
        "Memperbarui OpenSSL ke versi terbaru akan mengatasi masalah ini. Sumber ini memberikan informasi lebih lanjut tentang kerentanan dan remediasinya: http://ccsinjection.lepidum.co.jp/"],
    [17, "Dengan kerentanan ini, penyerang dapat melakukan serangan MiTM dan dengan demikian mengkompromikan faktor kerahasiaan.",
        "Memperbarui OpenSSL ke versi terbaru akan mengatasi masalah ini. Versi sebelum 1.1.0 rentan terhadap kerentanan ini. Informasi lebih lanjut dapat ditemukan di sumber ini: https://bobcares.com/blog/how-to-fix-sweet32-birthday-attacks-vulnerability-cve-2016-2183/"],
    [18, "Dengan serangan LogJam, penyerang dapat menurunkan koneksi TLS yang memungkinkan penyerang membaca dan memodifikasi data apa pun yang dikirim melalui koneksi.",
        "Pastikan pustaka TLS yang Anda gunakan sudah diperbarui, server yang Anda kelola menggunakan bilangan prima 2048-bit atau lebih besar, dan klien yang Anda kelola menolak bilangan prima Diffie-Hellman yang lebih kecil dari 1024-bit. Informasi lebih lanjut dapat ditemukan di sumber ini: https://weakdh.org/"],
    [19, "Memungkinkan penyerang jarak jauh menyebabkan penolakan layanan (crash), dan mungkin mendapatkan informasi sensitif dalam aplikasi yang menggunakan OpenSSL, melalui pesan handshake ClientHello yang salah format yang memicu akses memori di luar batas.",
        "Versi OpenSSL 0.9.8h hingga 0.9.8q dan 1.0.0 hingga 1.0.0c rentan. Disarankan untuk memperbarui versi OpenSSL. Sumber dan informasi lebih lanjut dapat ditemukan di sini: https://www.openssl.org/news/secadv/20110208.txt"],
    [20, "Juga disebut serangan BREACH, mengeksploitasi kompresi dalam protokol HTTP yang mendasarinya. Penyerang dapat memperoleh alamat email, token sesi, dll dari lalu lintas web yang dienkripsi TLS.",
        "Mematikan kompresi TLS tidak mengatasi kerentanan ini. Langkah pertama untuk mitigasi adalah menonaktifkan kompresi Zlib diikuti dengan langkah-langkah lain yang disebutkan dalam sumber ini: http://breachattack.com/"],
                     [21, "Juga disebut sebagai serangan Injeksi Teks Biasa, memungkinkan penyerang MiTM untuk menyisipkan data ke dalam sesi HTTPS, dan mungkin jenis sesi lain yang dilindungi oleh TLS atau SSL, dengan mengirimkan permintaan yang tidak diautentikasi yang diproses secara retroaktif oleh server dalam konteks pasca-renegosiasi.",
        "Langkah-langkah remediasi terperinci dapat ditemukan di sumber ini: https://securingtomorrow.mcafee.com/technical-how-to/tips-securing-ssl-renegotiation/ https://www.digicert.com/news/2011-06-03-ssl-renego/"],
    [22, "Kerentanan ini memungkinkan penyerang mencuri sesi TLS yang ada dari pengguna.",
        "Saran terbaik adalah menonaktifkan resumsi sesi. Untuk memperkuat resumsi sesi, ikuti sumber ini yang memiliki informasi yang cukup: https://wiki.crashtest-security.com/display/KB/Harden+TLS+Session+Resumption"],
    [23, "Ini tidak ada hubungannya dengan risiko keamanan, namun penyerang dapat menggunakan ketidaktersediaan load balancer ini sebagai keuntungan untuk memanfaatkan serangan denial of service pada layanan tertentu atau pada seluruh aplikasi.",
        "Load Balancer sangat dianjurkan untuk aplikasi web apa pun. Mereka meningkatkan waktu kinerja serta ketersediaan data selama waktu server mati. Untuk mengetahui lebih banyak informasi tentang load balancer dan pengaturannya, periksa sumber ini: https://www.digitalocean.com/community/tutorials/what-is-load-balancing"],
    [24, "Penyerang dapat meneruskan permintaan yang datang ke URL atau aplikasi web yang sah ke alamat pihak ketiga atau ke lokasi penyerang yang dapat menyajikan malware dan memengaruhi mesin pengguna akhir.",
        "Sangat disarankan untuk menerapkan DNSSec pada target host. Penerapan penuh DNSSEC akan memastikan pengguna akhir terhubung ke situs web atau layanan lain yang sesuai dengan nama domain tertentu. Untuk informasi lebih lanjut, periksa sumber ini: https://www.cloudflare.com/dns/dnssec/how-dnssec-works/"],
    [25, "Penyerang dapat menemukan sejumlah besar informasi dari file-file ini. Bahkan ada kemungkinan penyerang dapat mengakses informasi penting dari file-file ini.",
        "Disarankan untuk memblokir atau membatasi akses ke file-file ini kecuali diperlukan."],
    [26, "Penyerang dapat menemukan sejumlah besar informasi dari direktori ini. Bahkan ada kemungkinan penyerang dapat mengakses informasi penting dari direktori ini.",
        "Disarankan untuk memblokir atau membatasi akses ke direktori ini kecuali diperlukan."],
    [27, "Mungkin tidak rentan terhadap SQLi. Penyerang akan dapat mengetahui bahwa host menggunakan backend untuk operasi.",
        "Banner Grabbing harus dibatasi dan akses ke layanan dari luar harus diminimalkan."],
    [28, "Penyerang akan dapat mencuri cookie, merusak aplikasi web, atau mengarahkan ke alamat pihak ketiga mana pun yang dapat menyajikan malware.",
        "Validasi input dan sanitasi output dapat sepenuhnya mencegah serangan Cross Site Scripting (XSS). Serangan XSS dapat diminimalkan di masa depan dengan mengikuti metodologi pengkodean yang aman. Sumber komprehensif berikut memberikan informasi terperinci tentang memperbaiki kerentanan ini: https://www.owasp.org/index.php/XSS_(Cross_Site_Scripting)_Prevention_Cheat_Sheet"],
    [29, "Kerentanan terkait SSL merusak faktor kerahasiaan. Penyerang dapat melakukan serangan MiTM, menginterpretasikan, dan menyadap komunikasi.",
        "Implementasi yang tepat dan versi pustaka SSL dan TLS yang diperbarui sangat penting untuk memblokir kerentanan terkait SSL."],
    [30, "Pemindai tertentu menemukan beberapa kerentanan yang mungkin dicoba oleh penyerang untuk mengeksploitasi target.",
        "Lihat RS-Vulnerability-Report untuk melihat informasi lengkap tentang kerentanan, setelah pemindaian selesai."],
    [31, "Penyerang dapat mengumpulkan lebih banyak informasi dari subdomain yang terkait dengan domain induk. Penyerang bahkan dapat menemukan layanan lain dari subdomain dan mencoba mempelajari arsitektur target. Bahkan ada kemungkinan penyerang menemukan kerentanan karena permukaan serangan menjadi lebih besar dengan lebih banyak subdomain yang ditemukan.",
        "Kadang-kadang bijaksana untuk memblokir subdomain seperti pengembangan, staging ke dunia luar, karena ini memberikan lebih banyak informasi kepada penyerang tentang tumpukan teknologi. Praktik penamaan yang kompleks juga membantu mengurangi permukaan serangan karena penyerang kesulitan melakukan brute force subdomain melalui kamus dan daftar kata."],
    [32, "Melalui protokol yang sudah usang ini, penyerang mungkin dapat melakukan MiTM dan serangan rumit lainnya.",
        "Sangat disarankan untuk berhenti menggunakan layanan ini karena sudah sangat usang. SSH dapat digunakan untuk menggantikan TELNET. Untuk informasi lebih lanjut, periksa sumber ini: https://www.ssh.com/ssh/telnet"],
    [33, "Protokol ini tidak mendukung komunikasi yang aman dan kemungkinan besar penyerang dapat menyadap komunikasi. Selain itu, banyak program FTP memiliki eksploitasi yang tersedia di web sehingga penyerang dapat langsung merusak aplikasi atau mendapatkan akses SHELL ke target.",
        "Perbaikan yang disarankan adalah menggunakan protokol SSH sebagai pengganti FTP. Ini mendukung komunikasi yang aman dan kemungkinan serangan MiTM cukup jarang."],
    [34, "StuxNet adalah worm tingkat-3 yang mengekspos informasi penting dari organisasi target. Itu adalah senjata siber yang dirancang untuk menggagalkan intelijen nuklir Iran. Serius bertanya-tanya bagaimana ini bisa sampai di sini? Semoga ini bukan positif palsu dari Nmap ;)",
        "Sangat disarankan untuk melakukan pemindaian rootkit lengkap pada host. Untuk informasi lebih lanjut, lihat sumber ini: https://www.symantec.com/security_response/writeup.jsp?docid=2010-071400-3123-99&tabid=3"],
         [35, "WebDAV diketahui memiliki banyak kerentanan. Dalam beberapa kasus, penyerang dapat menyembunyikan file DLL berbahaya di dalam share WebDAV dan, dengan meyakinkan pengguna untuk membuka file yang tampaknya tidak berbahaya, mengeksekusi kode dalam konteks pengguna tersebut.",
        "Disarankan untuk menonaktifkan WebDAV. Sumber daya penting tentang cara menonaktifkan WebDAV dapat ditemukan di URL ini: https://www.networkworld.com/article/2202909/network-security/-webdav-is-bad---says-security-researcher.html"],
    [36, "Penyerang selalu melakukan fingerprinting pada server sebelum meluncurkan serangan. Fingerprinting memberikan informasi tentang jenis server, konten yang disajikan, waktu modifikasi terakhir, dll., yang memungkinkan penyerang mempelajari lebih banyak informasi tentang target.",
        "Praktik yang baik adalah mengaburkan informasi ke dunia luar. Dengan melakukan ini, penyerang akan kesulitan memahami tumpukan teknologi server dan dengan demikian memanfaatkan serangan."],
    [37, "Penyerang biasanya mencoba membuat aplikasi web atau layanan tidak berguna dengan membanjiri target, sehingga memblokir akses pengguna yang sah. Ini dapat memengaruhi bisnis perusahaan atau organisasi serta reputasinya.",
        "Dengan memastikan load balancer yang tepat, mengonfigurasi batas kecepatan, dan pembatasan koneksi ganda, serangan semacam itu dapat diminimalkan secara drastis."],
    [38, "Penyusup dapat menyertakan file shell secara jarak jauh dan dapat mengakses sistem file inti atau membaca semua file. Ada kemungkinan lebih tinggi bagi penyerang untuk mengeksekusi kode secara jarak jauh pada sistem file.",
        "Praktik pengkodean yang aman sebagian besar akan mencegah serangan LFI, RFI, dan RCE. Sumber berikut memberikan wawasan mendalam tentang praktik pengkodean yang aman: https://wiki.sei.cmu.edu/confluence/display/seccode/Top+10+Secure+Coding+Practices"],
    [39, "Peretas dapat mencuri data dari backend dan juga dapat mengautentikasi diri mereka ke situs web dan menyamar sebagai pengguna mana pun karena mereka memiliki kendali penuh atas backend. Mereka bahkan dapat menghapus seluruh database. Penyerang juga dapat mencuri informasi cookie dari pengguna yang diautentikasi dan bahkan dapat mengarahkan target ke alamat berbahaya atau sepenuhnya merusak aplikasi.",
        "Validasi input yang tepat harus dilakukan sebelum langsung melakukan query ke informasi database. Pengembang harus ingat untuk tidak mempercayai input pengguna akhir. Dengan mengikuti metodologi pengkodean yang aman, serangan seperti SQLi, XSS, dan BSQLi dapat diminimalkan. Sumber berikut memberikan panduan tentang cara menerapkan metodologi pengkodean yang aman dalam pengembangan aplikasi: https://wiki.sei.cmu.edu/confluence/display/seccode/Top+10+Secure+Coding+Practices"],
    [40, "Penyerang mengeksploitasi kerentanan dalam BASH untuk melakukan eksekusi kode jarak jauh pada target. Penyerang yang berpengalaman dapat dengan mudah mengambil alih sistem target dan mengakses sumber daya internal mesin.",
        "Kerentanan ini dapat diminimalkan dengan memperbarui versi BASH. Sumber berikut memberikan analisis mendalam tentang kerentanan dan cara mengatasinya: https://www.symantec.com/connect/blogs/shellshock-all-you-need-know-about-bash-bug-vulnerability https://www.digitalocean.com/community/tutorials/how-to-protect-your-server-against-the-shellshock-bash-vulnerability"],
    [41, "Memberikan penyerang gambaran tentang bagaimana skema alamat dilakukan secara internal pada jaringan organisasi. Menemukan alamat pribadi yang digunakan dalam organisasi dapat membantu penyerang dalam melakukan serangan pada lapisan jaringan yang bertujuan untuk menembus infrastruktur internal organisasi.",
        "Batasi informasi banner ke dunia luar dari layanan yang mengungkapkan informasi tersebut. Informasi lebih lanjut tentang mitigasi kerentanan ini dapat ditemukan di sini: https://portswigger.net/kb/issues/00600300_private-ip-addresses-disclosed"],
    [42, "Ada kemungkinan penyerang dapat memanipulasi file di server web.",
        "Disarankan untuk menonaktifkan metode HTTP PUT dan DEL jika Anda tidak menggunakan layanan REST API. Sumber berikut membantu Anda mengetahui cara menonaktifkan metode ini: http://www.techstacks.com/howto/disable-http-methods-in-tomcat.html https://docs.oracle.com/cd/E19857-01/820-5627/gghwc/index.html https://developer.ibm.com/answers/questions/321629/how-to-disable-http-methods-head-put-delete-option/"],
    [43, "Penyerang mencoba mempelajari lebih banyak tentang target dari jumlah informasi yang terpapar di header. Penyerang dapat mengetahui jenis tumpukan teknologi yang digunakan aplikasi web dan banyak informasi lainnya.",
        "Banner Grabbing harus dibatasi dan akses ke layanan dari luar harus diminimalkan."],
    [44, "Penyerang yang berhasil mengeksploitasi kerentanan ini dapat membaca data, seperti view state, yang dienkripsi oleh server. Kerentanan ini juga dapat digunakan untuk manipulasi data, yang, jika berhasil dieksploitasi, dapat digunakan untuk mendekripsi dan memanipulasi data yang dienkripsi oleh server.",
        "Microsoft telah merilis serangkaian patch di situs web mereka untuk mengatasi masalah ini. Informasi yang diperlukan untuk memperbaiki kerentanan ini dapat ditemukan di sumber ini: https://docs.microsoft.com/en-us/security-updates/securitybulletins/2010/ms10-070"],
    [45, "Server web yang sudah usang mungkin mengandung banyak kerentanan karena dukungannya telah berakhir. Penyerang dapat memanfaatkan peluang seperti itu untuk melancarkan serangan.",
        "Sangat disarankan untuk memperbarui server web ke versi terbaru yang tersedia."],
    [46, "Peretas dapat dengan mudah memanipulasi URL melalui permintaan GET/POST. Mereka dapat menyisipkan beberapa vektor serangan di URL dengan mudah dan juga dapat memantau responsnya.",
        "Dengan memastikan teknik sanitasi yang tepat dan menerapkan praktik pengkodean yang aman, akan menjadi tidak mungkin bagi penyerang untuk menembus. Sumber berikut memberikan wawasan mendalam tentang praktik pengkodean yang aman: https://wiki.sei.cmu.edu/confluence/display/seccode/Top+10+Secure+Coding+Practices"],
    [47, "Karena penyerang memiliki pengetahuan tentang jenis backend tertentu yang dijalankan target, mereka dapat meluncurkan eksploitasi yang ditargetkan untuk versi tertentu. Mereka juga dapat mencoba mengautentikasi dengan kredensial default untuk mendapatkan akses.",
        "Patch keamanan backend harus diinstal secara tepat waktu. Kredensial default harus diubah. Jika memungkinkan, informasi banner dapat diubah untuk menyesatkan penyerang. Sumber berikut memberikan informasi lebih lanjut tentang cara mengamankan backend Anda: http://kb.bodhost.com/secure-database-server/"],
    [48, "Penyerang dapat meluncurkan eksploitasi jarak jauh untuk merusak layanan atau menggunakan alat seperti ncrack untuk mencoba brute-force kata sandi pada target.",
        "Disarankan untuk memblokir layanan ke dunia luar dan membuat layanan hanya dapat diakses melalui serangkaian IP yang diizinkan jika benar-benar diperlukan. Sumber berikut memberikan wawasan tentang risiko serta langkah-langkah untuk memblokir layanan: https://www.perspectiverisk.com/remote-desktop-service-vulnerabilities/"],
    [49, "Peretas dapat membaca string komunitas melalui layanan dan mengumpulkan cukup banyak informasi dari target. Selain itu, ada beberapa kerentanan Eksekusi Kode Jarak Jauh dan Penolakan Layanan yang terkait dengan layanan SNMP.",
        "Gunakan firewall untuk memblokir port dari dunia luar. Artikel berikut memberikan wawasan luas tentang pengamanan layanan SNMP: https://www.techrepublic.com/article/lock-it-down-dont-allow-snmp-to-compromise-network-security/"],
    [50, "Penyerang dapat menemukan log dan informasi kesalahan yang dihasilkan oleh aplikasi. Mereka juga dapat melihat kode status yang dihasilkan pada aplikasi. Dengan menggabungkan semua informasi ini, penyerang dapat memanfaatkan serangan.",
        "Dengan membatasi akses ke aplikasi logger dari dunia luar akan lebih dari cukup untuk mengurangi kelemahan ini."],
    [51, "Penjahat siber terutama menargetkan layanan ini karena sangat mudah bagi mereka untuk melakukan serangan jarak jauh dengan menjalankan eksploitasi. WannaCry Ransomware adalah salah satu contohnya.",
        "Mengekspos layanan SMB ke dunia luar adalah ide yang buruk. Disarankan untuk menginstal patch terbaru untuk layanan ini agar tidak dikompromikan. Sumber berikut memberikan informasi terperinci tentang konsep pengamanan SMB: https://kb.iweb.com/hc/en-us/articles/115000274491-Securing-Windows-SMB-and-NetBios-NetBT-Services"]
                           ]

# Tool Set
tools_precheck = [
                    ["wapiti"], ["whatweb"], ["nmap"], ["golismero"], ["host"], ["wget"], ["uniscan"], ["wafw00f"], ["dirb"], ["davtest"], ["theHarvester"], ["xsser"], ["dnsrecon"],["fierce"], ["dnswalk"], ["whois"], ["sslyze"], ["lbd"], ["golismero"], ["dnsenum"],["dmitry"], ["davtest"], ["nikto"], ["dnsmap"], ["amass"]
                 ]

def get_parser():

    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('-h', '--help', action='store_true', 
                        help='Show help message and exit.')
    parser.add_argument('-u', '--update', action='store_true', 
                        help='Update RapidScan.')
    parser.add_argument('-s', '--skip', action='append', default=[],
                        help='Skip some tools', choices=[t[0] for t in tools_precheck])
    parser.add_argument('-n', '--nospinner', action='store_true', 
                        help='Disable the idle loader/spinner.')
    parser.add_argument('target', nargs='?', metavar='URL', help='URL to scan.', default='', type=str)
    return parser


# Shuffling Scan Order (starts)
scan_shuffle = list(zip(tool_names, tool_cmd, tool_resp, tool_status))
random.shuffle(scan_shuffle)
tool_names, tool_cmd, tool_resp, tool_status = zip(*scan_shuffle)
tool_checks = (len(tool_names) + len(tool_resp) + len(tool_status)) / 3 # Cross verification incase, breaks.
tool_checks = round(tool_checks)
# Shuffling Scan Order (ends)

# Tool Head Pointer: (can be increased but certain tools will be skipped)
tool = 0

# Run Test
runTest = 1

# For accessing list/dictionary elements
arg1 = 0
arg2 = 1
arg3 = 2
arg4 = 3
arg5 = 4
arg6 = 5

# Detected Vulnerabilities [will be dynamically populated]
rs_vul_list = list()
rs_vul_num = 0
rs_vul = 0

# Total Time Elapsed
rs_total_elapsed = 0

# Tool Pre Checker
rs_avail_tools = 0

# Checks Skipped
rs_skipped_checks = 0

if len(sys.argv) == 1:
    logo()
    helper()
    sys.exit(1)

args_namespace = get_parser().parse_args()

if args_namespace.nospinner:
    spinner.disabled = True

if args_namespace.help or (not args_namespace.update \
    and not args_namespace.target):
    logo()
    helper()
elif args_namespace.update:
    logo()
    print("RapidScan is updating....Please wait.\n")
    spinner.start()
    # Checking internet connectivity first...
    rs_internet_availability = check_internet()
    if rs_internet_availability == 0:
        print("\t"+ bcolors.BG_ERR_TXT + "There seems to be some problem connecting to the internet. Please try again or later." +bcolors.ENDC)
        spinner.stop()
        sys.exit(1)
    cmd = 'sha1sum rapidscan.py | grep .... | cut -c 1-40'
    oldversion_hash = subprocess.check_output(cmd, shell=True)
    oldversion_hash = oldversion_hash.strip()
    os.system('wget -N https://raw.githubusercontent.com/skavngr/rapidscan/master/rapidscan.py -O rapidscan.py > /dev/null 2>&1')
    newversion_hash = subprocess.check_output(cmd, shell=True)
    newversion_hash = newversion_hash.strip()
    if oldversion_hash == newversion_hash :
        clear()
        print("\t"+ bcolors.OKBLUE +"You already have the latest version of RapidScan." + bcolors.ENDC)
    else:
        clear()
        print("\t"+ bcolors.OKGREEN +"RapidScan successfully updated to the latest version." +bcolors.ENDC)
    spinner.stop()
    sys.exit(1)

elif args_namespace.target:

    target = url_maker(args_namespace.target)
    #target = args_namespace.target
    os.system('rm /tmp/rapidscan* > /dev/null 2>&1') # Clearing previous scan files
    os.system('clear')
    os.system('setterm -cursor off')
    logo()
    print(bcolors.BG_HEAD_TXT+"[ Checking Available Security Scanning Tools Phase... Initiated. ]"+bcolors.ENDC)

    unavail_tools_names = list()

    while (rs_avail_tools < len(tools_precheck)):
        precmd = str(tools_precheck[rs_avail_tools][arg1])
        try:
            p = subprocess.Popen([precmd], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,shell=True)
            output, err = p.communicate()
            val = output + err
        except:
            print("\t"+bcolors.BG_ERR_TXT+"RapidScan was terminated abruptly..."+bcolors.ENDC)
            sys.exit(1)
        
        # If the tool is not found or it's part of the --skip argument(s), disabling it
        if b"not found" in val or tools_precheck[rs_avail_tools][arg1] in args_namespace.skip :
            if b"not found" in val:
                print("\t"+bcolors.OKBLUE+tools_precheck[rs_avail_tools][arg1]+bcolors.ENDC+bcolors.BADFAIL+"...unavailable."+bcolors.ENDC)
            elif tools_precheck[rs_avail_tools][arg1] in args_namespace.skip :
                print("\t"+bcolors.OKBLUE+tools_precheck[rs_avail_tools][arg1]+bcolors.ENDC+bcolors.BADFAIL+"...skipped."+bcolors.ENDC)
            
            for scanner_index, scanner_val in enumerate(tool_names):
                if scanner_val[2] == tools_precheck[rs_avail_tools][arg1]:
                    scanner_val[3] = 0 # disabling scanner as it's not available.
                    unavail_tools_names.append(tools_precheck[rs_avail_tools][arg1])

        else:
            print("\t"+bcolors.OKBLUE+tools_precheck[rs_avail_tools][arg1]+bcolors.ENDC+bcolors.OKGREEN+"...available."+bcolors.ENDC)
        rs_avail_tools = rs_avail_tools + 1
        clear()
    unavail_tools_names = list(set(unavail_tools_names))
    if len(unavail_tools_names) == 0:
        print("\t"+bcolors.OKGREEN+"All Scanning Tools are available. Complete vulnerability checks will be performed by RapidScan."+bcolors.ENDC)
    else:
        print("\t"+bcolors.WARNING+"Some of these tools "+bcolors.BADFAIL+str(unavail_tools_names)+bcolors.ENDC+bcolors.WARNING+" are unavailable or will be skipped. RapidScan will still perform the rest of the tests. Install these tools to fully utilize the functionality of RapidScan."+bcolors.ENDC)
    print(bcolors.BG_ENDL_TXT+"[ Checking Available Security Scanning Tools Phase... Completed. ]"+bcolors.ENDC)
    print("\n")
    print(bcolors.BG_HEAD_TXT+"[ Preliminary Scan Phase Initiated... Loaded "+str(tool_checks)+" vulnerability checks. ]"+bcolors.ENDC)
    #while (tool < 1):
    while(tool < len(tool_names)):
        print("["+tool_status[tool][arg3]+tool_status[tool][arg4]+"] Deploying "+str(tool+1)+"/"+str(tool_checks)+" | "+bcolors.OKBLUE+tool_names[tool][arg2]+bcolors.ENDC,)
        if tool_names[tool][arg4] == 0:
            print(bcolors.WARNING+"\nScanning Tool Unavailable. Skipping Test...\n"+bcolors.ENDC)
            rs_skipped_checks = rs_skipped_checks + 1
            tool = tool + 1
            continue
        try:
            spinner.start()
        except Exception as e:
            print("\n")
        scan_start = time.time()
        temp_file = "/tmp/rapidscan_temp_"+tool_names[tool][arg1]
        cmd = tool_cmd[tool][arg1]+target+tool_cmd[tool][arg2]+" > "+temp_file+" 2>&1"

        try:
            subprocess.check_output(cmd, shell=True)
        except KeyboardInterrupt:
            runTest = 0
        except:
            runTest = 1

        if runTest == 1:
                spinner.stop()
                scan_stop = time.time()
                elapsed = scan_stop - scan_start
                rs_total_elapsed = rs_total_elapsed + elapsed
                #print(bcolors.OKBLUE+"\b...Completed in "+display_time(int(elapsed))+bcolors.ENDC+"\n")
                sys.stdout.write(ERASE_LINE)
                print(bcolors.OKBLUE+"\nScan Completed in "+display_time(int(elapsed))+bcolors.ENDC, end='\r', flush=True)
                print("\n")
                #clear()
                rs_tool_output_file = open(temp_file).read()
                if tool_status[tool][arg2] == 0:
                    if tool_status[tool][arg1].lower() in rs_tool_output_file.lower():
                        #print "\t"+ vul_info(tool_resp[tool][arg2]) + bcolors.BADFAIL +" "+ tool_resp[tool][arg1] + bcolors.ENDC
                        vul_remed_info(tool,tool_resp[tool][arg2],tool_resp[tool][arg3])
                        rs_vul_list.append(tool_names[tool][arg1]+"*"+tool_names[tool][arg2])
                else:
                    if any(i in rs_tool_output_file for i in tool_status[tool][arg6]):
                        m = 1 # This does nothing.
                    else:
                        #print "\t"+ vul_info(tool_resp[tool][arg2]) + bcolors.BADFAIL +" "+ tool_resp[tool][arg1] + bcolors.ENDC
                        vul_remed_info(tool,tool_resp[tool][arg2],tool_resp[tool][arg3])
                        rs_vul_list.append(tool_names[tool][arg1]+"*"+tool_names[tool][arg2])
        else:
                runTest = 1
                spinner.stop()
                scan_stop = time.time()
                elapsed = scan_stop - scan_start
                rs_total_elapsed = rs_total_elapsed + elapsed
                #sys.stdout.write(CURSOR_UP_ONE) 
                sys.stdout.write(ERASE_LINE)
                #print("-" * terminal_size(), end='\r', flush=True)
                print(bcolors.OKBLUE+"\nScan Interrupted in "+display_time(int(elapsed))+bcolors.ENDC, end='\r', flush=True)
                print("\n"+bcolors.WARNING + "\tTest Skipped. Performing Next. Press Ctrl+Z to Quit RapidScan.\n" + bcolors.ENDC)
                rs_skipped_checks = rs_skipped_checks + 1

        tool=tool+1

    print(bcolors.BG_ENDL_TXT+"[ Preliminary Scan Phase Completed. ]"+bcolors.ENDC)
    print("\n")

    #################### Report & Documentation Phase ###########################
    date = subprocess.Popen(["date", "+%Y-%m-%d"],stdout=subprocess.PIPE).stdout.read()[:-1].decode("utf-8")
    debuglog = "rs.dbg.%s.%s" % (target, date) 
    vulreport = "rs.vul.%s.%s" % (target, date)
    print(bcolors.BG_HEAD_TXT+"[ Report Generation Phase Initiated. ]"+bcolors.ENDC)
    if len(rs_vul_list)==0:
        print("\t"+bcolors.OKGREEN+"No Vulnerabilities Detected."+bcolors.ENDC)
    else:
        with open(vulreport, "a") as report:
            while(rs_vul < len(rs_vul_list)):
                vuln_info = rs_vul_list[rs_vul].split('*')
                report.write(vuln_info[arg2])
                report.write("\n------------------------\n\n")
                temp_report_name = "/tmp/rapidscan_temp_"+vuln_info[arg1]
                with open(temp_report_name, 'r') as temp_report:
                    data = temp_report.read()
                    report.write(data)
                    report.write("\n\n")
                temp_report.close()
                rs_vul = rs_vul + 1

            print("\tComplete Vulnerability Report for "+bcolors.OKBLUE+target+bcolors.ENDC+" named "+bcolors.OKGREEN+vulreport+bcolors.ENDC+" is available under the same directory RapidScan resides.")

        report.close()
    # Writing all scan files output into RS-Debug-ScanLog for debugging purposes.
    for file_index, file_name in enumerate(tool_names):
        with open(debuglog, "a") as report:
            try:
                with open("/tmp/rapidscan_temp_"+file_name[arg1], 'r') as temp_report:
                        data = temp_report.read()
                        report.write(file_name[arg2])
                        report.write("\n------------------------\n\n")
                        report.write(data)
                        report.write("\n\n")
                temp_report.close()
            except:
                break
        report.close()

    print("\tTotal Number of Vulnerability Checks        : "+bcolors.BOLD+bcolors.OKGREEN+str(len(tool_names))+bcolors.ENDC)
    print("\tTotal Number of Vulnerability Checks Skipped: "+bcolors.BOLD+bcolors.WARNING+str(rs_skipped_checks)+bcolors.ENDC)
    print("\tTotal Number of Vulnerabilities Detected    : "+bcolors.BOLD+bcolors.BADFAIL+str(len(rs_vul_list))+bcolors.ENDC)
    print("\tTotal Time Elapsed for the Scan             : "+bcolors.BOLD+bcolors.OKBLUE+display_time(int(rs_total_elapsed))+bcolors.ENDC)
    print("\n")
    print("\tFor Debugging Purposes, You can view the complete output generated by all the tools named "+bcolors.OKBLUE+debuglog+bcolors.ENDC+" under the same directory.")
    print(bcolors.BG_ENDL_TXT+"[ Report Generation Phase Completed. ]"+bcolors.ENDC)

    os.system('setterm -cursor on')
    os.system('rm /tmp/rapidscan_te* > /dev/null 2>&1') # Clearing previous scan files
