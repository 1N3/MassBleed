MassBleed SSL Vulnerability Scanner v2015116

![alt tag](https://github.com/1N3/MassBleed/blob/master/screenshot.png)

USAGE: 
sh massbleed.sh [CIDR|IP] [single|port|subnet] [port] [proxy]

ABOUT:
This script has four main functions with the ability to proxy all connections:
 1. To mass scan any CIDR range for OpenSSL vulnerabilities via port 443/tcp (https) (example: sh massbleed.sh 192.168.0.0/16)
 2. To scan any CIDR range for OpenSSL vulnerabilities via any custom port specified (example: sh massbleed.sh 192.168.0.0/16 port 8443)
 3. To individual scan every port (1-10000) on a single system for vulnerable versions of OpenSSL (example: sh massbleed.sh 127.0.0.1 single)
 4. To scan every open port on every host in a single class C subnet for OpenSSL vulnerabilities (example: sh massbleed.sh 192.168.0. subnet)

PROXY: 
A proxy option has been added to scan via proxychains. You'll need to configure /etc/proxychains.conf for this to work. 

PROXY USAGE EXAMPLES:
 (example: sh massbleed.sh 192.168.0.0/16 0 0 proxy)
 (example: sh massbleed.sh 192.168.0.0/16 port 8443 proxy)
 (example: sh massbleed.sh 127.0.0.1 single 0 proxy)
 (example: sh massbleed.sh 192.168.0. subnet 0 proxy)

VULNERABILITIES:
 1. OpenSSL HeartBleed Vulnerability (CVE-2014-0160)
 2. OpenSSL CCS (MITM) Vulnerability (CVE-2014-0224)
 3. Poodle SSLv3 vulnerability (CVE-2014-3566)

REQUIREMENTS:
 Is the heartbleed POC present? 
 Is the openssl CCS script present?
 Is unicornscan installed?
 Is nmap installed?
 Is sslscan installed?

