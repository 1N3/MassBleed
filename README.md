# MassBleed SSL Vulnerability Scanner

![alt tag](https://github.com/1N3/MassBleed/blob/master/screenshot.png)

## USAGE:
``` 
sh massbleed.sh [CIDR|IP] [single|port|subnet] [port] [proxy]
```

## ABOUT:
This script has four main functions with the ability to proxy all connections:
* To mass scan any CIDR range for OpenSSL vulnerabilities via port 443/tcp (https) (example: sh massbleed.sh 192.168.0.0/16)
* To scan any CIDR range for OpenSSL vulnerabilities via any custom port specified (example: sh massbleed.sh 192.168.0.0/16 port 8443)
* To individual scan every port (1-10000) on a single system for vulnerable versions of OpenSSL (example: sh massbleed.sh 127.0.0.1 single)
* To scan every open port on every host in a single class C subnet for OpenSSL vulnerabilities (example: sh massbleed.sh 192.168.0. subnet)

## PROXY: 
A proxy option has been added to scan via proxychains. You'll need to configure /etc/proxychains.conf for this to work. 

## PROXY USAGE EXAMPLES:
* (example: ./massbleed 192.168.0.0/16 0 0 proxy)
* (example: ./massbleed 192.168.0.0/16 port 8443 proxy)
* (example: ./massbleed 127.0.0.1 single 0 proxy)
* (example: ./massbleed 192.168.0. subnet 0 proxy)

## VULNERABILITIES:
1. OpenSSL HeartBleed Vulnerability (CVE-2014-0160)
2. OpenSSL CCS (MITM) Vulnerability (CVE-2014-0224)
3. Poodle SSLv3 Vulnerability (CVE-2014-3566)
4. WinShock SChannel Vulnerability (MS14-066)
5. DROWN Attack (CVE-2016-0800)

## REQUIREMENTS:
* Is the heartbleed POC present? 
* Is the openssl CCS script present?
* Is the winshock script present?
* Is unicornscan installed?
* Is nmap installed?
* Is sslscan installed?

## LICENSE:
This software is free to distribute, modify and use with the condition that credit is provided to the creator (1N3@CrowdShield) and is not for commercial use.

## DONATIONS:
Donations are welcome. This will help fascilitate improved features, frequent updates and better overall support.
- [x] BTC 1Fav36btfmdrYpCAR65XjKHhxuJJwFyKum
- [x] DASH XoWYdMDGb7UZmzuLviQYtUGb5MNXSkqvXG
- [x] ETH 0x20bB09273702eaBDFbEE9809473Fd04b969a794d
- [x] LTC LQ6mPewec3xeLBYMdRP4yzeta6b9urqs2f