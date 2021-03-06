// 32bit, executable stack, no stack protector
// gcc -m32 -g -z execstack -z norelro -fno-stack-protector source.c

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv)
{
    int n = 0;
    char buf[100];

    fgets(buf, 100, stdin);
    n = 0;
    while (n < strlen(buf))
    {
        if (buf[n] >= 'A' && buf[n] <= 'Z')
            buf[n] = buf[n] ^ 0x20; // to lowercase
        n++;
    }
    printf(buf);
    exit(0);
}

// main
//    0x08048444 <+0>:	    push   ebp
//    0x08048445 <+1>:	    mov    ebp,esp
//    0x08048447 <+3>:	    push   edi
//    0x08048448 <+4>:	    push   ebx
//    0x08048449 <+5>:	    and    esp,0xfffffff0
//    0x0804844c <+8>:	    sub    esp,0x90                         # 144
//    0x08048452 <+14>: 	mov    DWORD PTR [esp+0x8c],0x0         # n = 0
//    0x0804845d <+25>: 	mov    eax,ds:0x80497f0                 # stdin
//    0x08048462 <+30>: 	mov    DWORD PTR [esp+0x8],eax
//    0x08048466 <+34>: 	mov    DWORD PTR [esp+0x4],0x64
//    0x0804846e <+42>: 	lea    eax,[esp+0x28]                   # buf
//    0x08048472 <+46>: 	mov    DWORD PTR [esp],eax
//    0x08048475 <+49>: 	call   0x8048350 <fgets@plt>            # fgets(buf, 0x64, stdin);
//    0x0804847a <+54>: 	mov    DWORD PTR [esp+0x8c],0x0         # n = 0
//    0x08048485 <+65>: 	jmp    0x80484d3 <main+143>
//    0x08048487 <+67>: 	lea    eax,[esp+0x28]                   # *buf
//    0x0804848b <+71>: 	add    eax,DWORD PTR [esp+0x8c]         # + n
//    0x08048492 <+78>: 	movzx  eax,BYTE PTR [eax]               # buf[n]
//    0x08048495 <+81>: 	cmp    al,0x40                          # cmp buf[n], '@'
//    0x08048497 <+83>: 	jle    0x80484cb <main+135>             # if <=
//    0x08048499 <+85>: 	lea    eax,[esp+0x28]
//    0x0804849d <+89>: 	add    eax,DWORD PTR [esp+0x8c]
//    0x080484a4 <+96>: 	movzx  eax,BYTE PTR [eax]
//    0x080484a7 <+99>: 	cmp    al,0x5a                          # cmp buf[n], 'Z'
//    0x080484a9 <+101>:	jg     0x80484cb <main+135>             # if >
//    0x080484ab <+103>:	lea    eax,[esp+0x28]
//    0x080484af <+107>:	add    eax,DWORD PTR [esp+0x8c]
//    0x080484b6 <+114>:	movzx  eax,BYTE PTR [eax]
//    0x080484b9 <+117>:	mov    edx,eax
//    0x080484bb <+119>:	xor    edx,0x20
//    0x080484be <+122>:	lea    eax,[esp+0x28]
//    0x080484c2 <+126>:	add    eax,DWORD PTR [esp+0x8c]
//    0x080484c9 <+133>:	mov    BYTE PTR [eax],dl                # buf[n] ^= 0x20

//    0x080484cb <+135>:	add    DWORD PTR [esp+0x8c],0x1         # n += 1
//    0x080484d3 <+143>:	mov    ebx,DWORD PTR [esp+0x8c]         # n
//    0x080484da <+150>:	lea    eax,[esp+0x28]                   # buf
//    0x080484de <+154>:	mov    DWORD PTR [esp+0x1c],0xffffffff
//    0x080484e6 <+162>:	mov    edx,eax
//    0x080484e8 <+164>:	mov    eax,0x0
//    0x080484ed <+169>:	mov    ecx,DWORD PTR [esp+0x1c]
//    0x080484f1 <+173>:	mov    edi,edx
//    0x080484f3 <+175>:	repnz scas al,BYTE PTR es:[edi]         # pseudo strlen(buf)
//    0x080484f5 <+177>:	mov    eax,ecx
//    0x080484f7 <+179>:	not    eax
//    0x080484f9 <+181>:	sub    eax,0x1
//    0x080484fc <+184>:	cmp    ebx,eax                          # cmp n, strlen(buf)
//    0x080484fe <+186>:	jb     0x8048487 <main+67>              # if <
//    0x08048500 <+188>:	lea    eax,[esp+0x28]                   # buf
//    0x08048504 <+192>:	mov    DWORD PTR [esp],eax
//    0x08048507 <+195>:	call   0x8048340 <printf@plt>           # printf(buf);
//    0x0804850c <+200>:	mov    DWORD PTR [esp],0x0
//    0x08048513 <+207>:	call   0x8048370 <exit@plt>             # exit(0);
