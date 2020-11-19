// 64bit, executable stack, no stack protector
// gcc -g -z execstack -z norelro -fno-stack-protector source.c

#include <stdio.h>
#include <string.h>

// char *fgets(char *s, int size, FILE *stream);
// void *memset(void *s, int c, size_t n);
// int puts(const char *s);
// int printf(const char *format, ...);
// int strncmp(const char *s1, const char *s2, size_t n);

char a_user_name[0x100];

int verify_user_pass(char *pass)
{
    return strncmp(pass, "admin", 0x5);
}

int verify_user_name(void)
{
    char username[] = "dat_wil";

    puts("verifying username....\n");
    return strncmp(a_user_name, username, 7);
}

int main(int argc, char **argv)
{
    char buf[0x48];
    int isIncorrect;

    memset(buf, '\0', 0x10);
    puts("********* ADMIN LOGIN PROMPT *********");
    isIncorrect = 0;
    printf("Enter Username: ");
    fgets(a_user_name, 0x100, stdin);
    isIncorrect = verify_user_name();
    if (isIncorrect)
    {
        puts("nope, incorrect username...\n");
        return 1;
    }
    puts("Enter Password: ");
    fgets(buf, 0x64, stdin);
    isIncorrect = verify_user_pass(buf);
    if (!isIncorrect || isIncorrect)
    {
        puts("nope, incorrect password...\n");
        return 1;
    }
    return 0;
}

// verify_user_pass
//    0x080484a3 <+0>:     push   ebp
//    0x080484a4 <+1>:     mov    ebp,esp
//    0x080484a6 <+3>:     push   edi
//    0x080484a7 <+4>:     push   esi
//    0x080484a8 <+5>:     mov    eax,DWORD PTR [ebp+0x8]                   # arg
//    0x080484ab <+8>:     mov    edx,eax
//    0x080484ad <+10>:    mov    eax,0x80486b0                             # "admin"
//    0x080484b2 <+15>:    mov    ecx,0x5
//    0x080484b7 <+20>:    mov    esi,edx
//    0x080484b9 <+22>:    mov    edi,eax
//    0x080484bb <+24>:    repz cmps BYTE PTR ds:[esi],BYTE PTR es:[edi]    # pseudo strncmp(arg, "admin", 0x5)
//    0x080484bd <+26>:    seta   dl
//    0x080484c0 <+29>:    setb   al
//    0x080484c3 <+32>:    mov    ecx,edx
//    0x080484c5 <+34>:    sub    cl,al
//    0x080484c7 <+36>:    mov    eax,ecx
//    0x080484c9 <+38>:    movsx  eax,al
//    0x080484cc <+41>:    pop    esi
//    0x080484cd <+42>:    pop    edi
//    0x080484ce <+43>:    pop    ebp
//    0x080484cf <+44>:    ret

// verify_user_name
//    0x08048464 <+0>:     push   ebp
//    0x08048465 <+1>:     mov    ebp,esp
//    0x08048467 <+3>:     push   edi
//    0x08048468 <+4>:     push   esi
//    0x08048469 <+5>:     sub    esp,0x10
//    0x0804846c <+8>:     mov    DWORD PTR [esp],0x8048690                 # "verifying username....\n"
//    0x08048473 <+15>:    call   0x8048380 <puts@plt>                      # puts("verifying username....\n")
//    0x08048478 <+20>:    mov    edx,0x804a040                             # 0x804a040 <a_user_name>:
//    0x0804847d <+25>:    mov    eax,0x80486a8                             # 0x80486a8: "dat_wil"
//    0x08048482 <+30>:    mov    ecx,0x7
//    0x08048487 <+35>:    mov    esi,edx
//    0x08048489 <+37>:    mov    edi,eax
//    0x0804848b <+39>:    repz cmps BYTE PTR ds:[esi],BYTE PTR es:[edi]    # pseudo strncmp(a_user_name, "dat_wil", 7);
//    0x0804848d <+41>:    seta   dl
//    0x08048490 <+44>:    setb   al
//    0x08048493 <+47>:    mov    ecx,edx
//    0x08048495 <+49>:    sub    cl,al
//    0x08048497 <+51>:    mov    eax,ecx
//    0x08048499 <+53>:    movsx  eax,al
//    0x0804849c <+56>:    add    esp,0x10
//    0x0804849f <+59>:    pop    esi
//    0x080484a0 <+60>:    pop    edi
//    0x080484a1 <+61>:    pop    ebp
//    0x080484a2 <+62>:    ret

// main
//    0x080484d0 <+0>:     push   ebp
//    0x080484d1 <+1>:     mov    ebp,esp
//    0x080484d3 <+3>:     push   edi
//    0x080484d4 <+4>:     push   ebx
//    0x080484d5 <+5>:     and    esp,0xfffffff0
//    0x080484d8 <+8>:     sub    esp,0x60
//    0x080484db <+11>:    lea    ebx,[esp+0x1c]                # buf;
//    0x080484df <+15>:    mov    eax,0x0
//    0x080484e4 <+20>:    mov    edx,0x10
//    0x080484e9 <+25>:    mov    edi,ebx
//    0x080484eb <+27>:    mov    ecx,edx
//    0x080484ed <+29>:    rep stos DWORD PTR es:[edi],eax      # pseudo memset(buf, '\0', 0x10)
//    0x080484ef <+31>:    mov    DWORD PTR [esp+0x5c],0x0      # int isIncorrect
//    0x080484f7 <+39>:    mov    DWORD PTR [esp],0x80486b8     # 0x80486b8: "********* ADMIN LOGIN PROMPT *********"
//    0x080484fe <+46>:    call   0x8048380 <puts@plt>          # puts("********* ADMIN LOGIN PROMPT *********")
//    0x08048503 <+51>:    mov    eax,0x80486df                 # "Enter Username: "
//    0x08048508 <+56>:    mov    DWORD PTR [esp],eax
//    0x0804850b <+59>:    call   0x8048360 <printf@plt>        # printf("Enter Username: ")
//    0x08048510 <+64>:    mov    eax,ds:0x804a020              # stdin
//    0x08048515 <+69>:    mov    DWORD PTR [esp+0x8],eax
//    0x08048519 <+73>:    mov    DWORD PTR [esp+0x4],0x100
//    0x08048521 <+81>:    mov    DWORD PTR [esp],0x804a040     # 0x804a040 <a_user_name>
//    0x08048528 <+88>:    call   0x8048370 <fgets@plt>         # fgets(a_user_name, 0x100, stdin)
//    0x0804852d <+93>:    call   0x8048464 <verify_user_name>  # verify_user_name()
//    0x08048532 <+98>:    mov    DWORD PTR [esp+0x5c],eax      # isIncorrect
//    0x08048536 <+102>:   cmp    DWORD PTR [esp+0x5c],0x0
//    0x0804853b <+107>:   je     0x8048550 <main+128>
//    0x0804853d <+109>:   mov    DWORD PTR [esp],0x80486f0     # "nope, incorrect username...\n"
//    0x08048544 <+116>:   call   0x8048380 <puts@plt>          # puts("nope, incorrect username...\n")
//    0x08048549 <+121>:   mov    eax,0x1
//    0x0804854e <+126>:   jmp    0x80485af <main+223>
//    0x08048550 <+128>:   mov    DWORD PTR [esp],0x804870d     # "Enter Password: "
//    0x08048557 <+135>:   call   0x8048380 <puts@plt>          # puts("Enter Password: ")
//    0x0804855c <+140>:   mov    eax,ds:0x804a020              # stdin
//    0x08048561 <+145>:   mov    DWORD PTR [esp+0x8],eax
//    0x08048565 <+149>:   mov    DWORD PTR [esp+0x4],0x64
//    0x0804856d <+157>:   lea    eax,[esp+0x1c]                # buf
//    0x08048571 <+161>:   mov    DWORD PTR [esp],eax
//    0x08048574 <+164>:   call   0x8048370 <fgets@plt>         # fgets(buf, 0x64, stdin)
//    0x08048579 <+169>:   lea    eax,[esp+0x1c]
//    0x0804857d <+173>:   mov    DWORD PTR [esp],eax
//    0x08048580 <+176>:   call   0x80484a3 <verify_user_pass>  # verify_user_pass(buf)
//    0x08048585 <+181>:   mov    DWORD PTR [esp+0x5c],eax      # isIncorrect
//    0x08048589 <+185>:   cmp    DWORD PTR [esp+0x5c],0x0
//    0x0804858e <+190>:   je     0x8048597 <main+199>
//    0x08048590 <+192>:   cmp    DWORD PTR [esp+0x5c],0x0
//    0x08048595 <+197>:   je     0x80485aa <main+218>
//    0x08048597 <+199>:   mov    DWORD PTR [esp],0x804871e     # "nope, incorrect password...\n"
//    0x0804859e <+206>:   call   0x8048380 <puts@plt>          # puts("nope, incorrect password...\n")
//    0x080485a3 <+211>:   mov    eax,0x1
//    0x080485a8 <+216>:   jmp    0x80485af <main+223>
//    0x080485aa <+218>:   mov    eax,0x0
//    0x080485af <+223>:   lea    esp,[ebp-0x8]
//    0x080485b2 <+226>:   pop    ebx
//    0x080485b3 <+227>:   pop    edi
//    0x080485b4 <+228>:   pop    ebp
//    0x080485b5 <+229>:   ret