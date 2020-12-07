# Override

## About

> Override is last ISO that will have you search for faults present in the protected binaries, and re-build these binaries depending on their behavior.

This is the third project of the Security branch at School 42 Paris

## Content

Each level folders contains these files:

- `flag`: Password for the next user
- `source`: A pseudocode of the binary to reverse
- `README`: How to find the password
- `main.sh`: Main script to execute. It connects us through ssh and executes `script.sh` on virtual machine.

## Setup VM (Ubuntu/Debian)

Requirements:

- VirtualBox
- VirtualBox Guest Addition

```shell
./scripts/createVM.sh
./scripts/startVM.sh
./scripts/installUtils.sh
```
