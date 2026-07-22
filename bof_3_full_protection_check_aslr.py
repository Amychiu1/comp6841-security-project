from pwn import *
context.log_level = 'error'

for i in range(3):
    p = process('./vuln')
    pid = p.pid
    with open(f'/proc/{pid}/maps') as f:
        first_line = f.readline()
    print(f"Run {i+1}: binary base mapping -> {first_line.strip()}")
    p.close()
