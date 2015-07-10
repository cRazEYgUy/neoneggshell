# neoneggshell

NES is an OSX and Jailbroken IOS command shell creation tool written in python
This tool creates an command line session with extra functionality like
downloading files, taking pictures, and gathering  data  on  a  target.  
To run neoneggshell, first create a payload (shellscript or deb  file).
The payload should then be executed on the target device that you  want
to control. For executing a shell script, it can be pasted right on  to
the command line, or embedded in a program. It is your job to get it on
the target, the rest is for NES to handle. For deb files, you can  host
them on a cydia repo or they can be installed by downloading them  from 
safari and installing  them  in  ifile. The way NES works is simple,  a
reverse connection is  created, NES  can  bypass  firewalls  since  the 
target creates the connection. A binary payload is then  sent  from  NES 
to the target and is injected into memory and leaves no  traces  on  the 
disk. This tool is for pentesting only, not for controlling peoples devices

NOT MEANT FOR USING ON COMPUTERS THAT ARE'NT YOURS, I DO NOT TAKE RESPONSABLITY FOR ANY DAMAGE YOU MAY CAUSE
