# Brody Larson

#Importing Libs
import nmap

#Cue The ASCII Art

print("""

    ___         __           _   __                    
   /   | __  __/ /_____     / | / /___ ___  ____ _____ 
  / /| |/ / / / __/ __ \   /  |/ / __ `__ \/ __ `/ __  /
 / ___ / /_/ / /_/ /_/ /  / /|  / / / / / / /_/ / /_/ /
/_/  |_\__,_/\__/\____/  /_/ |_/_/ /_/ /_/\__,_/ .___/ 
                                              /_/      


                    """)
#Letting the User Enter Ip and Port Range
IP = input("Please Enter the Machine IP:\n")

#Checking if the IP is Valid

if len(IP) > 12 :
    print("Please Enter A Valid IP!")
    exit()

if len(IP) < 4 :
    print("Please Enter a Valid IP!")
    exit()

ports = input("Please Enter Your Desired Port Range ex. (21-443)\n")

#Checking if user actually entered ports

if len(ports) == 0 :
    print("Please enter a value for ports!!!")
    exit()


#Starting PortScanner Object
nmScan = nmap.PortScanner()

#Start Nmap with Specified Varibles
nmScan.scan(IP, ports)

#Printing Results
print("""

    ____                  ____      
   / __ \___  _______  __/ / /______
  / /_/ / _ \/ ___/ / / / / __/ ___/
 / _, _/  __(__  ) /_/ / / /_(__  ) 
/_/ |_|\___/____/\__,_/_/\__/____/  
                                         


                    """)
for host in nmScan.all_hosts():
     print('Host : %s (%s)' % (host, nmScan[host].hostname()))
     print('State : %s' % nmScan[host].state())
     for proto in nmScan[host].all_protocols():
         print('----------')
         print('Protocol : %s' % proto)

         lport = nmScan[host][proto].keys()
         for port in lport:
             print ('port : %s\tstate : %s' % (port, nmScan[host][proto][port]['state']))
