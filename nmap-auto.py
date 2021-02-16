# Brody Larson

#Importing Librarys
import nmap

#Letting the User Enter Ip and Port Range
IP = input("Please Enter the Machine IP:\n")
ports = input("Please Enter Your Desired Port Range ex. (21-443)\n") 

#Starting PortScanner Object
nmScan = nmap.PortScanner()

#Start Nmap with Specified Varibles
nmScan.scan(IP, ports)

#Printing Results
for host in nmScan.all_hosts():
     print('Host : %s (%s)' % (host, nmScan[host].hostname()))
     print('State : %s' % nmScan[host].state())
     for proto in nmScan[host].all_protocols():
         print('----------')
         print('Protocol : %s' % proto)

         lport = nmScan[host][proto].keys()
         for port in lport:
             print ('port : %s\tstate : %s' % (port, nmScan[host][proto][port]['state']))