import os
import socket
import subprocess
import re
import sys, getopt
from tkinter import *
from tkinter.ttk import *
import tkinter.messagebox

startGUI = True

# A List of common TCP ports, including Nmap's top 20.
commonPorts = [20, 21, 22, 23, 25, 42, 53, 67, 68, 69, 80,
               110, 111, 119, 123, 135, 137, 138, 139,
               143, 161, 162, 389, 443, 445, 636, 873,
               993, 995, 1433, 1723, 3306, 3389, 5800, 5900, 8080]

def format_ports(portstring:str) -> list:
    """Recieves input data from the user, and filters it to turn it into a format usable by the scan_ports function.
        This function can take single ports, dash separated port ranges, and comma separated port lists. """

    try:
        #If a port range (dash separated) is recieved
        if "-" in portstring:
            ports = portstring.split("-")
            # If the user inputs something like 160-150, this will make it low>high
            ports.sort()
            #Turns the split input string into integers
            startP = int(ports[0])
            endP = int(ports[1])

            # Making sure the returned list contains a startPort lower than the endPort
            if startP <= endP:
                return list(range(startP, endP+1))
            else:
                print("Invalid portrange input")

        #If a list of ports is recieved
        elif "," in portstring:
            # Creates a list of ports from the string
            ports = portstring.split(",")
            for p in range(0, len(ports)):
                # Converts them to int's
                ports[p] = int(ports[p])
            # Sorts the ports from low to high
            ports.sort()
            # Converts the ports to a set, removing any duplicates entered by the user, then converts that to a list
            # Since the scan_ports function takes a list as an argument.
            return list(set(ports))
        # If a single port is recieved, try converting it to an int.
        else:
            ports = int(portstring)
            # Adds 1 to the end of the range, as a range excludes the last integer
            return list(range(ports, ports+1))
    except:
        print("Invalid Input")

def scan_ports(adr:str, ports:list) -> list:
    """Takes a host (ipaddress) as a list of ports as input, and goes through each port and attempts to connect to it
        using Sockets. After testing if a socket connection is successful it separates Open and Closed/Filtered ports
        into separate lists, and returns them."""

    print (ports)
    openPorts = []
    closedFilteredPorts = []

    # Goes through the ports, attempting to establish a TCP connection
    for p in ports:
        socket_obj = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        # Lower timeout means the it may skip to false even if the port is
        # open, but establishing connection is slow.
        socket.setdefaulttimeout(1)
        try:
            socket_obj.connect((adr, p))
            result = True
            # If connection is established, add the port number to the list of open ports.
            openPorts.append(p)
        except:
            result = False
            # If no connection is made, add it to the "failed" list
            closedFilteredPorts.append(p)
        # Then close the connection before trying the next port.
        socket_obj.close()

        #Prints the result to the terminal
        if result:
            print(adr, " - ", p, " is Open")
        else:
            print(adr, " - ", p, " is Closed or Filtered")

    # Returns both the list of successes and failures as a list.
    result = [openPorts, closedFilteredPorts]
    return result

def scan_local_network() -> list:
    """Scans the local network using the 'arp -a' command. It then separates the returned string into a list of lines
        and searches for patterns matching the ip_filter, the matches are then appended to a list, and the list is returned."""

    # Filters local network IP ranges
    ip_filter = ["10.", "172.", "192.168"]
    # The list starts with localhost defined.
    IPs = ["127.0.0.1"]
    # Using Regular expressions to create a filter for IP addresses
    pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
    #Stores the output as a string, reading it from stdout.
    result = subprocess.run(['arp', '-a'], stdout=subprocess.PIPE).stdout.decode('utf-8')
    #Splits the string into a list of lines
    filtered = result.splitlines()
    #Searches through the list of lines to find matching patterns, and filters out the ones matching the ip_filter
    for line in filtered:
        if any(x in line for x in ip_filter):
            IPs.append(pattern.search(line)[0])

    print("Network Scanned!")
    IPs.reverse()
    # Prints a numbered sorted list of active IPs in the network.
    for e in IPs:
        print("[{}]. {} ".format(IPs.index(e),e))
    return IPs


def scan_network_button_clicked():
    """Function for the GUI version, updates the combolist and StringVar with the local network scan result."""

    ipCombolist["values"] = scan_local_network()
    ipCombolist.current(0)
    ipScanResult_dynamic.set("Active nodes in local network: {}".format(len(ipCombolist["values"])))

def scan_ports_button_clicked(portsToScan:str,host:str):
    """Function for the GUI version, takes a start and end port, and host address as input. If the minP and maxP are
        left empty, the scan_ports() function will use the predefined list of commonPorts."""

    # If the ports the user wants to scan is left empty..
    if portsToScan == "" and host != "":
        # Take the given host, and scan the pre-defined list of ports
        result = scan_ports(host, commonPorts)
        #Sets the StringVars to be the value of the corresponding list.
        portScanOpen_dynamic.set("Open: {}".format(result[0]))
        portScanClosedFiltered_dynamic.set("Closed/Filtered: {}".format(result[1]))
    else:
    # If the user did enter ports, format them to make sure they are correct.
      try:
          entrybox_ports = format_ports(portsToScan)
          result = scan_ports(host, entrybox_ports)
          portScanOpen_dynamic.set("Open: {}".format(result[0]))
          portScanClosedFiltered_dynamic.set("Closed/Filtered: {}".format(result[1]))
    # Shows an error popup window if this fails
      except:
          tkinter.messagebox.showerror(title="Invalid input", message="Invalid input, try again.")


def main(argv):
    """This function should only run when the program is started from the commandline.
        It takes a -target (host) and -p (port/port-range/port-list) as arguments which is passed to other functions to
        return a result. using the argument '-s' lists active hosts on the network, -h prints the "help" text."""

    inp_host = ''
    inp_ports = ''

    # Tries to get passed arguments
    try:
       opts, args = getopt.getopt(argv,"hst:p:",["target=","ports="])
    except getopt.GetoptError:
        print("Scan for open TCP ports. \n\n"
              "Usage:\n" +
              "-" * 50 + "\n"
              "-h: Prints the help text\n"
              "-s: Scans the local network for active hosts.\n"
              "-t <keyword>: The target host ip address\n"
              "-p <keyword>: Port(s) to scan. Ex: '-p 80' or '-p 80-89' or '-p 80,81,82,84,89,95'\n"
              "NetMap.py -t <host> -p <port(s)>\n"
              "Scan the network for active hosts: NetMap.py -s\n"
              "Use interactive GUI: NetMap.py -gui\n"
              "Use interactive commandline: NetMap.py -cmd")
        sys.exit()

    #Iterates through the arguments, and assigns the corresponding value (arg) to the matching variables (opt)
    for opt, arg in opts:
        if opt == "-h":
            print("Scan for open TCP ports. \n\n"
                  "Usage:\n" +
                  "-" * 50 + "\n"
                  "-h: Prints the help text\n"
                  "-s: Scans the local network for active hosts.\n"
                  "-t <keyword>: The target host ip address\n"
                  "-p <keyword>: Port(s) to scan. Ex: '-p 80' or '-p 80-89' or '-p 80,81,82,84,89,95'\n"
                  "NetMap.py -t <host> -p <port(s)>\n"
                  "Scan the network for active hosts: NetMap.py -s\n"
                  "Use interactive GUI: NetMap.py -gui\n"
                  "Use interactive commandline: NetMap.py -cmd")
            sys.exit()
        elif opt in ("-t", "--target"):
           inp_host = arg
        elif opt in ("-s", "--scan"):
           scan_local_network()
        elif opt in ("-p", "--port"):
           inp_ports = arg

    #If host and ports is not empty, use functions to achieve a result, then exit.
    if inp_host != "" and inp_ports != "":
        ports = format_ports(inp_ports)
        scan_ports(inp_host, ports)
    sys.exit()


if sys.stdin and sys.stdin.isatty():
    """This checks if arguments are passed to the program through the commandline. It will switch between GUI, commandline
        and taking arguments depending on input. """

    # This will have a minimum length of 1, since the name of the script is index 0
    if len(sys.argv) > 1:
        # If this argument is recieved, set the startGUI bool and skip other args.
        if sys.argv[1] == "-gui":
            startGUI = True
            pass
        # If this argumed is recieved, set the startGUI bool to False, and skip other args
        elif sys.argv[1] == "-cmd":
            startGUI = False
            pass
        else:
            main(sys.argv[1:])

    # If the program is run from the commandline, without arguments, the 'main'
    # function is run with the -h argument to help the user use it correctly.
    else:
        main(["-h"])
        sys.exit()


if startGUI:
    """Code for the GUI, is the program is started with startGUI set to True"""
    window = Tk()
    window.geometry("500x550")
    window.title("Network Scanner v1")

    # Defines the various dynamic strings used by the GUI
    ipScanResult_dynamic = StringVar()
    ipScanResult_dynamic.set("Scan to begin")
    portScanOpen_dynamic = StringVar()
    portScanOpen_dynamic.set("Open :")
    portScanClosedFiltered_dynamic = StringVar()
    portScanClosedFiltered_dynamic.set("Closed/Filtered :")

    # Button that starts the scan network function.
    btn_ident = Button(window, text="Scan Local Network", command=scan_network_button_clicked)
    btn_ident.pack(pady=2, side=TOP)

    Label(window, textvariable=ipScanResult_dynamic, text=" Nodes found").pack(pady=2, side=TOP)
    Label(window, text="Select IP address to scan: ").pack(pady=10, side=TOP)

    # Drop-down list of hosts on the network.
    ipCombolist = Combobox(window)
    ipCombolist.pack(pady=5, side=TOP)

    Label(window, text="__"*60).pack(pady=10, side=TOP)

    Label(window, text="Select ports to scan. \nLeave empty to scan the following common ports:").pack(pady=1, side=TOP)
    Label(window, text="{}".format(commonPorts), wraplength=270).pack(side=TOP)

    # Entry field for the ports to scan
    Label(window,text="Enter a single port\nA range of ports separated by '-'\nOr a list of ports separated by ','").pack(side=TOP)
    entry_portsToScan = Entry(window)
    entry_portsToScan.pack(side=TOP)

    # Button that starts the scan, when a button is starting a command with arguments, it needs to be a lambda.
    btn_search = Button(window, text="Scan ports", command= lambda: scan_ports_button_clicked(entry_portsToScan.get(), ipCombolist.get()))  # If you end the command with () it runs on startup, except when using Lambda
    btn_search.pack(pady=10, side=TOP)


    Label(window, text="__" * 60).pack(pady=10, side=TOP)

    Label(window, textvariable=portScanOpen_dynamic).pack(pady=5,side=TOP)
    Label(window, textvariable=portScanClosedFiltered_dynamic).pack(pady=5,side=TOP)

    window.mainloop()


if not startGUI:
    """Code for the Non GUI version, if startGUI is set to False"""

    input ("Press <ENTER> to scan local network")
    while True:
        IPList = scan_local_network()
        inp_host = input("Select a host to scan [index]: ")
        # The user must select a valid host to scan
        try:
            inp_host = int(inp_host)
        except:
            pass

        # Checks if the input exists as an index in the list of hosts.
        if inp_host in range(0,len(IPList)):
            selectedHost = IPList[inp_host]
            inp_ports = input("Host <{}> selected.\n"
                              "Input a port range separated by - (ex:22-30), or a single port: ".format(selectedHost))
            # Tries to run the scan with the given input, then breaks the loop
            try:
                scan_ports(selectedHost, format_ports(inp_ports))
                break
            except:
                print("Invalid input")


