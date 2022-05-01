import sys
import hashlib
import os
import getopt
from tkinter import *
from tkinter.ttk import *


startGUI = True

def discover_wordlists() -> list:
    """Goes through the files in the current working directory, filters out files ending in .txt, and adds them to a list,
        and returns the list."""

    # Gets all files in the current directory
    temp_fileList = os.listdir()
    fileList = []

    # Adds files matching the .txt filter to list.
    for files in temp_fileList:
        if ".txt" in files:
            fileList.append(files)
    # Sorts the list
    fileList.sort()
    # Returns the list of files, empty if no files matches the filter (".txt")
    return fileList

def determine_hash_algorithm(hash:str) -> str:
    """Makes an attempt at determining the hashing algorithm used by looking at the length of the hash, and compares it
       to the known output length of each algorithm. Adds the correct hashlib.<algorithm> to the global list
       'determinedAlgorithms', and returns a string 'result' informing the user of what algorithm is likely used."""

    global determinedAlgorithms
    #Character count of the given hash
    chars = len(hash)

    # Attempts to match the length of characters to the known output length of each algorithm.
    # Returns a list of algorithms matching the output length. (Like SHA1-256 and SHA3-256)
    if chars == 32:
        algorithm = "MD5"
        determinedAlgorithms = [hashlib.md5]

    elif chars == 40:
        algorithm = "SHA1"
        determinedAlgorithms = [hashlib.sha1]

    elif chars == 56:
        algorithm = "SHA1-224 / SHA3-224"
        determinedAlgorithms = [hashlib.sha224, hashlib.sha3_224]

    elif chars == 64:
        algorithm = "SHA1-256 / SHA3-256"
        determinedAlgorithms = [hashlib.sha256, hashlib.sha3_256]

    elif chars == 96:
        algorithm = "SHA1-384 / SHA3-384"
        determinedAlgorithms = [hashlib.sha384, hashlib.sha3_384]

    elif chars == 128:
        algorithm = "SHA1-512 / SHA3-512"
        determinedAlgorithms = [hashlib.sha512, hashlib.sha3_512]

    #If no matches are found, returns a result string informing the user, and ends the functions execution
    else:
        result = "Can not determine hash algorithm used based on the length of the hash. \nDoes not match: MD5, SHA1, SHA1-224/256/384/512, SHA3-224/256/384/512"
        return result

    #If a match is found, returns a result string informing the user of wich algorithm it might be.
    result = "Algorithm used is likely {} \nWith a length of {} bytes/characters".format(algorithm, chars)
    return result

def create_list_from_file(filename:str) -> list:
    """Reads through the given .txt file line by line, generating a list of passwords to hash and test.
        Returns the list"""

    #Opens the file, and reads all lines into a list named "data", and ignore errors.
    with open(filename, "r", errors="ignore") as file:
        data = file.read().splitlines() #Removes \n in each line
        file.close()

    #If the data list contains more than 0 entries, return it.
    if len(data)>0:
        print("List generated, containing [{}] entries".format(len(data)))
        return data
    else:
        print("Could not generate list")

def process_hash_using_list(wordlist:list, hash:str) ->str:
    """Goes through the wordlist, hashes each word using each of the algorithms in the determinedAlgorithms list and
        tests it against the hash provided by the user. Returns the result as a string, informing the user of the
        matching word and which algorithm was used, and runs the save function. Returns a result of the hash
        comparison (str)"""

    digestResult = ""
    # Makes the given hash lowercase if its not.
    hash = hash.lower()
    print("Testing hash [{}] against {} entries.".format(hash, len(wordlist)))

    # Goes through each word in the dictionary file, generates a hash, and determines if it exists there.
    for word in wordlist:
        #For each word, it also hashes with each of the algorithms determined earlier (Ex: SHA1-256 + SHA3-256)
        for algs in determinedAlgorithms:
            #The digest and hash will both be in lowercase.
            digest = algs(word.encode("utf-8")).hexdigest().lower()
            #If the hashed word (digest) matches the provided hash, success.
            if digest == hash:
                #Saves the result, runs the save function, and exits the loop
                #Also includes the __name__ property of the algorithm, using it to name the saved textfile.
                digestResult = "Password is: {} \nHashed with: {}".format(word, algs.__name__)
                save_hash(algs.__name__, digest, word)
                break

    #If no matches are found, return a string informing the user.
    if digestResult == "":
        digestResult = "Password not found in list"


    #print(digestResult)
    return digestResult #Returned string is used by the GUI

def save_hash(algorithm:str, solvedhash:str, solution:str):
    """Creates, or opens an existing file where the solved hashes are to be stored. The filename contains the algorithm
        used, and checks if the solved hash(password) already exists in the file to avoid saving duplicates.
        Returns a save location string"""

    # Used for assigning the result string to the  corresponding GUI's StringVar
    global saveResult_dynamic

    # Create or Open an existing file for appending and reading
    with open(algorithm+"_Solved.txt", "a+") as file:
        # Opening the file in append+ puts the pointer at the end of the file, in order to read the lines the pointer
        # needs to be at the beginning
        file.seek(0)
        # Adds each line (without then end character \n) into a list
        lines = file.read().splitlines()
        # Checks if the solved hash already exists in the file.
        # Appends it to the file, if unique.
        if solution not in lines:
            file.write(solution+"\n")
            save_result = "Password saved to: \n"+ os.path.abspath(file.name)
        else:
            save_result = "Password: {} already found in file: \n{}.".format(solution,os.path.abspath(file.name))
        file.close()

    #Tries to set the stringvar, and prints in case the user is using cmd.
    try:
        saveResult_dynamic.set(save_result)
    except:
        pass

    print(save_result)



def main(argv):
    """This function should only run when the program is started from the commandline.
        It takes a hash and wordfile as arguments which is passed to other functions to return a result.
        It can also find textfiles (assumed to be a list of words) with '-s', and prints help with -h."""

    inpHash = ''
    wordfile = ''

    # Tries to get passed arguments
    try:
       opts, args = getopt.getopt(argv,"hsi:f:",["inhash=","wordfile="])
    #If there is an exception in trying to get arguments, the -h text will be printed and the program will exit
    except getopt.GetoptError:
       print ("Process a hash using a wordfile. \n\n"
              "Usage:\n"+
              "-"*50+"\n"
              "-s: Scan working directory for .txt files\n"
              "-i <keyword>: The hash to 'crack'\n"
              "-f <keyword>: The .txt file to use as a dictionary\n"
              "-gui: Start the program with interactive GUI\n"
              "-cmd: Start the program with interactive commandline\n\n"
              "Example:\n"
              "PasswordCrack.py -i <input hash> -f <wordfile>\n"              
              "Use interactive GUI: PasswordCrack.py -gui\n"
              "Use interactive commandline: PasswordCrack.py -cmd")
       sys.exit()

    #Iterates through the arguments, and assigns the corresponding value (arg) to the matching variables (opt)
    for opt, arg in opts:
        if opt == "-h":
            print("Process a hash using a wordfile. \n\n"
                  "Usage:\n"+
                  "-"*50+"\n"
                  "-s: Scan working directory for .txt files\n"
                  "-i: The hash to 'crack'\n"
                  "-f: The .txt file to use as a dictionary\n"
                  "-gui: Start the program with interactive GUI\n"
                  "-cmd: Start the program with interactive commandline\n\n"
                  "Example:\n"
                  "PasswordCrack.py -i <input hash> -f <wordfile>\n"              
                  "Use interactive GUI: PasswordCrack.py -gui\n"
                  "Use interactive commandline: PasswordCrack.py -cmd")
            sys.exit()
        elif opt in ("-i", "--inhash"):
           inpHash = arg
        elif opt in ("-s", "--scan"):
           print("Text files found in current working directory: \n",discover_wordlists())
        elif opt in ("-f", "--wordfile"):
           wordfile = arg

    #If hash and file is not empty, use functions to achieve a result, then exit.
    if inpHash != "" and wordfile != "":
        # Creates a list of words from the wordfile.
        selectedlist = create_list_from_file(wordfile)
        # Determines the type of hash given.
        determine_hash_algorithm(inpHash)
        # Uses the wordlist to find a matching hash to the one provided.
        process_hash_using_list(selectedlist, inpHash)
    sys.exit()


def identify_button_clicked():
    """Function used by the GUI, btn_ident, which runs a function to try and determine the hash algorithm used. """

    global inputHash
    # Resets the save file location string when taking a new hash
    saveResult_dynamic.set("")
    # Resets the digest result when taking a new hash
    digestResult_dynamic.set("")
    # Read the Textfield from line 1, character index 0, to END -1 character.
    # The textbox adds a \n. -1c removes it.
    inputHash = inputHash_text.get("1.0",'end-1c')
    hashAlgorithm_dynamic.set(determine_hash_algorithm(inputHash))
    # Changes the Search button's state to Active
    btn_search["state"] = ACTIVE

def search_button_clicked():
    """Function used by the GUI, btn_search, takes the selected list, and given hash, and uses the process_hash_using_list() function
        to return a result"""

    # Converts the selected textfile to a list
    listToUse = create_list_from_file(combolist.get())
    # Processes the hash and wordlist
    digRes = process_hash_using_list(listToUse, inputHash)
    # Returns the result to the StringVar
    digestResult_dynamic.set(digRes)




if sys.stdin and sys.stdin.isatty():
    """This checks if arguments are passed to the program through the commandline. It will switch between GUI, commandline
        and taking arguments depending on input. """

    # This will have a minimum length of 1, since the name of the script is index 0
    if len(sys.argv) > 1:
        # If this argument is recieved, set the startGUI bool and skip other args.
        if sys.argv[1] == "-gui":
            startGUI = True
            pass
        # If this argument is recieved, set the startGUI bool to False, and skip other args
        elif sys.argv[1] == "-cmd":
            startGUI = False
            pass
        #If gui or cmd is not used, read the args as normal.
        else:
            main(sys.argv[1:])

    # If the program is run from the commandline, without arguments, the 'main' function is run
    # with the -h argument to help the user use it correctly.
    else:
        main(["-h"])
        sys.exit()

if startGUI:
    """If the startGUI bool is True, this defines the variables and elements used by Tkinter, and starts the 
    window.mainloop()"""

    window = Tk()
    window.geometry("550x450")
    window.title("Password Cracker v1")

    hashAlgorithm_dynamic = StringVar()
    hashAlgorithm_dynamic.set("Input hash and identify to determine algorithm")
    digestResult_dynamic = StringVar()
    digestResult_dynamic.set("Digest Result")
    saveResult_dynamic = StringVar()


    Label(window, text="="*5+"Enter Hash:"+"="*5).pack(pady=2, side=TOP)
    # Textbox with the same width/heigth as a SHA512 hash
    inputHash_text = Text(window, width=64, height=2)
    inputHash_text.pack(pady=2,side=TOP)

    # Button that starts the identify function
    btn_ident = Button(window, text="Identify", command=identify_button_clicked)
    btn_ident.pack(pady=2,side=TOP)
    # Label that tells the user which algorithm the hash is generated from
    labl_algorithm = Label(window, textvariable=hashAlgorithm_dynamic, wraplength=450)
    labl_algorithm.pack(pady=2,side=TOP)

    Label(window, text="Select wordlist: ").pack(pady=5, side=TOP)
    # Creates a Combolist, to be populated with .txt files
    combolist = Combobox(window)
    combolist["values"] = discover_wordlists()
    combolist.current(0)
    combolist.pack(pady=5, side=TOP)

    # Button that reloads the list. If the command=name was ended with () the function would run on startup.
    btn_search = Button(window, text="Search", command=search_button_clicked, state=DISABLED)
    btn_search.pack(pady=5,side=TOP)

    # Result of the hash process and save location, with a bigger font size for readability.
    labl_digestResult = Label(window, textvariable=digestResult_dynamic, font=("TkDefaultFont", 14)).pack(pady=10, side=TOP)
    labl_saveResult = Label(window, textvariable=saveResult_dynamic, font=("TkDefaultFont", 14)).pack(pady=10, side=TOP)

    #Starts the Tk.mainloop()
    window.mainloop()

if not startGUI:
    """ If the startGUI bool is False, runs the interactive commandline mode instead. Also works in the Python interpreter."""
    # Takes the hash you want to crack as input
    inputHash = input("Enter Hash :")
    # Attempts to determine what hash algorithm is used to digest it, and prints it to the terminal/interpreter.
    print(determine_hash_algorithm(inputHash))
    # Returns a list of all .txt files (possible wordlists) in this programs folder
    wordfiles = discover_wordlists()



    while True:
        # Prints the textfiles found in the current directory.
        print("Text files found: ")
        for f in wordfiles:
            print("[{}] - {}".format(wordfiles.index(f), f))

        selectFile = input("Please select a password list to use, [Index] or name.txt: ")

        # Selects a text file by taking either the filename or index as input. If input is a match,
        # the program generates a list from the .txt file, and passes it with the input hash to the process algorithm.
        # Then breaking out of the loop, letting the program end.
        if selectFile in wordfiles:
            selectedList = create_list_from_file(selectFile)
            process_hash_using_list(selectedList, inputHash)
            break
        elif int(selectFile) < len(wordfiles):
            selectedList = create_list_from_file(wordfiles[int(selectFile)])
            process_hash_using_list(selectedList, inputHash)
            break
