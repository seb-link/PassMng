import secrets,os
import json
import sqlite3 as sqlite
from Crypto.Cipher import AES
from hashlib import sha256
import getpass
import base64
import math
import argon2
from colorama import Fore
import pyperclip
import time


log = False
if log:
    import logging
    import datetime
    import sys
    import os

    main_script_filename = os.path.abspath(sys.argv[0])

    logging.basicConfig(filename='log.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

    def log_function_call(frame, event, arg):
        if event == 'call':
            function_name = frame.f_code.co_name
            filename = frame.f_globals.get('__file__')
            
            if filename and os.path.abspath(filename) == main_script_filename:
                logging.info(f"{datetime.datetime.now()} - func {function_name}")
                
                arg_info = ', '.join([f"{arg}: {frame.f_locals[arg]}" for arg in frame.f_locals])
                
                logging.info(f"{datetime.datetime.now()} - args: {arg_info}")
                
        return log_function_call

    sys.settrace(log_function_call)



class BytesEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, bytes):
            return obj.decode('utf-8')  # Decode bytes to utf-8
        return super().default(obj)

ph = argon2.PasswordHasher()
conn = sqlite.connect("pass.db")
cursor = conn.cursor()

def entropy(password):
    char_set = set(password)
    char_set_size = len(char_set)
    password_size = len(password)
    entropy = math.log2(char_set_size ** password_size)
    return entropy

def newdb():
    try:
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS PasswordManager (
                id INTEGER PRIMARY KEY NOT NULL ,
                website TEXT,
                username TEXT,
                password TEXT
            );
        """)
        return 0
    except sqlite.DatabaseError as e:
        print('The database is already encrypted !')
        return 1
        

def addpwd(website,username,password):
    # Update the entry with the given entry_id
    try:
        cursor.execute(f"""
            INSERT INTO PasswordManager
            (website, username,password) VALUES(?,?,?)""",(website,username,password))
        conn.commit()
    except sqlite.DatabaseError as e:
        print('The database is still encrypted !')

def deletepwd(website,username,password):
    try:
        cursor.execute(f"""
            DELETE FROM PasswordManager WHERE
            website = ? AND username = ? AND password = ?""",(website,username,password))
        conn.commit()
    except sqlite.DatabaseError as e:
        print('The database is still encrypted !')

def fetchpwdbywebsite(website):
    try:
        liste = list()
        cursor.execute(f"SELECT * FROM PasswordManager")
        entry = cursor.fetchall()
        for i in entry:
            if website in i[1]:
                liste.append(i)
        return json.dumps(liste, indent=2)
    except sqlite.DatabaseError as e:
        return "The database is either corrupt or encrypted or non-existent"
    
def fetchpwdbyindex(index):
    try:
        cursor.execute(f"SELECT * FROM PasswordManager")
        entry = cursor.fetchall()
        for i in entry:
            if str(i[0]) == str(index):
                return i
        return ()
    except sqlite.DatabaseError as e:
        return "The database is either corrupt or encrypted or non-existent"
    
def fetchpwd():
    try:
        cursor.execute(f"SELECT * FROM PasswordManager")
        entry = cursor.fetchall()
        return json.dumps(entry, indent=2)
    except sqlite.DatabaseError:
        return "The database is either corrupt or encrypted or non-existent"

def decrypt():
    global encrypted
    try:
        with open("pass.db","rb") as f:
            info = json.load(f)
    except UnicodeDecodeError:
        print("either the databse is not encrypted or the database is corrupted")
        return
    key = getpass.getpass("Enter ciphing key (will not echo): ")
    try:
        ph.verify(info["hash"],key)
    except argon2.exceptions.VerifyMismatchError:
        print("The password is incorrect")
        del key
        return
    key = sha256(key.encode()).hexdigest()
    key = key[:32]
    cipher = AES.new(key.encode(), AES.MODE_EAX, base64.b64decode(info["nonce"]))
    data = cipher.decrypt_and_verify(base64.b64decode(info["ciphertext"]), base64.b64decode(info["tag"]))
    with open("pass.db","wb") as f:
        f.write(data)
    
    encrypted = False
    

def encrypt():
    global encrypted
    with open("pass.db","rb") as f:
        data = f.read()
    key = getpass.getpass("Enter ciphing key (will not echo) : ")
    hash = ph.hash(key)
    key = sha256(key.encode()).hexdigest()
    key = key[:32]
    cipher = AES.new(key.encode(), AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    nonce = cipher.nonce
    stored_text = {"encrypted":True,"hash":hash,'nonce':base64.b64encode(nonce),'tag':base64.b64encode(tag),"ciphertext":base64.b64encode(ciphertext)}
    with open("pass.db","w") as f:
        json.dump(stored_text, f, cls=BytesEncoder, indent=2)
    encrypted = True

def main():
    print("""0.Show this panel
1.Encrypt
2.Decrypt
3.View all stocked password
4.Add password
5.Select a password
6.Search password by website
7.Delete stored password
99.Exit""")
    while 1:
        choice = input(""">> """)
        if choice == "2":
            try:
                decrypt()
            except KeyboardInterrupt:
                print("")
                continue
        elif choice == "0":
            print("""0.Show this panel
1.Encrypt
2.Decrypt
3.View all stocked password
4.Add password
5.Select a password
6.Search password by website
7.Delete stored password
99.Exit""")
        elif choice == "1":
            try:
                if newdb() == 0:
                    print(Fore.YELLOW + "WARNING LOSING ENCRYPTION KEY CAN RESULT INTO LOSING ALL STORED PASSWORD. NO KEY = NO DATA" + Fore.RESET)
                    encrypt()
            except KeyboardInterrupt:
                print("")
                continue
        elif choice == "3":   
            print(fetchpwd())
        elif choice == "4":
            try:
                newdb()
                website = input("Website : ")
                user = input('Username : ')
                password = getpass.getpass('Password (will not echo) (write RANDOM for a random password): ')
                if password == "RANDOM":
                    lenght = input("How long should the generated password should be ? : ")
                    password = secrets.token_urlsafe(int(lenght))
                    print("Random password generated !")
                if entropy(password) <= 75:
                    print(Fore.YELLOW + "WARNING : The password entropy is low ! this migh be a sign of a weak password ! Current entropy : %s" % round(entropy(password),1))
                    print(Fore.RESET)
                print("Current entropy : %s" % round(entropy(password),1))
                print(f"If your password is random it will take approximatively {2**(round(entropy(password),1)-4) / 100_000_000}s for a reasonably powerfull computer to crack it")
                a = input("Confirm add password ? Type NO to cancel ")
                if a.lower() == "no":
                    continue
                addpwd(website,user,password)
                del password
            except KeyboardInterrupt:
                print("")
                continue
        if choice == "99":
            if not encrypted:
                print(Fore.RED + "WARNING:THE DATABASE IS NOT ENCRYPTED !")
            a = input("Are you sure you wanna exit ? (Type YES to confirm): " + Fore.RESET)
            if a.lower() != "yes":
                continue
            print('Bye!')
            time.sleep(1)
            os.system('cls' if os.name=='nt' else 'clear')
            exit()
        if choice == "5":
            print(fetchpwd())
            if fetchpwd() == "The database is either corrupt or encrypted or non-existent":
                continue
            num = input("What is the numero : ")
            compo = fetchpwdbyindex(num)
            pyperclip.copy(compo[-1])
            print(Fore.YELLOW + "WARNING : The password will be removed from the clipboard in 10 seconds.")
            pyperclip.copy(compo[-1])
            time.sleep(10)
            pyperclip.copy("")
            print("The password is deleted from clipboard!" + Fore.RESET)
        if choice == "6":
            print(fetchpwdbywebsite(input("Website to search for : ")))
        if choice == "7":
            deletepwd(input("Website : "),input("Username : "),input("Password : "))

def innit():
    os.system('cls' if os.name=='nt' else 'clear')
    global encrypted
    try:
        with open("pass.db","rb") as f:
            info = json.load(f)
            info["encrypted"]
            encrypted = True
    except:
        encrypted = False
    
if __name__ == "__main__":
    innit()
    try:
        main()
    except KeyboardInterrupt:
        pass