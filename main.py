import secrets
import json
import sqlite3 as sqlite
from Crypto.Cipher import AES
from hashlib import sha256
import getpass
import base64
import math
import argon2
from colorama import Fore
from random import choice

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


def newdb() :
    try :
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS PasswordManager (
                website TEXT,
                username TEXT,
                password TEXT
            );
        """)
    except sqlite.DatabaseError :
        exit('The database is already encrypted !')
        
def addpwd(website,username,password) :
    # Update the entry with the given entry_id
    try :
        cursor.execute(f"""
            INSERT INTO PasswordManager
            (website, username,password) VALUES(?,?,?)""",(website,username,password))
        conn.commit()
    except sqlite.DatabaseError as e:
        print('The database is still encrypted !')
        print(e)

def fetchpwdbywebsite(website) :
    try :
        liste = list()
        cursor.execute(f"SELECT * FROM PasswordManager")
        entry = cursor.fetchall()
        for i in entry :
            if i[0] == website :
                liste.append(i)
        return liste
    except sqlite.DatabaseError as e:
        return f"the database is either corrupt or encrypted or non-existent {e}"
    
def fetchpwd() :
    try :
        cursor.execute(f"SELECT * FROM PasswordManager")
        entry = cursor.fetchall()
        return entry
    except sqlite.DatabaseError :
        return "the database is either corrupt or encrypted or non-existent"

def decrypt() :
    with open("pass.db","rb") as f :
        data = f.read()
    try :
        info = json.loads(data)
    except UnicodeDecodeError :
        print("either the databse is not encrypted or the database is corrupted")
    key = getpass.getpass("Enter ciphing key (will not echo) : ")
    try :
        ph.verify(info["hash"],key)
    except argon2.exceptions.VerifyMismatchError :
        print("The password is incorrect")
        del key
        return
    key = sha256(key.encode()).hexdigest()
    key = key[:32]
    cipher = AES.new(key.encode(), AES.MODE_EAX, base64.b64decode(info["nonce"]))
    data = cipher.decrypt_and_verify(base64.b64decode(info["ciphertext"]), base64.b64decode(info["tag"]))
    with open("pass.db","wb") as f :
        f.write(data)
    

def encrypt() :
    with open("pass.db","rb") as f :
        data = f.read()
    key = getpass.getpass("Enter ciphing key (will not echo) : ")
    hash = ph.hash(key)
    key = sha256(key.encode()).hexdigest()
    key = key[:32]
    cipher = AES.new(key.encode(), AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    nonce = cipher.nonce
    stored_text = {"hash":hash,'nonce':base64.b64encode(nonce),'tag':base64.b64encode(tag),"ciphertext":base64.b64encode(ciphertext)}
    with open("pass.db","w") as f :
        json.dump(stored_text, f, cls=BytesEncoder)  
print("""1.Encrypt
2.Decrypt
3.View all stocked password
4.Add password
5.Search password by website
99.Exit""")
while 1 :
    choice = input("""-> """)
    if choice == "2" :
        decrypt()
    elif choice == "1" :
        try :
            newdb()
            print(Fore.RED + "WARNING LOSING ENCRYPTION KEY CAN RESULT INTO LOSING ALL STORED PASSWORD. NO KEY = NO DATA")
            print(Fore.RESET)
            encrypt()
        except KeyboardInterrupt :
            continue
    elif choice == "3" :   
        print(fetchpwd())
    elif choice == "4" :
        try :
            newdb()
            website = input("website : ")
            user = input('username : ')
            password = getpass.getpass('password (will not echo) (write RANDOM for a random password): ')
            if password == "RANDOM" :
                lenght = input("How long should the generated password should be ? : ")
                password = secrets.token_urlsafe(int(lenght))
                print("Random password generated !")
            if entropy(password) <= 75 :
                print(Fore.YELLOW + "WARNING : The password entropy is low ! this migh be a sign of a weak password ! Current entropy : %s" % round(entropy(password),1))
                print(Fore.RESET)
            print("Current entropy : %s" % round(entropy(password),1))
            print(f"If your password is random it will take approximatively {2**(round(entropy(password),1)-4) / 100_000_000}s for a reasonably powerfull computer to crack it")
            a = input("Confirm add password ? Type NO to cancel ")
            if a.lower() == "no" :
                continue
            addpwd(website,user,password)
            del password
        except KeyboardInterrupt :
            continue
    if choice == "99" :
        exit()
    if choice == "5" :
        print(fetchpwdbywebsite(input("Website to search for : ")))
