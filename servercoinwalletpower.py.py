servers = {}
data = {"Well":"Yeah"}
data["Weel"] = {"Yeah"}
print("Data: "+str(data))
filenames ={}
VMNAMES = {}
filespacedata = {}
filespacedatapurchasesnum = 1
loadit = True
serveramount = 0
while loadit == True:
    server = int(input("Do you want to add a server or stop this? 1. for adding a server to the list or 2. for stopping this."))
    if server == 1:
        servery = input("What is the IP of the server?")
        servers[serveramount]  = servery
    else:
        loadit = False

import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import requests
import random
import sys
import time
import ast
import mnemonic
import json
import base64
from mnemonic import Mnemonic
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from ecdsa import SigningKey,VerifyingKey
from ecdsa.curves import SECP256k1
import os
import psutil
import math
import socket
import pickle
import random
import sys
import math
from flask import g
import sqlite3
import threading
import subprocess
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    encode_dss_signature,
    decode_dss_signature
)
def filesave():
       with open("files.txt","w") as file:
            json.dump(filenames,file)
def filespacesave():
       with open("filespace.txt","w") as file:
           json.dump(filespacedata,file)
def vmnamesave():
       with open("vmnames.txt","w") as file:
           json.dump(VMNAMES,file)
def listfilespacelistasafile():
       try:
        with open("files.txt","r") as file:
            filenames = json.load(file)
       except:
           print("NO!")
def listfiledatalistasafile():
       try:
        with open("filespace.txt","r") as file:
            filespacedata = json.load(file)
       except:
           print("NO!")
def listvmdatalistasafile():
       try:
        with open("vmnames.txt","r") as file:
            VMNAMES = json.load(file)
       except:
           print("NO!")
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.exceptions import InvalidSignature
from ecdsa import SigningKey,VerifyingKey
from ecdsa.curves import SECP256k1
import time
import pickle
import hashlib
import math
import socket
import requests
import base64
import copy
import random
import requests
import flask
from flask import app
from flask import request
from flask import Flask,jsonify
numbers = []
listfilespacelistasafile()
listfiledatalistasafile()
listvmdatalistasafile()
def add_padding(b64_string):
    missing_padding = len(b64_string) % 4
    if missing_padding != 0:
        b64_string += '=' * (4 - missing_padding)
    return b64_string
for item in "0123456789":
    numbers.append(item)

verifyingkey = ""
walletname = ""
LOADTHING = True
serverlists = {}
for item in servers:
    url = "http://"+str(servers[item])+"/recieveservers"
    stringything = ""
    serverlistX = {}
    response = requests.get(url)
    if response.status_code:
        data=response.json()
        data=data["Success"]
        serverlistX = ast.literal_eval(str(data))
        for itemm in str(data):
            stringything = stringything+str(itemm)
    hashthing = hashlib.sha256(stringything.encode('utf8')).hexdigest()
    if hashthing not in serverlists:
     serverlists[hashthing] = {"Servers":serverlistX,"Amount":1}
    else:
        serverlists[hashthing]["Amount"]+=1
trueserverlist = max(serverlists, key=lambda x:['Amount'])
servers = serverlists[trueserverlist]["Servers"]
print(servers)
while LOADTHING == True:
 seed_phrase = input("Seed Phrase: ")
 walletnameX = input("walletname: ")
# Derive a cryptographic key from the seed phrase
 seed_key = hashlib.sha256(seed_phrase.encode()).digest()
 mnemo = Mnemonic("english")
 seed = mnemo.to_seed(seed_phrase)
 seed_key = hashlib.sha256(seed_phrase.encode()).digest()
# Generate a private key

 salt = "22".encode('utf-8')  
 kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000,
    backend=default_backend()
 )
 key = kdf.derive(seed_phrase.encode())

 private_key3333 = ec.derive_private_key(
    int.from_bytes(key, byteorder='big'),  
    ec.SECP256R1(),  
    backend=default_backend()
 )

 private_pem = private_key3333.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
 )

 public_key3333333 = private_key3333.public_key()
 public_pem = public_key3333333.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
 )

 serverlist = {}
 serverlist = servers
 serverlen = len(serverlist)
 serverip = serverlist[str(random.randint(0,serverlen-1))]
 walletname = walletnameX
 data = {"walletname":walletnameX,"publickey":public_pem.decode('utf-8')}
 def getthatkeything():
    key = load_pem_public_key(public_pem, default_backend())
    return key
 CREATEWALLETISNECCESSARY = int(input("1. for creating a wallet, and 2. for not. and 3. for ending this."))
 if CREATEWALLETISNECCESSARY == 1:
  try:
   response = requests.post("http://"+serverip+"/createwallet",json=data)
  except Exception as e:
     print(e)
 if response.status_code == 200:
     print("Wallet created! If it didn't exist before. ")
     LOADTHING = False
     verifyingkey = seed_key
 elif CREATEWALLETISNECCESSARY == 3:
     LOADTHING = False
seed_phrase = input("What is the seed phrase of the wallet you will ACTUALLY use?")
walletname = input("What is the name of the wallet you will ACTUALLY use?")
salt = "22".encode('utf-8')  
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000,
    backend=default_backend()
)
key = kdf.derive(seed_phrase.encode())

private_key3333 = ec.derive_private_key(
    int.from_bytes(key, byteorder='big'),  
    ec.SECP256R1(),  
    backend=default_backend()
)

private_pem = private_key3333.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

public_key3333333 = private_key3333.public_key()
public_pem = public_key3333333.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)
print("PUBLICKEY: "+str(public_pem))
while True:
   Mode = int(input("1. for start a transaction. 2. for doing file stuff to a servercoin server 3. for doing filespace stuff to a servercoin server 4. for doing VM stuff to a servercoin server. or 5. for stopping this thing. or 6. Get the wallet balance. or 7. Get the filespace balance. or 8. for making the signature to make an account on a servercoinguard server or 9. for adding an ad to a servercoinguard server"))
   if Mode == 1:
       amountofcoins = float(input("What is the amount of coins you are using to spend on "))*(10**8)
       amountofcoins=math.floor(amountofcoins)
       txextra = input("What do you want the txextra to be?")
       wallet2 = input("What is the name of the wallet you are sending these coins to?")
       transactionfee = 0
       print(private_pem)
       howtogettransactionfee = int(input("1. For manually setting the transactionfee and 2. for this setting it automatically."))
       if howtogettransactionfee == 1:
           transactionfee = float(input("What is the transaction fee you want?"))*(10**8)
       else:
           transactioneefee = 0
           serverlen = len(servers)
           serverip = servers[str(random.randint(0,serverlen-1))]
           responsey = requests.get("http://"+serverip+"/getaveragetransactionfee")
           if responsey.status_code == 200:
               data=responsey.json()
               transactioneefee = int(data["Success"])
               transactionfee = transactioneefee

       url = "http://"+serverip+"/addtransaction"  # Replace 'your_server_address' with the actual server address

# Example data for the transaction
       data = {
        "Sender": walletname,
        "Reciever": wallet2,
        "amountofcoins": amountofcoins,
        "transactionfee": transactionfee,
        "txextra": txextra
       }

# Convert data to JSON format

# Sign the data
       message = str(data["Sender"])+str(data["Reciever"])+str(data["amountofcoins"])+str(data["transactionfee"])+str(data["txextra"])
       message = message.encode('utf-8')
       signature = private_key3333.sign(
         message,
         ec.ECDSA(hashes.SHA256())
       )
       try:
                                     public_key3333333.verify(
                                      signature.encode("utf-8"),
                                      message.encode('utf-8'),
                                      ec.ECDSA(hashes.SHA256())
                                    
                                     )
                                     
       except:
        print("SIGNATURE: "+str(signature))
        print("MESSAGE: "+str(message))
        print("FAILURE")
       print(signature)
# Encode the signature in base64
       encoded_signature = base64.b64encode(signature).decode('utf-8')

# Include the signature in the transaction data
       data["verifyingsig"] = encoded_signature
# Set the URL for the transaction endpoint
       data = {
        "Sender": walletname,
        "Reciever": wallet2,
        "amountofcoins": amountofcoins,
        "transactionfee": transactionfee,
        "txextra": txextra,
        "verifyingsig":encoded_signature
       }
       sender = data["Sender"]
       receiver = data["Reciever"]
       coins = data["amountofcoins"]  # Ensure proper data type for coins
       transactionfee = data["transactionfee"]  # Ensure proper data type for transaction fee
       verifyingsig = base64.b64decode(data["verifyingsig"])
       txextra = data["txextra"]
       print(verifyingsig)
       print("SIGNATURE: "+str(verifyingsig))
       json.dumps(data)
       messagething = str(sender) + str(receiver) + str(coins) + str(transactionfee) + str(txextra)
       messagething = messagething.encode('utf-8')
       print("MESSAGETHING: "+str(messagething))
       well = True
       verifyingkeyloader = ""
       
# Convert the updated data dictionary to JSON format

# Send the POST request with the transaction data
       try:
        response = requests.post(url, json=data)
        if response.status_code == 200:
         print("Transaction successful!")
        else:
         print("Transaction failed with status code:", response.status_code)
         print("Transaction failed because: ", str(response.json()))
         print("URL: "+str(url))
       except requests.RequestException as e:
        print("An error occurred:", e)
        
   elif Mode == 2:
       SUBMODE = int(input("1. for adding a file to a servercoin server. 2. for getting a file from a servercoin server. 3. for deleting a file from a servercoin server."))
       if SUBMODE == 1:
           drive = input("What is the drive of this file?")
           filename = input("What is the address of the file?")
           filename2 = drive+filename
           filedata = b""  # Use a bytes object to handle binary data
           truepower = True
           SERVERIP = ""

           try:
            with open(filename2, "rb") as file:  # Open file in binary mode
             try:
              filedata = base64.b64encode(file.read()).decode('utf-8')
             except Exception as e:
              truepower = False
              print(f"An error occurred while reading the file: {e}")
           except FileNotFoundError:
            truepower = False
            print("FILE DOESN'T EVEN EXIST")
           except Exception as e:
            truepower = False
            print(f"An error occurred: {e}")

# Rest of your code

           if truepower == True:
              choosenum = int(input("1. for selecting the cheapest servercoin server and 2. for manually selecting the servercoin server."))
              if choosenum == 1:
               print("READY@###")
               serverlen = len(servers)
               bannedservers = []
               while True:
                   serverthingSN = int(input("1. for adding a server to the banned server list. and 2. for stopping this."))
                   if serverthingSN == 1:
                       serveripy = input("What is the IP of a server")
                       bannedservers.append(serveripy)
                   else:
                       break
               for item in bannedservers:
                   if item in servers:
                       del servers[item]
               SERVERIP = servers[str(random.randint(0,serverlen-1))]
               serverlen = len(servers)
               bannedservers = []
               while True:
                   serverthingSN = int(input("1. for adding a server to the banned server list. and 2. for stopping this."))
                   if serverthingSN == 1:
                       serveripy = input("What is the IP of a server")
                       bannedservers.append(serveripy)
                   else:
                       break
               SERVERIP = input("What is the IP of the server?")
               data = {"BannedServers":bannedservers}
               responsey = requests.post("http://"+SERVERIP+"/getcheapestCSP",json=data)
               if responsey.status_code == 200:
                   dataofit = responsey.json()
                   
                  
                   price = 0
                   txextrathing = ""
                   transactionfeeee = 0
                   transactionamount = 0
                   filesize = sys.getsizeof(filedata)
                   daysoflasting = int(input("How many days do you want this file to last for?"))
                   filehash = hashlib.sha256(filedata.encode('utf8')).hexdigest()
                   loadlistnum = 0
                   loadlistnum2 = 0
                   controlthing = False
                   stringthingyyy = ""
                   filetype = input("Type Public for Public and Private for Private.")
                  
                   signaturethingy = private_key3333.sign(
                                            "ABCHGGGGGGHJJJJJJ".encode('utf-8'),
                                            ec.ECDSA(hashes.SHA256())
                                         )
                   encoded_signature = base64.b64encode(signaturethingy).decode('utf-8')
                   serverlen = len(servers)
                   ipthing = "http://"+str(dataofit["Success"])+"/addfile"
                   print("IPTHING: "+str(ipthing))
                   print("SIGNATURE: "+str(encoded_signature))
                   data = {"filetype":filetype,"filename":filename,"filedata":filedata,"walletname":walletname,"verifyingsig": encoded_signature,"messagething":"ABCHGGGGGGHJJJJJJ","dayslastingfor":daysoflasting}
                   responsey3 = requests.post(ipthing,json=data)
                  
                   if responsey3.status_code == 200:
                       datathing = responsey3.json()
                       print(datathing)
                       datathing = datathing["Success"]
                       print("THEDATA: "+str(datathing))

                       datathing2 = datathing.find("fileprice:")
                       fileprice = ""
                       lolthing = 0
                       for i in range(1000):
                           
                           if datathing[datathing2+10+lolthing] in numbers:
                               fileprice = fileprice+str(datathing[datathing2+10+lolthing])
                               lolthing+=1
                           else:
                               break
                       datathing3 = datathing.find("transactionamount:")
                       transactionamount = ""
                       lolthing = 0
                       for i in range(1000):
                           if datathing[datathing3+lolthing+len("transactionamount")+1] in numbers:
                               transactionamount = transactionamount+datathing[datathing3+lolthing+len("transactionamount")+1]
                               lolthing+=1
                               print("YEA YEA TTTTTTT")
                           else:
                               print("HERE: "+datathing[datathing3+lolthing+len("transactionamount")+1])
                               break
                       datathing4 = datathing.find("txextra:")
                       datathing5 = datathing.find("transactionfee:")
                       txextra = ""
                       lolthing = 0
                       for i in range(1000):
                           if not datathing4+8+lolthing == datathing5:
                               txextra = txextra+datathing[datathing4+8+lolthing]
                               lolthing+=1
                           else:
                               break
                       transactionfee32 = ""
                       lolthing = 0
                       print(datathing[len(datathing)-1])
                       for i in range(1000):
                         try:
                           if  datathing[len(datathing)-1+lolthing] in numbers:
                               print("DATATHING: "+datathing)
                               transactionfee32 = transactionfee32+datathing[len(datathing)-1+lolthing]
                               print("ACTION FEE"+transactionfee32)
                               lolthing+=1
                           else:
                             try:
                               print("WE MESSED UP!")
                               transactionfee32 = transactionfee32+datathing[112+lolthing]
                               print("ACTION FEE"+transactionfee32)
                               break
                             except:
                                 print("OMEGA BIG BAD MESS UP")
                                 break
                         except:
                             print("OMEGA BIG BAD NESS UP")
                             break
                               
                       Reciever = ""
                       lolthing = 0
                       datathing6 = datathing.find("selfwallet:")
                       for i in range(1000):
                           if not datathing6+11+lolthing == datathing4:
                               Reciever = Reciever+datathing[datathing6+11+lolthing]
                               lolthing+=1
                           else:
                               break
                       neofileprice = int(fileprice)/(10**8)
                       INPUTTY = int(input("fileprice: "+str(neofileprice)+ '\n' +"transactionfee: " +str(transactionfee32)+ '\n' +"Server: "+str(dataofit)+ '\n' +"1. for do the transaction or 2. for don't do it. Remember you'll have to start this transaction again if you don't answer in time."))
                       if INPUTTY == 1:
                        print("txextra: "+str(txextra))
                        print("transactionfee: "+str(transactionfee32))
                        verifythis = txextra+str(fileprice)+str(transactionfee32)+".0"
                        print("VERIFYKEY: "+str(verifythis))
                        signaturethingy = private_key3333.sign(
                                            verifythis.encode('utf-8'),
                                            ec.ECDSA(hashes.SHA256())
                                         )
                        encoded_signature = base64.b64encode(signaturethingy).decode('utf-8')
                        data2 = {"walletname":walletname,"transactionnum":int(transactionamount),"verifyingsig":encoded_signature,"txextra":txextra}
                        response = requests.post("http://"+str(dataofit["Success"])+"/finishfiletransaction",json=data2)
                        if response.status_code == 200:
                            filenames[filename2] = {"daysoflasting":daysoflasting,"Serverofit":dataofit}
                        else:
                         print("TOO LATE.")
                   else:
                       print("WWWWWW")
              else:
                   dataofit = input("What is the address of the server you want to use?")
                   
                   print("UP!")
                   price = 0
                   txextrathing = ""
                   transactionfeeee = 0
                   transactionamount = 0
                   filesize = sys.getsizeof(filedata)
                   daysoflasting = int(input("How many days do you want this file to last for?"))
                   filehash = hashlib.sha256(filedata.encode('utf8')).hexdigest()
                   loadlistnum = 0
                   loadlistnum2 = 0
                   controlthing = False
                   stringthingyyy = ""
                   filetype = input("Type Public for Public and Private for Private.")
                   signaturethingy = private_key3333.sign(
                                            "ABCHGGGGGGHJJJJJJ".encode('utf-8'),
                                            ec.ECDSA(hashes.SHA256())
                                         )
                   encoded_signature = base64.b64encode(signaturethingy).decode('utf-8')
                   data = {"filetype":filetype,"filename":filename,"filedata":filedata,"walletname":walletname,"verifyingsig":base64.b64encode(signaturethingy).decode('utf-8'),"messagething":"ABCHGGGGGGHJJJJJJ","dayslastingfor":daysoflasting}
                   responsey3 = requests.post("http://"+dataofit+"/addfile",json=data)
                   if responsey3.status_code == 200:
                       datathing = responsey3.json()
                       print(datathing)
                       datathing = datathing["Success"]
                       datathing2 = datathing.find("fileprice:")
                       fileprice = ""
                       lolthing = 0
                       for i in range(1000):
                           
                           if datathing[datathing2+10+lolthing] in numbers:
                               fileprice = fileprice+str(datathing[datathing2+10+lolthing])
                               lolthing+=1
                           else:
                               break
                       datathing3 = datathing.find("transactionamount:")
                       transactionamount = ""
                       lolthing = 0
                       for i in range(1000):
                           if datathing[datathing3+lolthing+len("transactionamount")+1] in numbers:
                               transactionamount = transactionamount+datathing[datathing3+lolthing+len("transactionamount")+1]
                               lolthing+=1
                               print("YEA YEA TTTTTTT")
                           else:
                               print("HERE: "+datathing[datathing3+lolthing+len("transactionamount")+1])
                               break
                       datathing4 = datathing.find("txextra:")
                       datathing5 = datathing.find("transactionfee:")
                       txextra = ""
                       lolthing = 0
                       for i in range(1000):
                           if not datathing4+8+lolthing == datathing5:
                               txextra = txextra+datathing[datathing4+8+lolthing]
                               lolthing+=1
                           else:
                               break
                       transactionfee32 = ""
                       lolthing = 0
                       print(datathing[len(datathing)-1])
                       for i in range(1000):
                         try:
                           if  datathing[len(datathing)-1+lolthing] in numbers:
                               print("DATATHING: "+datathing)
                               transactionfee32 = transactionfee32+datathing[len(datathing)-1+lolthing]
                               print("ACTION FEE"+transactionfee32)
                               lolthing+=1
                           else:
                             try:
                               print("WE MESSED UP!")
                               transactionfee32 = transactionfee32+datathing[112+lolthing]
                               print("ACTION FEE"+transactionfee32)
                               break
                             except:
                                 print("OMEGA BIG BAD MESS UP")
                                 break
                         except:
                             print("OMEGA BIG BAD NESS UP")
                             break
                               
                       Reciever = ""
                       lolthing = 0
                       datathing6 = datathing.find("selfwallet:")
                       for i in range(1000):
                           if not datathing6+11+lolthing == datathing4:
                               Reciever = Reciever+datathing[datathing6+11+lolthing]
                               lolthing+=1
                           else:
                               break
                       INPUTTY = int(input("fileprice: "+str(fileprice)+ '\n' +"transactionfee: " +str(transactionfee32)+ '\n' +"Server: "+str(dataofit)+ '\n' +"1. for do the transaction or 2. for don't do it. Remember you'll have to start this transaction again if you don't answer in time."))
                       if INPUTTY == 1:
                        verifythis = txextra+str(fileprice)+str(transactionfee32)+".0"
                        print("VERIFYTHIS")
                        signaturethingy = private_key3333.sign(
                                            verifythis.encode('utf-8'),
                                            ec.ECDSA(hashes.SHA256())
                                         )
                        encoded_signature = base64.b64encode(signaturethingy).decode('utf-8')
                        data2 = {"walletname":walletname,"transactionnum":int(transactionamount),"verifyingsig":encoded_signature,"txextra":str(txextra)}
                        response = requests.post("http://"+dataofit+"/finishfiletransaction",json=data2)
                        if response.status_code == 200:
                            filenames[filename] = {"daysoflasting":daysoflasting,"Serverofit":dataofit}
                            print("WE DID IT")
                        else:
                         print("TOO LATE.")
       elif SUBMODE == 2:
           filename = input("What is the name of the file?")
           
           serverlen = len(servers)
           serveripthing = input("What is the server the file is stored on?")
           verifythis = str(filename)
           verifythis = verifythis.encode('utf8')
           verifyingsig = private_key3333.sign(
                                            verifythis,
                                            ec.ECDSA(hashes.SHA256())
                                         )
           encoded_signature = base64.b64encode(verifyingsig).decode('utf-8')
           data = {"walletname":walletname,"verifyingsig":encoded_signature,"filename":filename}
           responset4 = requests.post("http://"+serveripthing+"/getfile",json=data)
           if responset4.status_code == 200:
                   data = responset4.json()
                   if not data == "":
                    with open(filename,"wb") as file:
                       file.write(base64.b64decode(data["Success"]))
           else:
               print("YOU CANT GET TO THIS FILE, OR IT DOESNT EXIST")
       elif SUBMODE == 3:
           filename = input("What is the name of the file?")
           verifythis = str(filename)+str(walletname)
           verifythis = verifythis.encode('utf8')
           verifyingsig = private_key3333.sign(
                                            verifythis,
                                            ec.ECDSA(hashes.SHA256())
           )
           encoded_signature = base64.b64encode(verifyingsig).decode('utf-8')
           server = input("What is the server this file is on?")
           data3333 = {"walletname":walletname,"filename":filename,"verifyingsig":encoded_signature}
           requests.post("http://"+server+"/deletefilealt",json=data3333)
   elif Mode == 3:
       SUBMODE = int(input("1. for buying filespace from a servercoin server. 2. for getting a file from a servercoin server. 3. for adding a file to a servercoin server"))
       if SUBMODE == 1:
           filespace = int(input("What is the amount of filespace you want to buy?"))
           daysoflastingy = int(input("How many days do you want this to last for?"))
           verifythis = str(filespace)+str(daysoflastingy)
           verifythis = verifythis.encode('utf8')
           verifyingsig = private_key3333.sign(
                                            verifythis,
                                            ec.ECDSA(hashes.SHA256())
                                         )
           
           encoded_signature = base64.b64encode(verifyingsig).decode('utf-8')
           data = {"Sender":walletname,"verifyingsig":encoded_signature,"filespace":filespace,"daysoflasting":daysoflastingy}
           choosenum = int(input("1. for selecting the cheapest servercoin server and 2. for manually selecting the servercoin server."))
           if choosenum == 1:
               serverlen = len(servers)
               bannedservers = []
               while True:
                   serverthingSN = int(input("1. for adding a server to the banned server list. and 2. for stopping this."))
                   if serverthingSN == 1:
                       serveripy = input("What is the IP of a server")
                       bannedservers.append(serveripy)
                   else:
                       break
               SERVERIP = servers[str(random.randint(0,serverlen-1))]
               data2 = {"BannedServers":bannedservers}
               responsey = requests.post("http://"+SERVERIP+"/getcheapestCSP",json=data2)
               if responsey.status_code == 200:
                   dataofit = responsey.json()
                   responsey3 = requests.post("http://"+dataofit["Success"]+"/startfilespacepurchase",json=data)
                   if responsey3.status_code == 200:
                       datathingyy = responsey3.json()
                       datathingyy = datathingyy["Success"]
                       print("Data: "+str(datathingyy))
                       datathingyy2 = datathingyy.find("filepricething:")
                       filepricething = ""
                       lolthing = 0
                       for i in range(1000):
                           
                           try:
                            if datathingyy[datathingyy2+lolthing+15] in numbers:
                               filepricething = filepricething+str(datathingyy[datathingyy2+lolthing+15])
                               lolthing+=1
                            else:
                               break
                           except:
                               break
                       pendingtransactionnum = ""
                       lolthing = 0
                       for i in range(1000):
                           if not datathingyy[lolthing] == "f":
                               pendingtransactionnum = pendingtransactionnum+str(datathingyy[lolthing])
                               lolthing+=1
                           else:
                               break
                       transactionfeex = ""
                       datathingyy3 = datathingyy.find("transactionfee:")
                       lolthing = 0
                       for i in range(1000):
                         try:
                           if  datathingyy[datathingyy3+15+lolthing] in numbers:
                               transactionfeex = transactionfeex+str(datathingyy[datathingyy3+15+lolthing])
                               lolthing+=1
                         except:
                             print("WE RUN OUT OF ROOM!")
                             print("THING: "+str(datathingyy[datathingyy3+15+lolthing]))
                             break
                       txextra = ""
                       lolthing = 0
                       datathingyy4 = datathingyy.find("txextra:")
                       for i in range(1000):
                           if not int(datathingyy4+lolthing+8) == int(datathingyy3):
                               txextra = txextra+str(datathingyy[datathingyy4+lolthing+8])
                               lolthing+=1
                           else:
                               break
                       reciever = ""
                       lolthing = 0
                       datathingyy5 = datathingyy.find("selfwallet:")
                       for i in range(1000):
                           if not datathingyy5+lolthing+11 == datathingyy4:
                               reciever = reciever+str(datathingyy[datathingyy5+lolthing+11])
                               lolthing+=1
                           else:
                               print("DATAPIECE1: "+str(datathingyy5+lolthing+11))
                               print("DATAPIECE2: "+str(datathingyy4+8))

                               break
                       neofilepricething = int(filepricething)/(10**8)
                       stringthingpower = "filepricething: "+str(neofilepricething)+'\n'+"transactionfee: "+str(transactionfeex)+'\n'+"server: "+str(dataofit)+'\n'+"1. For I accept the offer and 2. for I decline the offer."
                       inputthingy = int(input(stringthingpower))
                       if inputthingy == 1:
                           verifythisthing = str(pendingtransactionnum)+str(filespace)+str(daysoflastingy)+str(reciever)+str(txextra)+str(math.floor(int(filepricething)))+str(math.floor(int(transactionfeex)))
                           
                           verifyingsig = private_key3333.sign(
                                            verifythisthing.encode('utf-8'),
                                            ec.ECDSA(hashes.SHA256())
                                         )
                           print("VERIFYTHING: "+str(verifythisthing))
                           encoded_signature = base64.b64encode(verifyingsig).decode('utf-8')
                           datayyy = {"pendingtransactionnum":int(pendingtransactionnum),"verifyingsig":encoded_signature}
                           filespacedata[filespacedatapurchasesnum] = {"TimePurchased":time.time(),"DaysOfLasting":daysoflastingy,"Serverbeingused":dataofit}
                           try:
                            responsepawn = requests.post("http://"+dataofit["Success"]+"/endfilespacepurchase",json=datayyy)
                            print(responsepawn.status_code)
                           except:
                               print("WE FAILED.")
                           print("W")
           else:
                   dataofit = input("What is the address of the server you are using?")
                   responsey3 = requests.post("http://"+dataofit+"/startfilespacepurchase",json=data)
                   if responsey3.status_code == 200:
                       datathingyy = responsey3.json()
                       datathingyy = datathingyy["Success"]
                       print("Data: "+str(datathingyy))
                       datathingyy2 = datathingyy.find("filepricething:")
                       filepricething = ""
                       lolthing = 0
                       for i in range(1000):
                           
                           try:
                            if datathingyy[datathingyy2+lolthing+15] in numbers:
                               filepricething = filepricething+str(datathingyy[datathingyy2+lolthing+15])
                               lolthing+=1
                            else:
                               break
                           except:
                               break
                       pendingtransactionnum = ""
                       lolthing = 0
                       for i in range(1000):
                           if not datathingyy[lolthing] == "f":
                               pendingtransactionnum = pendingtransactionnum+str(datathingyy[lolthing])
                               lolthing+=1
                           else:
                               break
                       transactionfeex = ""
                       datathingyy3 = datathingyy.find("transactionfee:")
                       lolthing = 0
                       for i in range(1000):
                         try:
                           if  datathingyy[datathingyy3+15+lolthing] in numbers:
                               transactionfeex = transactionfeex+str(datathingyy[datathingyy3+15+lolthing])
                               lolthing+=1
                         except:
                             print("WE RUN OUT OF ROOM!")
                             break
                       txextra = ""
                       lolthing = 0
                       datathingyy4 = datathingyy.find("txextra:")
                       for i in range(1000):
                           if not int(datathingyy4+lolthing+8) == int(datathingyy3):
                               txextra = txextra+str(datathingyy[datathingyy4+lolthing+8])
                               lolthing+=1
                           else:
                               break
                       reciever = ""
                       lolthing = 0
                       datathingyy5 = datathingyy.find("selfwallet:")
                       for i in range(1000):
                           if not datathingyy5+lolthing+11 == datathingyy4:
                               reciever = reciever+str(datathingyy[datathingyy5+lolthing+11])
                               lolthing+=1
                           else:
                               print("DATAPIECE1: "+str(datathingyy5+lolthing+11))
                               print("DATAPIECE2: "+str(datathingyy4+8))

                               break
                       stringthingpower = "filepricething: "+str(int(filepricething)/(10**8))+'\n'+"transactionfee: "+str(transactionfeex)+'\n'+"server: "+str(dataofit)+'\n'+"1. For I accept the offer and 2. for I decline the offer."
                       inputthingy = int(input(stringthingpower))
                       if inputthingy == 1:
                           verifythisthing = str(pendingtransactionnum)+str(filespace)+str(daysoflastingy)+str(reciever)+str(txextra)+str(filepricething)+str(transactionfeex)
                           print("txextra:"+str(txextra))
                           print("RECIEVER: "+str(reciever))
                           print("VERIFYTHISTHING: "+str(verifythisthing))
                           verifyingsig = private_key3333.sign(
                                            verifythisthing.encode('utf-8'),
                                            ec.ECDSA(hashes.SHA256())
                                         )
                           encoded_signature = base64.b64encode(verifyingsig).decode('utf-8')
                           datayyy = {"pendingtransactionnum":int(pendingtransactionnum),"verifyingsig":encoded_signature}
                           filespacedata[filespacedatapurchasesnum] = {"TimePurchased":time.time(),"DaysOfLasting":daysoflastingy,"Serverbeingused":dataofit}
                           requests.post("http://"+dataofit+"/endfilespacepurchase",json=datayyy)
       elif SUBMODE == 2:
           filename = input("What is the name of the file you are getting???")
           servery = input("What is the server you are getting the file from???")
           verifythis33 = str(walletname)+str(filename)
           verifythis33 = verifythis33.encode('utf8')
           verifyingsig = private_key3333.sign(
                                            verifythis33,
                                            ec.ECDSA(hashes.SHA256())
           )
           encoded_signature = base64.b64encode(verifyingsig).decode('utf-8')
           data = {"walletname":walletname,"filename":filename,"verifyingsig":encoded_signature}
           responseXX = requests.post("http://"+servery+"/getaltfile",json=data)
           if responseXX.status_code == 200:
               datajson = responseXX.json()
               print("DATAJSON: "+str(datajson))
               with open(str(filename),"wb") as file:
                   file.write(base64.b64decode(datajson["Success"]))
       elif SUBMODE == 3:
           filedrivename = input("WHAT IS THE DRIVE NAME?")
           filename = input("What is the name of the file you are uploading?")
           filenamething = filedrivename+filename
           servery = input("What is the server you are uploading to?")
           filetype = input("Public for public file and Private for private file.")
           filedata = ""
           truepoweralt = True
           try:
            with open(filenamething,"rb") as file:
                filedata=base64.b64encode(file.read()).decode('utf-8')
           except:
               truepoweralt = False
           if truepoweralt == True:
               verifythis33 = str(filename)+str(walletname)
               verifythis33 = verifythis33.encode('utf8')
               verifyingsig = private_key3333.sign(
                                            verifythis33,
                                            ec.ECDSA(hashes.SHA256())
               )
               verifythis66 = str(filename)+str(walletname)
               try:
                 public_key3333333.verify(
                  verifyingsig,
                  verifythis66.encode('utf-8'),
                  ec.ECDSA(hashes.SHA256())
                 )
               except:
                   print("FOUND THE ERROR!!!")
               encoded_signature = base64.b64encode(verifyingsig).decode('utf-8')
               data2 = {"filedata":filedata,"filename":filename,"walletname":walletname,"verifyingsig":encoded_signature,"filetype":filetype}
               requests.post("http://"+servery+"/addfilealt",json=data2)
   elif Mode==4:
       submode = int(input("1. for buying vm data, 2. for adding a file to VM, 3 for starting up a VM, 4 for executing a command on the VM, 5 for creating a VM, 6 for deleting a VM, 7 for stopping a VM., and 8 for deleting a file from a VM"))
       if submode == 1:
           Buything = int(input("1. for cheapest VCPUS, 2. for cheapest datatransfer, 3. for cheapest storage price, 4. for cheapest Ram price, 5. for you choosing your own server. "))
           dataofthis = ""
           bannedservers = []
           while True:
                   serverthingSN = int(input("1. for adding a server to the banned server list. and 2. for stopping this."))
                   if serverthingSN == 1:
                       serveripy = input("What is the IP of a server")
                       bannedservers.append(serveripy)
                   else:
                       break
           if Buything == 1:
               data = {"BannedServers":bannedservers}
               serverlen = len(servers)
               servery = servers[str(random.randint(0,serverlen-1))]
               print("http://"+servery+"/getcheapestCSP2")
               responsething5t = requests.post("http://"+servery+"/getcheapestCSP2",json=data)
               responsething5t = responsething5t.json()
               dataofthis = responsething5t["Success"]
           elif Buything == 2:
               data = {"BannedServers":bannedservers}

               serverlen = len(servers)
               servery = servers[str(random.randint(0,serverlen-1))]
               responsething5t = requests.post("http://"+servery+"/getcheapestCSP4",json=data)
               responsething5t = responsething5t.json()
               dataofthis = responsething5t["Success"]
           elif Buything == 3:
               data = {"BannedServers":bannedservers}

               serverlen = len(servers)
               servery = servers[str(random.randint(0,serverlen-1))]
               responsething5t = requests.post("http://"+servery+"/getcheapestCSP",json=data)
               responsething5t = responsething5t.json()
               dataofthis = responsething5t["Success"]
           elif Buything == 4:
               data = {"BannedServers":bannedservers}

               serverlen = len(servers)
               servery = servers[str(random.randint(0,serverlen-1))]
               responsething5t = requests.post("http://"+servery+"/getcheapestCSP3",json=data)
               responsething5t = responsething5t.json()
               dataofthis = responsething5t["Success"]
           elif Buything == 5:
               dataofthis = input("What is your server?")
           RAMGB = float(input("WHAT IS the ram you want? "))*(10**9)
           DATASTORAGEGB = float(input("WHAT IS THE DATASTORAGE YOU WANT?"))*(10**9)
           DATATRANSFERGB = float(input("WHAT IS THE DATATRANSFER amount you want?"))*(10**9)
           VCPUS = int(input("What is the amount of VCPUS you want?"))
           DAYS = int(input("How many days will this last?"))
           serverlen = len(servers)
           servery = servers[str(random.randint(0,serverlen-1))]
           verifythis33 = str(RAMGB)+str(DATASTORAGEGB)+str(VCPUS)+str(DATATRANSFERGB)+str(walletname)+str(DAYS)
           verifythis33 = verifythis33.encode('utf8')
           verifyingsig22 = private_key3333.sign(
                                            verifythis33,
                                            ec.ECDSA(hashes.SHA256())
           )
          
           encoded_signature = base64.b64encode(verifyingsig22).decode('utf-8')
           verifythis66 = str(RAMGB)+str(DATASTORAGEGB)+str(VCPUS)+str(DATATRANSFERGB)+str(walletname)+str(DAYS)
           try:
            public_key3333333.verify(
             base64.b64decode(encoded_signature),
             verifythis66.encode('utf-8'),
             ec.ECDSA(hashes.SHA256())
            )
           except:
               print("MESS UP!")
           jsondata = {"RAMGB":RAMGB,"DATASTORAGEGB":DATASTORAGEGB,"VCPUS":VCPUS,"DATATRANSFERGB":DATATRANSFERGB,"verifyingsig":encoded_signature,"daysoflasting":DAYS,"walletname":walletname}
           requestpower = requests.post("http://"+dataofthis+"/startVMSTUFFTRANSACTION",json=jsondata)
           requestdata = requestpower.json()
           requestdata =requestdata["Success"]
           
           Price = ""
           walletname = ""
           txextra = ""
           pendingvmnum = ""
           selfwallet = ""
           transactionfee = ""
           datathingpower1 = requestdata.find("Price:")
           datathingpower2 = requestdata.find("walletname:")
           datathingpower3 = requestdata.find("txextra:")
           datathingpower4 = requestdata.find("pendingvmnum:")
           datathingpower5 = requestdata.find("selfwallet:")
           datathingpower6 = requestdata.find("transactionfee:")
           lolthing=0
           bannedservers = []
           for i in range(1000):
                           
                           try:
                            if requestdata[datathingpower1+lolthing+len("Price:")] in numbers:
                               Price = Price+str(requestdata[datathingpower1+len("Price:")+lolthing])
                               lolthing+=1
                            else:
                               break
                           except:
                               break
           lolthing=0
           for i in range(1000):
                           
                           try:
                            if not datathingpower2+lolthing+len("walletname:") ==datathingpower3:
                               walletname = walletname+str(requestdata[datathingpower2+len("walletname:")+lolthing])
                               lolthing+=1
                            else:
                               break
                           except:
                               break
           lolthing=0
           for i in range(1000):
                           
                           try:
                            if not datathingpower3+lolthing+len("txextra:") ==datathingpower4:
                               txextra = txextra+str(requestdata[datathingpower3+len("txextra:")+lolthing])
                               lolthing+=1
                            else:
                               break
                           except:
                               break
           lolthing=0
           for i in range(1000):
                           
                           try:
                            if  requestdata[datathingpower4+lolthing+len("pendingvmnum:")] in numbers:
                               pendingvmnum = pendingvmnum+str(requestdata[datathingpower4+len("pendingvmnum:")+lolthing])
                               lolthing+=1
                            else:
                               break
                           except:
                               break
           lolthing=0
           for i in range(1000):
                           
                           try:
                            if not datathingpower5+lolthing+len("selfwallet:") ==datathingpower6:
                               selfwallet= selfwallet+str(requestdata[datathingpower5+len("selfwallet:")+lolthing])
                               lolthing+=1
                            else:
                               break
                           except:
                               break
           lolthing=0
           for i in range(1000):
                           
                           try:
                            if not datathingpower6+lolthing+len("transactionfee:") ==len(requestdata):
                               transactionfee= transactionfee+str(requestdata[datathingpower6+len("transactionfee:")+lolthing])
                               lolthing+=1
                            else:
                               break
                           except:
                               break
           verifythis = str(Price)+walletname+txextra+str(pendingvmnum)+str(selfwallet)+str(transactionfee)
           print("VERIFYTHIS: "+str(verifythis))
           verifyingsig = private_key3333.sign(
                                            verifythis.encode('utf-8'),
                                            ec.ECDSA(hashes.SHA256())
           )
           encoded_signature = base64.b64encode(verifyingsig).decode('utf-8')
           datae = {"WP":"LOL"}
           response44 = requests.post("http://"+dataofthis+"/getOS",json=datae)
           response44 = response44.json()
           response44 = response44["Success"]
           numtoload = int(input("Server: "+str(dataofthis)+"\nPrice: "+str(int(Price)/(10**8))+"\nTransactionfee: "+str(int(transactionfee)/(10**8))+'\nOS: '+str(response44)+"\n1. for do the purchase and 2. for don't do the purchase."))
           datathing = {"verifyingsig":encoded_signature,"vmtransactionnum":int(pendingvmnum)}
           if numtoload == 1:
             response66 = requests.post("http://"+dataofthis+"/endVMSTUFFTRANSACTION",json=datathing)
       elif submode == 2:
         subsubmode = int(input("1. for file on server and 2. for file not on server."))
         if subsubmode == 1:
           filename = input("What is the name of the file?")
           vmname = input("What is the name of the VM?")
           verifythis = str(vmname)+str(filename)
           verifythis = verifythis.encode('utf-8')
           verifyingsig = private_key3333.sign(
                                            verifythis.encode('utf-8'),
                                            ec.ECDSA(hashes.SHA256())
           )
           encoded_signature = base64.b64encode(verifyingsig).decode('utf-8')
           data = {"verifyingsig":encoded_signature,
                   "walletname":walletname,
                   "filename":filename,
                   "vmname":vmname}
           serverip = input("What is the server you are connecting to?")
           requests.post("http://"+serverip+"/ADDFILETOVM",json=data)
         else:
           vmname = input("What is the name of the VM?")
           Drive = input("What is the drive of this file?")
           filename = input("What is the name of the file?")
           verifythis = str(vmname)+str(filename)
           verifythis = verifythis.encode('utf-8')
           serverip = input("What is the server you are connecting to?")
           verifyingsig = private_key3333.sign(
                                            verifythis,
                                            ec.ECDSA(hashes.SHA256())
           )
           encoded_signature = base64.b64encode(verifyingsig).decode('utf-8')
           filedata = ""
           truepowerX = True
           try:
               with open(filename,"rb") as file:
                   filedata = base64.b64encode(file.read()).decode('utf-8')
           except:
               truepowerX = False
           data = {"verifyingsig":encoded_signature,
                   "walletname":walletname,
                   "filename":filename,
                   "vmname":vmname,
                   "filedata":filedata}
           requests.post("http://"+serverip+"/ADDFILETOVM2",json=data)
       elif submode == 3:
           vmname = input("What is the name of the VM?")
           verifyingsig = private_key3333.sign(
                                            vmname.encode('utf-8'),
                                            ec.ECDSA(hashes.SHA256())
           )
           encoded_signature = base64.b64encode(verifyingsig).decode('utf-8')
           serverip = input("What is the server you are connecting to?")

           data = {"verifyingsig":encoded_signature,
                   "vmname":vmname,
                   "walletname":walletname}
           requests.post("http://"+serverip+"/startvm",json=data)
       elif submode == 4:
           vmname = input("What is the name of the VM")
           command = input("Enter a command for this.")
           verifythis = vmname+command
           verifyingsig = private_key3333.sign(
                                            verifythis.encode('utf-8'),
                                            ec.ECDSA(hashes.SHA256())
           )
           encoded_signature = base64.b64encode(verifyingsig).decode('utf-8')
           serverip = input("What is the server you are connecting to?")
           data = {"vmname":vmname,
                   "command":command,
                   "verifyingsig":encoded_signature,
                   "wallet":walletname}
           requests.post("http://"+serverip+"/executecommand",json=data)
       elif submode == 5:
           DATATRANSFERMB = int(input("How many megabytes are you using for the datatransfer balance."))
           RAMMB = int(input("How many ram megabytes are you using for this thing?"))
           DATASTORAGEMB = int(input("How many megabytes are using for this thing's datastorage?"))
           VCPUS = int(input("How many VCPUS do you want this thing to have."))
           verifythis = str(VCPUS)+str(DATATRANSFERMB)+str(RAMMB)+str(DATASTORAGEMB)
           verifyingsig = private_key3333.sign(
                                            verifythis.encode('utf-8'),
                                            ec.ECDSA(hashes.SHA256())
           )
           encoded_signature = base64.b64encode(verifyingsig).decode('utf-8')
           data = {"VCPUS":VCPUS,
                   "DATASTORAGEMB":DATASTORAGEMB,
                   "RAMMB":RAMMB,
                   "DATATRANSFERMB":DATATRANSFERMB,
                   "walletname":walletname,
                   "verifyingsig":encoded_signature}
           serverip = input("What is the server you are connecting to?")
           response = requests.post("http://"+serverip+"/createvm",json=data)
           responsedata = response.json()
           responsedata = responsedata["Success"]
           VMNAMES[responsedata] = {"VMDATE":time.time(),"DATATRANSFERMB":DATATRANSFERMB,"RAMMB":RAMMB,"DATASTORAGEMB":DATASTORAGEMB,"VCPUS":VCPUS,"IP":""}
           print("VMName: "+str(responsedata))
       elif submode==6:
          vmname = input("What is the name of the VM?")
          verifyingsig = private_key3333.sign(
                                            vmname.encode('utf-8'),
                                            ec.ECDSA(hashes.SHA256())
          )
          encoded_signature = base64.b64encode(verifyingsig).decode('utf-8')
          data = {"vmname":vmname,
                  "verifyingsig":encoded_signature,
                  "walletname":walletname}
          serverip = input("What is the server you are connecting to?")
          requests.post("http://"+serverip+"/DELETEVM",json=data)
       elif submode == 7:
          vmname = input("What is the name of the VM?")
          verifyingsig = private_key3333.sign(
                                            vmname.encode('utf-8'),
                                            ec.ECDSA(hashes.SHA256())
          )
          encoded_signature = base64.b64encode(verifyingsig).decode('utf-8')
          data = {"vmname":vmname,
                  "verifyingsig":encoded_signature,
                  "walletname":walletname
          }
          serverip = input("What is the server you are connecting to?")
          requests.post("http://"+serverip+"/STOPVM",json=data)
       elif submode == 8:
         vmname = input("What is the name of the VM?")
         filename = input("What is the name of the file?")
         serverip = input("What is the server you are connecting to?")
         verifyingsig = private_key3333.sign(
                                            vmname.encode('utf-8'),
                                            ec.ECDSA(hashes.SHA256())
          )
         encoded_signature = base64.b64encode(verifyingsig).decode('utf-8')
         data = {"walletname":walletname,
                 "verifyingsig":encoded_signature,
                 "filename":filename,
                 "vmname":vmname}
         requests.post("http://"+serverip+"/deletevmfile",json=data)
       elif submode == 10:
         vmname = input("What is the name of the VM?")
         filename = input("What is the name of the file?")
         serverip = input("What is the server you are connecting to?")
         datathing = str(vmname)+str(filename)
         verifyingsig = private_key3333.sign(
                                            datathing.encode('utf-8'),
                                            ec.ECDSA(hashes.SHA256())
          )
         encoded_signature = base64.b64encode(verifyingsig).decode('utf-8')
         data = {"walletname":walletname,
                 "verifyingsig":encoded_signature,
                 "filename":filename,
                 "vmname":vmname}
         newdata = requests.post("http://"+serverip+"/GETFILEFROMVM",json=data)
         newdata = newdata.json()
         newdata = newdata["Success"]
         with open(str(filename),"wb") as file:
             file.write(base64.b64decode(newdata))
         
       elif submode == 9:
            vmname = input("What is the name of the VM?")
            serverip = input("What is the server you are connecting to?")
            verifyingsig = private_key3333.sign(
                                            vmname.encode('utf-8'),
                                            ec.ECDSA(hashes.SHA256())
            ) 
            encoded_signature = base64.b64encode(verifyingsig).decode('utf-8')
            data = {"walletname":walletname,
                 "verifyingsig":encoded_signature,
                 
                 "vmname":vmname}
            responsething = requests.post("http://"+serverip+"/getIP",json=data)
            responsedata = responsething.json()
            responsedata = responsething["Success"]
            VMNAMES[vmname]["IP"] = responsedata
   elif Mode==5:
       filespacesave()
       filesave()
       vmnamesave()
   elif Mode==6:
               dataxx ={"walletname":walletname}
               responsething = requests.post("http://"+servery+"/getwalletbalance",json=dataxx)
               if responsething.status_code == 200:
                responsedatathing = responsething.json()
                print(str(walletname)+"walletbalance: "+str(responsedatathing))
               else:
                print("Response: "+str(responsething))
   elif Mode==7:
       verifyingsig = private_key3333.sign(
                                            walletname.encode('utf-8'),
                                            ec.ECDSA(hashes.SHA256())
               )
       encoded_signature = base64.b64encode(verifyingsig).decode('utf-8')
       datathing = {"walletname":walletname,"verifyingsig":encoded_signature}
       IP = input("What is the address of the server you are asking for the filespace?")
       response = requests.post("http://"+str(IP)+"/getfilespace",json=datathing)
       dataspone = response.json()
       print("Filespace: "+str(dataspone["Success"]))
   elif Mode==8:
       SignThis = input("What is the password you are inputting on the website?")
       verifyingsig = private_key3333.sign(
                                            SignThis.encode('utf-8'),
                                            ec.ECDSA(hashes.SHA256())
               )
       encoded_signature = base64.b64encode(verifyingsig).decode('utf-8')
       with open("encodedsignature.txt","w") as file:
           file.write(encoded_signature)
       decoded_signature = base64.b64decode(encoded_signature)

# Now `decoded_signature` contains the original signature before it was encoded
       print(decoded_signature)
       try:
                public_key3333333.verify(
                   decoded_signature,
                   SignThis.encode('utf-8'),
                   ec.ECDSA(hashes.SHA256())
                )
                DOITNOW = True
       except:
                print("OHH THAT'S IT!")
                DOITNOW = False
   elif Mode==9:
       Coins = int(input("How many coins are you sending to that servercoin guard system?"))*(10**8)
       Wallet = input("What's the wallet of the servercoin guard system")
       Domain = input("What's the domain")
       Imagelink = input("What's the place the image you are uploading is stored on your computer")
       Imagename = input("What do you want the image to be called?")
       Imagetype = input("What is the file extension of the image?")
       Link = input("Where is the add linking to?")
       txextra = input("What do you want the txextra to be?")
       transactionfee = 0
       print(private_pem)
       howtogettransactionfee = int(input("1. For manually setting the transactionfee and 2. for this setting it automatically."))
       if howtogettransactionfee == 1:
           transactionfee = float(input("What is the transaction fee you want?"))*(10**8)
       else:
           transactioneefee = 0
           serverlen = len(servers)
           serverip = servers[str(random.randint(0,serverlen-1))]
           responsey = requests.get("http://"+serverip+"/getaveragetransactionfee")
           if responsey.status_code == 200:
               data=responsey.json()
               transactioneefee = int(data["Success"])
               transactionfee = transactioneefee
       url = "http://"+serverip+"/addtransaction"  # Replace 'your_server_address' with the actual server address

# Example data for the transaction
       data = {
        "Sender": walletname,
        "Reciever": Wallet,
        "amountofcoins": Coins,
        "transactionfee": transactionfee,
        "txextra": txextra
       }

# Convert data to JSON format

# Sign the data
       message = str(data["Sender"])+str(data["Reciever"])+str(data["amountofcoins"])+str(data["transactionfee"])+str(data["txextra"])
       message = message.encode('utf-8')
       signature = private_key3333.sign(
         message,
         ec.ECDSA(hashes.SHA256())
       )
       try:
                                     public_key3333333.verify(
                                      signature.encode("utf-8"),
                                      message.encode('utf-8'),
                                      ec.ECDSA(hashes.SHA256())
                                    
                                     )
                                     
       except:
        print("SIGNATURE: "+str(signature))
        print("MESSAGE: "+str(message))
        print("FAILURE")
       print(signature)
# Encode the signature in base64
       encoded_signature = base64.b64encode(signature).decode('utf-8')

# Include the signature in the transaction data
       data["verifyingsig"] = encoded_signature
# Set the URL for the transaction endpoint
       data = {
        "Sender": walletname,
        "Reciever": Wallet,
        "amountofcoins": Coins,
        "transactionfee": transactionfee,
        "txextra": txextra,
        "verifyingsig":encoded_signature
       }
       sender = data["Sender"]
       receiver = data["Reciever"]
       coins = data["amountofcoins"]  # Ensure proper data type for coins
       transactionfee = data["transactionfee"]  # Ensure proper data type for transaction fee
       verifyingsig = base64.b64decode(data["verifyingsig"])
       txextra = data["txextra"]
       print(verifyingsig)
       print("SIGNATURE: "+str(verifyingsig))
       json.dumps(data)
       messagething = str(sender) + str(receiver) + str(coins) + str(transactionfee) + str(txextra)
       messagething = messagething.encode('utf-8')
       print("MESSAGETHING: "+str(messagething))
       well = True
       verifyingkeyloader = ""
       filedata = ""
# Convert the updated data dictionary to JSON format

# Send the POST request with the transaction data
       try:
        print("DATAHERE: "+str(data))
        response = requests.post(url, json=data)
        if response.status_code == 200:
         print("Transaction successful!")
         with open(Imagelink,"rb") as file:
             filedata = base64.b64encode(file.read()).decode("utf-8")
         response = response.json()
         device = response["Success"]
         print("device: "+str(device))
         blocknum = device["Block"]
         transactionid = device["Transactionid"]
         data = {"coins":coins,
                 "link":Link,
                 "imagename":Imagename,
                 "imagetype":Imagetype,
                 "imagedata":filedata,
                 "transactionid":transactionid,
                 "blocknum":blocknum,
                 "wallet":walletname}
         print("Data: "+str(data))
         requests.post("http://"+Domain+"/addad",json=data)
        else:
         print("Transaction failed with status code:", response.status_code)

       except requests.RequestException as e:
        print("An error occurred:", e)
   elif Mode == 10:
       Coins = int(input("How many coins are you sending to that servercoin wrap system?"))*(10**8)
       Wallet = input("What's the wallet of the servercoin wrap system")
       
       txextra = input("What do you want the txextra to be?")
       transactionfee = 0
       print(private_pem)
       howtogettransactionfee = int(input("1. For manually setting the transactionfee and 2. for this setting it automatically."))
       if howtogettransactionfee == 1:
           transactionfee = float(input("What is the transaction fee you want?"))*(10**8)
       else:
           transactioneefee = 0
           serverlen = len(servers)
           serverip = servers[str(random.randint(0,serverlen-1))]
           responsey = requests.get("http://"+serverip+"/getaveragetransactionfee")
           if responsey.status_code == 200:
               data=responsey.json()
               transactioneefee = int(data["Success"])
               transactionfee = transactioneefee
       url = "http://"+serverip+"/addtransaction"  # Replace 'your_server_address' with the actual server address

# Example data for the transaction
       data = {
        "Sender": walletname,
        "Reciever": Wallet,
        "amountofcoins": Coins,
        "transactionfee": transactionfee,
        "txextra": txextra
       }

# Convert data to JSON format

# Sign the data
       message = str(data["Sender"])+str(data["Reciever"])+str(data["amountofcoins"])+str(data["transactionfee"])+str(data["txextra"])
       message = message.encode('utf-8')
       signature = private_key3333.sign(
         message,
         ec.ECDSA(hashes.SHA256())
       )
       try:
                                     public_key3333333.verify(
                                      signature.encode("utf-8"),
                                      message.encode('utf-8'),
                                      ec.ECDSA(hashes.SHA256())
                                    
                                     )
                                     
       except:
        print("SIGNATURE: "+str(signature))
        print("MESSAGE: "+str(message))
        print("FAILURE")
       print(signature)
# Encode the signature in base64
       encoded_signature = base64.b64encode(signature).decode('utf-8')

# Include the signature in the transaction data
       data["verifyingsig"] = encoded_signature
# Set the URL for the transaction endpoint
       data = {
        "Sender": walletname,
        "Reciever": Wallet,
        "amountofcoins": Coins,
        "transactionfee": transactionfee,
        "txextra": txextra,
        "verifyingsig":encoded_signature
       }
       sender = data["Sender"]
       receiver = data["Reciever"]
       coins = data["amountofcoins"]  # Ensure proper data type for coins
       transactionfee = data["transactionfee"]  # Ensure proper data type for transaction fee
       verifyingsig = base64.b64decode(data["verifyingsig"])
       txextra = data["txextra"]
       print(verifyingsig)
       print("SIGNATURE: "+str(verifyingsig))
       json.dumps(data)
       messagething = str(sender) + str(receiver) + str(coins) + str(transactionfee) + str(txextra)
       messagething = messagething.encode('utf-8')
       print("MESSAGETHING: "+str(messagething))
       well = True
       verifyingkeyloader = ""
# Convert the updated data dictionary to JSON format

# Send the POST request with the transaction data
       try:
        print("DATAHERE: "+str(data))
        response = requests.post(url, json=data)
        if response.status_code == 200:
         print("Transaction successful!")
 
         response = response.json()
         device = response["Success"]
         print("device: "+str(device))
         blocknum = device["Block"]
         transactionid = device["Transactionid"]
         data = {"coins":coins,
                 
                 "transactionid":transactionid,
                 "blocknum":blocknum,
                 "wallet":walletname}
         print("Data: "+str(data))
        else:
         print("Transaction failed with status code:", response.status_code)

       except requests.RequestException as e:
        print("An error occurred:", e)
