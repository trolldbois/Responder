NBT-NS/LLMNR Responder
Laurent Gaffie <lgaffie@trustwave.com>
http://www.spiderlabs.com

INTRODUCTION
============

This tool is first an LLMNR and NBT-NS responder, it will answer to 
*specific* NBT-NS (NetBIOS Name Service) queries based on their name 
suffix (see: http://support.microsoft.com/kb/163409). By default, the
tool will only answers to File Server Service request, which is for SMB.
The concept behind this, is to target our answers, and be stealthier on
the network. This also helps to ensure that we don't break legitimate
NBT-NS behavior.
You can set the -r option to 1 via command line if you want this tool to
answer to the Workstation Service request name suffix.

FEATURES
========

- Built-in SMB Auth server.
  Supports NTLMv1, NTLMv2 hashes. Successfully tested from Windows NT4
  to Server 2012 RC, Samba and Mac OSX Lion. This functionality is enabled
  by default when the tool is launched.

- Built-in MSSQL Auth server.
  In order to redirect SQL Authentication to this tool, you will need to
  set the option -r to 1(NBT-NS queries for SQL Server lookup are
  using the Workstation Service name suffix) for systems older than
  windows Vista (LLMNR will be used for Vista and higher). This server
  supports NTLMv1, LMv2 hashes. This functionality was successfully tested
  on Windows SQL Server 2005 & 2008.

- Built-in HTTP Auth server.
  In order to redirect HTTP Authentication to this tool, you will need
  to set the option -r to 1 for Windows version older than Vista (NBT-NS
  queries for HTTP server lookup are sent using the Workstation Service
  name suffix). For Vista and higher, LLMNR will be used. This server 
  supports NTLMv1, NTLMv2 hashes *and* Basic Authentication. This server
  was successfully tested on IE 6 to IE 10, Firefox, Chrome, Safari.
  Note: This module also works for WebDav NTLM authentication issued from
  Windows WebDav clients (WebClient).

- All hashes are printed to stdout and dumped in an unique file John
  Jumbo compliant, using this format:
  (SMB or MSSQL or HTTP)-(ntlm-v1 or v2 or clear-text)-Client_IP.txt
  The file will be located in the current folder.

- Responder will logs all its activity to a file Responder-Session.log.

- When the option -f is set to "On", Responder will fingerprint every host who issued an LLMNR/NBT-NS query.
  All capture modules still work while in fingerprint mode. 


CONSIDERATIONS
==============

- This tool listen on several port: UDP 137, TCP 1433,
  TCP 80, TCP 139, TCP 445, Multicast UDP 5553.
  If you run Samba on your system, stop smbd and nmbd and all other 
  services listening on these ports.

- This tool will *not* work on Windows by default.


USAGE
=====

Running this tool:

- python Responder.py [options]

Usage Example:

python Responder.py -i 10.20.30.40 -b 1 -s On -r 0 -f On

Options List:

-h, --help                           show this help message and exit.

-d PDC01, --domain=PDC01             The target domain name, if not set,
                                     this tool will use WORKGROUP by default.

-i 10.20.30.40, --ip=10.20.30.40     The ip address to redirect the traffic to.
                                     (usually yours)

-b 0, --basic=0                      Set this to 1 if you want to return a 
                                     Basic HTTP authentication. 0 will return 
                                     an NTLM authentication.

-s Off, --http=Off                   Set this to On or Off to start/stop the
                                     HTTP server. Default value is On.

-S Off, --smb=Off                    Set this to On or Off to start/stop the
                                     SMB server. Default value is On.

-q Off, --sql=Off                    Set this to On or Off to start/stop the
                                     SQL server. Default value is On.

-r 0, --wredir=0                     Set this to enable answers for netbios 
                                     wredir suffix queries. Answering to wredir
                                     will likely break stuff on the network 
                                     (like classics 'nbns spoofer' will).
                                     Default value is therefore set to Off (0).

-c 1122334455667788, --challenge=    The server challenge to set for NTLM
                                     authentication. If not set, then defaults
                                     to 1122334455667788, the most common
                                     challenge for existing Rainbow Tables.

-l file.log, --logfile=filename.log  Log file to use for Responder session.

-f Off, --fingerprint=Off            This option allows you to fingerprint a 
                                     host that issued an NBT-NS or LLMNR query.

For more information read this post: 
http://blog.spiderlabs.com/2012/10/introducing-responder-10.html


COPYRIGHT
=========

NBT-NS/LLMNR Responder
Created by Laurent Gaffie
Copyright (C) 2012 Trustwave Holdings, Inc.
 
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.
 
You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>
