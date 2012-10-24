NBT-NS/LLMNR Responder
Laurent Gaffie <lgaffie@trustwave.com>
http://www.spiderlabs.com

INTRODUCTION
============

This tool is first an LLMNR and NBT-NS responder.  This tool
answers to *specific* NBT-NS queries based on their name suffix
(see: http://support.microsoft.com/kb/163409).  By default, this tool
only answers to File Server Service request, which is for SMB. The
concept of this is to target our answers, and be more stealthy on
the network. This also helps ensure that we don't break legitimate
NBT-NS behavior.

You can set the -r option to 1 if you want this tool to answer to
Workstation Service request.

FEATURES
========

- Built-in SMB Auth server.
  Supports NTLMv1, NTLMv2 hash.  Successfully tested on Windows from NT4
  to Server 2012 RC, Samba, Mac OSX Lion.  This functionality is enabled
  by default.

- Built-in MSSQL Auth server.
  In order to redirect SQL Authentication to this tool, you will need to
  set the option -r to 1.  (NBT-NS queries for SQL Server lookup are
  sent using the Workstation Service name suffix.) Supports NTLMv1, LMv2
  hash.  Successfully tested on Windows SQL Server 2005 & 2008.

- Built-in HTTP Auth server.
  In order to redirect HTTP Authentication to this tool, you will need
  to set the option -r to 1.  For Windows version equal to or higher
  than Vista, there is no need to set -r option since they will use
  LLMNR before NBT-NS.  (NBT-NS queries for HTTP server lookup are sent
  using the Workstation Service name suffix.) Supports NTLMv1, LMv2
  hash and Basic Authentication.  Successfully tested on Windows SQL
  Server 2005 & 2008.

- All hashes are printed to stdout and dumped in an unique file John
  Jumbo compliant, using this format:
  
  (SMB or MSSQL or HTTP)-(ntlm-v1 or v2 or clear-text)-Client_IP.txt

  The file will be located in the current folder.

CONSIDERATIONS
==============

- This tool listen on several port: UDP 137, TCP 1433,
  TCP 80, TCP 139, TCP 445, Multicast UDP 5553.
  
  If you run Samba on your system, stop smbd and nmbd.

- This tool will *not* work on Windows by default.

- Please note that if you don't use rainbow tables to crack the hashes,
  you *better* change these 2 vars accordingly in Responder.py

  line 47: " # Change this if needed. Currently using the same
             challenge as Metasploit since several rainbow tables were
             created with that challenge.
             Challenge = "\x11\x22\x33\x44\x55\x66\x77\x88"
             NumChal = "1122334455667788" "
 
  Apparently, since a recent update Windows doesn't send the valild SMB
  NTLMv1 credentials when the fixed challenge 1122334455667788 is set.


USAGE
=====

Running this tool:

- python Responder.py [options]

Example:

python Responder.py -d PDC01 -i 10.20.30.40 -b 1 -s On -r 0

If you're not joined to a domain, use:

python Responder.py -d WORKGROUP -i 10.20.30.40



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
