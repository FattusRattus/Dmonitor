#!/usr/bin/python

import signal
import sys
import csv
import os
import optparse
import datetime

from scapy.all import *


# Define subs
# -----------

# Close cleanly on Ctrl+C
def signal_handler(sig, frame):
   print('You pressed Ctrl+C! Exiting...')
   os.system("airmon-ng stop " + wifi_interface + "  >/dev/null 2>&1")
   os.system("ifconfig " + options.interface + " down ; ifconfig " + options.interface + " up >/dev/null 2>&1")
   sys.exit(0)

# Print at location on screen
def print_at(x, y, text):
   sys.stdout.write("\x1b7\x1b[%d;%df%s\x1b8" % (y, x, text))
   sys.stdout.flush()

# Wifi sniffing routine
def wifisniff(pk):
   if pk.haslayer(Dot11Deauth) | pk.haslayer(Dot11Disas):
      if str.upper(ap_bssid) in [str.upper(pk.addr2), str.upper(pk.addr1)]:
         if pk.haslayer(Dot11Deauth):
            dmethod = 'A'
         if pk.haslayer(Dot11Disas):
            dmethod = 'S'

         if str([pk.addr2, pk.addr1, dmethod]) in database.keys():
            database[str([pk.addr2, pk.addr1, dmethod])]=database[str([pk.addr2, pk.addr1, dmethod])]+1
         else:
            database[str([pk.addr2, pk.addr1, dmethod])]=1
            # Below is my hard coded line to play WAV on each new detection
            #os.system('cvlc --play-and-exit /root/bin/avon.wav >/dev/null 2>&1 &')

         # Check if using database and swap names with BSSID's, truncate were needed
         line = 0
         for x,p in database.iteritems():
            wifi1, wifi2, d = eval(x)
            wifi1 = str.upper(wifi1)
            wifi2 = str.upper(wifi2)
            if ap_lines != 0:
               if ap_bssid == wifi1:
                  wifi1 = "{:<17}".format(options.essid)[:17]
               if ap_bssid == wifi2:
                  wifi2 = "{:<17}".format(options.essid)[:17]
               for ap in range(0, ap_lines):
                  if str.upper(ap_list[ap][1]) == wifi1:
                     wifi1 = "{:<17}".format(ap_list[ap][0])[:17]
                  if str.upper(ap_list[ap][1]) == wifi2:
                     wifi2 = "{:<17}".format(ap_list[ap][0])[:17]
            
            print_at( 3, line + 8, ("Deauthentication" if d == 'A' else "# Disassociation") + " Packet: " + wifi1 + " <--> " + wifi2 + " - Packets : " + str(p) + "     ")
            line+=1


# Main Code
# ---------

# Ensure wifi reg is set to GB
os.system("iw reg set GB")

# Get command line inputs
parser = optparse.OptionParser("\nusage ./dmonitor.py " + "-i <interface> [-e <ESSID>] [-d <APs database.]" + "\nRequires wifi interface in monitor mode.\n")
parser.add_option('-i', dest='interface', type='string', help='specify minitor interface, i.e. wlan0mon')
parser.add_option('-d', dest='apdb', type='string', default = "", help='specify APs database (CSV format)')
parser.add_option('-e', dest='essid', type='string', help='specify AP (ESSID)')

(options, args) = parser.parse_args()

if (options.interface == None) | (options.essid == None):
   print parser.usage
   if (options.interface != None):
      os.system("ifconfig " + options.interface + " down")
      os.system("ifconfig " + options.interface + " up")
      print "\nList of available APs:"
      list_aps = "iwlist " + options.interface + " scan | grep ESSID | sed 's/ESSID//g' | sed 's/ //g' | sed 's/\://g' | sed 's/\"//g'"
      os.system(list_aps)
      print " "
   exit(0)


# Check wifi AP exists
ap_essid = os.popen("iwlist " + options.interface + " scan | grep -B 5 -w " + options.essid + " | grep ESSID: | sed s/ESSID://g | sed s/^' '*//g | uniq | tr -d '\n'").read()

if ap_essid.replace('"', '') != options.essid:
   print "Unable to find wifi AP!\n"
   exit()


# Get BSSID from ESSID
ap_bssid = os.popen("iwlist " + options.interface + " scan | grep -B 5 -w " + options.essid + " | grep Address:  | head -1 | sed s/'Cell [0-9][0-9] - Address:'// | sed s/[^0-9:A-Z]*//g | tr -d '\n'").read()

if ap_bssid == "":
   print " Error with acquiring AP BSSID!\n"
   exit()


# Get channel of ESSID
ap_channel = os.popen("iwlist " + options.interface + " scan | grep -B 5 -w " + options.essid + " | grep Channel: | head -1 | sed s/Channel:// | sed s/[^0-9]*//g | tr -d '\n'").read()

if ap_channel == "":
   print " Error with acquiring AP channel!\n"
   exit()


# Set wifi channel
os.system("iwconfig " + options.interface + " channel " + str(ap_channel))


# Load AP database
ap_lines = 0

if options.apdb != "":
   with open(options.apdb, 'rb') as apfile:
      reader = csv.reader(apfile)
      ap_list = list(reader)

   ap_lines = sum(1 for line in ap_list)


# set wifi interface into promisc mode
os.system("airmon-ng start " + options.interface + "  >/dev/null 2>&1")
wifi_interface = options.interface + "mon"


# Wifi Sniffing
os.system('clear')
print "Deathentication & Disassociation Monitor"
print "========================================"
print "ESSID     : " + options.essid
print "BSSID     : " + ap_bssid
print "Channel   : " + ap_channel
print "Interface : " + wifi_interface

pk_count = 1
database = {}

signal.signal(signal.SIGINT, signal_handler)

sniff(iface=wifi_interface, prn=wifisniff, store=0)
