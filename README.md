# Dmonitor
Wifi Deauthentication & Disassociation monitor

Description
----
This script is based on ideas from several scripts I have seen doing this, but with added functions I wanted a critical addition most mis out... and written in a way that I understand :)

I have included Disassociation packets, which most scripts of this kind mis out – although less used, disassociation is still an effective Wifi DoS attack.

I have added ‘store=0’ to the Scapy sniffing routine, which almost every script I have seen misses out! Without this (or some clean up) these scripts will soon grind your system to a halt – it happens very quickly on a Raspberry Pi3.

Converted to Python 3 - 19 April 2020

Usage
----
Scan for wifi APs: ./dmonitor.py -i wlan0<br/>
Monitor wifi AP: ./dmonitor.py -i wlan0 -d sample.csv -e WifiAP<br/>


Python3 version: <br/>
Scan for wifi APs: ./dmonitor3.py -i wlan0<br/>
Monitor wifi AP: ./dmonitor3.py -i wlan0 -d sample.csv -e WifiAP<br/>


-d is optional in both cases


Requirements
----
It requires the Scapy Python module and Aircrack suite (to do switch the Wifi adapter on/off monitor mode). It runs best from Kali.
