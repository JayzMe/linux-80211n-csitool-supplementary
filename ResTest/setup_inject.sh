#!/usr/bin/sudo /bin/bash
modprobe -r iwlwifi mac80211 cfg80211
modprobe iwlwifi debug=0x40000
ifconfig wlan1 2>/dev/null 1>/dev/null
while [ $? -ne 0 ]
do
	        ifconfig wlan1 2>/dev/null 1>/dev/null
done
iw dev wlan1 interface add mon0 type monitor
iw mon0 set channel $1 $2
ifconfig mon0 up
