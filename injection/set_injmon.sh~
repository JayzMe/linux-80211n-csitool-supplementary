#!/usr/bin/sudo /bin/bash
sleep 1
modprobe -r iwlwifi mac80211 cfg80211
modprobe iwlwifi connector_log=0x5 debug=0x40000
echo "step 1---------------"

# Setup monitor mode, loop until it works
iwconfig wlan0 mode monitor 2>/dev/null 1>/dev/null
while [ $? -ne 0 ]
do
    iwconfig wlan0 mode monitor 2>/dev/null 1>/dev/null
done
sleep 1
echo "monitor mode successfully set"

ifconfig wlan0 up
sleep 1
echo "open wlan0"

iw wlan0 set channel $1 $2
sleep 1
echo "setting wlan channel parameters"

echo "successfully--------------------------"
