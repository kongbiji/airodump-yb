# airodump-yb
My airodump-ng program.

The wireless LAN packet is captured to the monitor mode. The statistics for station and AP is outputted.

# Environment
Only Linux

# How to use
1. Enable Monitor mode
- This must require a chipset or adapter that supports monitor mode.
```
sudo ifconfig <wlan interface> down
sudo iwconfig <wlan interface> mode monitor
sudo ifconfig <wlan interface> up
```
2. Download source code and build
```
git clone https://github.com/kongbiji/airodump-yb
cd airodump-yb
make
sudo ./airodump-yb <wlan interface>
```

# TODO
Smooth output is required...
