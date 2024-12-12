This add-on sniffs DHCP packets from the network and looks for configured MAC addresses. 

If an address is matched, an event is raised on the HA event bus and, optionally, a device tracker can be updated.
Also, this add-on will ping the IP addresses when a MAC is matched and when the ping fails, an event will be raised / optional device tracker updated.

This add-on was developed for detecting Blink cameras and rapidly refreshing their state based on the events generated.
It is more generally useful for detecting devices with known MAC addresses.