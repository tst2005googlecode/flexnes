The introduction of Network Address Translation (NAT) devices into the Internet, while serving many important functions, has added complexity and variability to the behavior of networks. Testing network applications to behave properly when using NAT devices with different behaviors is a challenge for developers. This project aims to develop a tool which can be used by developers to easily emulate the behaviors present in NAT devices in a simple, user-mode application.

This project is the offshoot of my Masters project at the College of William and Mary.  More information on that can be found at the original project link to the right.

In its current form, the project only handles UDP data, but it has been designed to be expandable to cover other protocols.  The code requires the use of iptables to intercept packets and is therefore limited to Linux.
