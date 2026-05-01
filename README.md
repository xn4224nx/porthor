# Porthor

This is a Rust module to give access to a range of functions to detect if a linux executable is running in a sandbox.

## Methods

The detection methods include:

1) Check physical characteristics of the host such as RAM, CPU cores, system uptime, BIOS infomation and available storage.

2) Access a non-existant domain and see if it is contactable.

3) Time manipulation using sleep and the network time protocol (NTP).
