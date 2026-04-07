# Porthor

This is a Rust module to give access to a range of functions to detect if a linux executable is running in a sandbox.

## Methods

The detection methods include:

1) Check physical characteristics of the host such as RAM, CPU cores, system uptime, BIOS infomation and available storage.

2) Inspect the running processes for tell a tale virtualisation processes.

3) Analysisng human input such as mouse movement and keyboard presses.

4) Access a non-existant domain and see if it is contactable.

5) Measure how many CPU cycles take place between two points in the code. This is known as the read time stamp counter (RDTSC).

6) Pocket litter checks such as command history, documents and non-stardard programs installed.

7) Time manipulation using sleep and the network time protocol (NTP).
