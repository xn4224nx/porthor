# Porthor

This is a Rust module to give access to a range of functions to detect if a linux executable is running in a sandbox.

## Methods

The detection methods include:

1) Check physical characteristics of the host such as RAM, CPU cores, system uptime, BIOS infomation and available storage.

2) Access a non-existant domain and see if it is contactable.

3) Time manipulation using sleep and the network time protocol (NTP).

## Development Plan

1) Fix `is_sleep_valid()` to ensure the output is only between 0.0 and 1.0.
   
2) Write the function `news_site_date_check()`.

3) Write a function to combine all the detection methods and give a boolean.

4) Write a function to give a visual display of the various detection methods.

5) Write a function to read mouse movement and keyboard presses.

6) Examine running processes.

7) Detect the card designer via MAC address.

8) Use the CPUID instruction.

9) Thread the various checks to speed them up.

10) Use Check DMI data (Desktop Management Interface)

11) Check the screen resolution.

12) Check for installed programs.

13) Check for a busy file system indicating user activity.
