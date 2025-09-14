# TemplateInjection-POC

This artifact contains PoC scripts and demo samples for Section 5.1 of our paper. Our attack accesses the victim's device and performs authentication using the attacker's sensor.
The entire attack requires physical access to the device, so it cannot be executed by code alone.

The PoC script includes the part that creates an attacker's template — which is accepted by the victim's system — from data extracted from the victim's partition as described in the paper.

In the actual attack we booted the victim device into a other bootable OS (ex. Windows PE)  and carried out that process, but for review purposes we assume certain files were already extracted and implemented the subsequent steps in code.

Our code takes the following files as input (an example is provided in the example folder)
- WinBioDB from \Windows\System32\WinBioDatabase
- DPAPI master key from \Windows\System32\Microsoft\Protect\S-1-5-18\User\~
- SYSTEM, SECURITY, SOFTWARE hive files from Windows\System32\config

The victim's WinBioDB is not mandatory.

Demo video: https://youtu.be/wmDJAhCoTO0
