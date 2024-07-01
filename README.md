# inside_pe
This tool allows you to take a glance at the properties of a pe file 

Features

PE Sections Analysis: Displays information about each section in the PE file, including name, virtual address, size of raw data, characteristics, and entropy.
Imported Libraries and Functions: Lists imported libraries and their associated functions within the PE file.

Requirements

Python 3.x
pefile library: Install with pip install pefile
scipy library: Install with pip install scipy

Run the script:
Replace pe_file.exe with the path to the PE file you want to analyze.

  python inside_pe.py pe_file.exe
