# rcDetectVirtual
#######################################################################

Red Crow Labs

#######################################################################

DESCRIPTION:

rcDetectVirtual is PoC Code to detect if it is running in a virtual machine. This code only works on linux but could be modified to work on windows as well.

=========================================================================

INSTALL: 

git clone https://github.com/redcrowlab/rcDetectVirtual.git

gcc -o rcDetectVirtual rcDetectVirtual.c


=========================================================================

USAGE: 

./rcDetectVirtual


=========================================================================

NOTE:

This code is prone to false positives. You may need to run it multiple times to get an accurate picture.
