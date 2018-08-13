Smartcard Driver Fuzzing Tools
==============================

This is a collection of several tools that help in fuzzing smartcard
drivers for *nix and windows. As usual for such stuff, it is quite
hackish in some parts and more tested in others :-)
If you have questions or need help, email eric.sesterhenn@x41-dsec.de or
read our blogpost at:

https://www.x41-dsec.de/lab/blog/smartcards/

What is in here?
----------------

/OpenSC/

A patch to OpenSC (654ca69c47f98dd6a82b4adc0bb6bb8ead887163) which adds 
another reader driver, that retrieves the APDU responses from an external 
file. This file can be fed with AFL for efficient fuzzing.

/scard_override/

A Linux library you can preload in order to fuzz smartcard applications, 
which use winscard instead of OpenSC.

/scard_win/

A windows library and testcase. The library can be preloaded in front
of your windows smartcard driver. The testcase tries to interact with the
driver. Only rudimentary.

/loadlibrary/

A monkey-patched version of tavisos loadlibrary, which allows to
load certain winscard drivers on linux in order to fuzz them.
