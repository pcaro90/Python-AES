Python-AES
==========

This scripts implements the Advanced Encryption Standard (AES) algorithm, as
defined in FIPS-197; and using PKCS#7 padding. A basic demonstration based on
the example vectors found in the Appendix C of the FIPS-197 publication is
included. Python 2 and Python 3 compatible.

This script is using "AES_base.py", a module containing the neccesary tables
used in the algorithm: S-Box and inverted S-Box for SubBytes and InvSubBytes
transformations, lookup tables for Galois Field product x2, x3, x9, x11, x13,
x14 used in MixColumns and InvMixColumns, and Rcon used in KeyExpansion. In
order to see how this tables are generated, check
[Python-AES-base](https://github.com/pcaro90/Python-AES-base/)

This code is only intended for educational and recreational purposes, and
should not be used in secure systems.

Usage
-----

    python AES.py -demo
    python AES.py (-e | -d) <file> [-c (128|192|256)]
        -e: Encript
        -d: Decript
        -c <n>: <n> bits key (default 128)
    Note: a function mode (-e/-d) has to be specified.

License
-------

Copyright (c) 2013 Pablo Caro. All Rights Reserved.

Pablo Caro <<me@pcaro.es>> - <http://pcaro.es/>

See LICENSE file
