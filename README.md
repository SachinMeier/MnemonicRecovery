# Mnemonic Phrase Recovery

This is a script for attempting to recover a BIP32 wallet from a partial mnemonic seed. There's no guarantee that it will find your seed. 

For now, it only works with P2PKH addresses derived from path m/44'/0'/0'/. I will work on making this more flexible and adding other script types. 

### Warning

The script has no networking components, so I am unable to view/steal your seed at any point. However, you should still run this script offline in case your computer is insecure. 

## Dependencies

The only dependency is '''bitarray''', a python library which can be installed with pip. 

## Install and Use

'''bash

# get source code
git clone git@github.com:SachinMeier/MnemonicRecovery.git
cd MnemonicRecovery

# setup virtual environment
python3 -m venv . 

# install bitarray
pip3 install bitarray

# run script
python3 src/brute-force.py
'''

The script will prompt the user to enter their words, select a gap limit, and enter any known addresses. 