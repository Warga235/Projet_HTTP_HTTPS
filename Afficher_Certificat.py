# -*- coding: utf-8 -*-
"""
Created on Thu May 14 15:59:55 2020

@author: Mr ABBAS-TURKI

Binome:
    ABDELAZIZ Hassan 
    OUEIDAT Mohamed
"""


import sys
import os
import ssl
from pprint import pprint as pp


def main():
    cert_file_name = os.path.join(os.path.dirname(__file__), "serveur-cle-publique.pem")
    try:
        cert_dict = ssl._ssl._test_decode_cert(cert_file_name)
        pp(cert_dict)

    except Exception as e:
        print("Error decoding certificate: {:}".format(e))


if __name__ == "__main__":
    print("Python {:s} on {:s}\n".format(sys.version, sys.platform))
    main()