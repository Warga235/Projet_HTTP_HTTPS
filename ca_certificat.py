# -*- coding: utf-8 -*-
"""
Created on Mon May 11 06:57:17 2020

@author: Mr ABBAS-TURKI

Binome:
    ABDELAZIZ Hassan 
    OUEIDAT Mohamed
"""

from PKI_utile import generate_private_key, generate_public_key
private_key = generate_private_key("ca-cle-privee.pem" ,"security")

generate_public_key( 
    
    private_key,
    nomdefichier="ca-cle-publique.pem",
    country="FR",
    state="Bourgogne Franche-Comte",
    locality="Belfort",
    org= "Societe SA",
    alt_names=["localhost"],
    hostname="mon-ca.com",
    )