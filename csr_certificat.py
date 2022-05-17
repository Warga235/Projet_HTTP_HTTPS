# -*- coding: utf-8 -*-
"""
Created on Mon May 11 07:06:46 2020

@author: Mr ABBAS-TURKI

Binome:
    ABDELAZIZ Hassan 
    OUEIDAT Mohamed
"""


from PKI_utile import generate_csr, generate_private_key
cle_privee_serveur = generate_private_key("serveur-cle-privee.pem", "Pass")

generate_csr(
    
    cle_privee_serveur,
    nomdefichier="serveur_csr.pem",
    country="FR",
    state="Bourgogne Franche-Comte",
    locality="Belfort",
    org= "Societe SA",
    alt_names=["localhost"],
    hostname="mon-site.com",
    )
