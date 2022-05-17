# -*- coding: utf-8 -*-
"""
Created on Wed May  6 12:46:22 2020

@author: Mr ABBAS-TURKI

Binome:
    ABDELAZIZ Hassan 
    OUEIDAT Mohamed
"""

from flask import Flask
# définir le message secret
MESSAGE_SECRET="le message secert que je vous envoies"
app=Flask(__name__)
@app.route("/")

def get_secret_message():
    return MESSAGE_SECRET

if __name__=="__main__":
    app.run(
            debug=True, 
            host="0.0.0.0",
            port=8081, 
            ssl_context=('serveur-cle-publique.pem','serveur-cle-privee.pem')
            )