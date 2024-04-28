#!/bin/bash

#python3 -m venv venv
#venv/bin/pip install --upgrade pip
#venv/bin/pip install -r requirements.txt
#source /venv/bin/activate
python3 -m venv venv
venv/bin/pip install --upgrade pip
venv/bin/pip install -r requirements.txt
source venv/bin/activate
python3 main.py --mempool=mempool > output.txt
