#!/bin/bash
python3.10 -m pip install --user pipenv
cd src/client
pipenv install
cd ../server
pipenv install
