# python-client-cli
Python Client/CLI for CloudByte ElastiStor 

Setup
(a) Copy the eccclient folder to a linux machine where python is installed.
(b) Install the following dependency packages
    - wget https://bootstrap.pypa.io/get-pip.py
    - python get-pip.py
    - pip install argcomplete
    - pip install requests
    - pip install requests_toolbelt
(c) Generate a sample config file by running following commands.
    cd <folder where eccclient is copied>/eccclient
    python cloudbyte/client/client -h
(d) Modify the config file ~/.cbesclient/config with your ElastiCenter credentials

