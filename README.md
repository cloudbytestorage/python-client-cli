# python-client-cli

Python Client/CLI for CloudByte ElastiStor 

### Setup

- Copy the eccclient folder to a linux machine where python is installed.
- Install the following dependency packages

```bash

 wget https://bootstrap.pypa.io/get-pip.py
 python get-pip.py
 pip install argcomplete
 pip install requests
 pip install requests_toolbelt
```

- Generate a sample config file by running following commands.

```bash

 cd <folder where eccclient is copied>/eccclient
 python cloudbyte/client/client -h
```

- Modify the config file ~/.cbesclient/config with your ElastiCenter credentials

