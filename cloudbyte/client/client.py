#!/usr/bin/python
# -*- coding: utf-8 -*-
# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
#
#
# The code is forked from Apache CloudStack CloudMonkey
# https://github.com/apache/cloudstack-cloudmonkey
#
#

try:
    import argcomplete
    import csv
    import copy
    import shlex
    import types
    import argparse
    import atexit
    import cmd
    import json
    import logging
    import os
    import sys
    import time
    import requests
    import md5
    import datetime

    from config import __version__, __description__, __projecturl__
    from config import display_types
    from config import read_config, write_config, config_file, default_profile
    from requester import ecrequest
    from urlparse import urlparse
    from xml.dom.minidom import parseString
except ImportError, e:
    print("Import error in %s : %s" % (__name__, e))
    import sys
    sys.exit()

log_fmt = '%(asctime)s - %(filename)s:%(lineno)s - [%(levelname)s] %(message)s'
logger = logging.getLogger(__name__)


class ECClient():
    config_options = []
    profile_names = []
    verbs = []
    error_on_last_command = False
    protocol = "https"
    host = "localhost"
    port = "443"
    path = "/client/api"

    def __init__(self, pname, cfile):
        self.program_name = pname
        self.config_file = cfile
        self.config_options = read_config(self.get_attr, self.set_attr,
                                          self.config_file)
        self.init_credential_store()
        logging.basicConfig(filename=self.log_file,
                            level=logging.DEBUG, format=log_fmt)
        logger.debug("Loaded config fields:\n%s" % map(lambda x: "%s=%s" %
                                                       (x, getattr(self, x)),
                                                       self.config_options))

    def get_attr(self, field):
        return getattr(self, field)

    def set_attr(self, field, value):
        return setattr(self, field, value)

    def init_credential_store(self):
        self.credentials = {'apikey': self.apikey, 'secretkey': self.secretkey,
                            'domain': self.domain, 'username': self.username,
                            'signatureversion': self.signatureversion}
        parsed_url = urlparse(self.url)
        self.protocol = "https" if not parsed_url.scheme else parsed_url.scheme
        self.host = parsed_url.netloc
        self.port = "443" if not parsed_url.port else parsed_url.port
        self.path = parsed_url.path

    def make_apirequest(self, command, args={}, isasync=False):
        self.error_on_last_command = False
        response, error = ecrequest(command, args, isasync,
                                        self.asyncblock, logger,
                                        self.url, self.credentials,
                                        self.timeout, self.expires,
                                        self.verifysslcert == 'true',
                                        self.signatureversion)
        if error:
            self.clientprint(u"Error {0}".format(error))
            self.error_on_last_command = True
        return response

    def make_cmdrequest(self, command, args={}, isasync=False):
        self.error_on_last_command = False
        response, error = ecrequest(command, args, isasync,
                                        self.asyncblock, logger,
                                        self.url, self.credentials,
                                        self.timeout, self.expires,
                                        self.verifysslcert == 'true',
                                        self.signatureversion)
        if error:
            self.clientprint(u"Error {0}".format(error))
            self.error_on_last_command = True
        else:
            self.print_result( response )

        return response

    def print_result(self, result, result_filter=[]):
        if not result or len(result) == 0:
            return

        filtered_result = copy.deepcopy(result)
        if result_filter and isinstance(result_filter, list) \
                and len(result_filter) > 0:
            tfilter = {}  # temp var to hold a dict of the filters
            tresult = filtered_result  # dupe the result to filter
            if result_filter:
                for res in result_filter:
                    tfilter[res] = 1
                for okey, oval in result.iteritems():
                    if isinstance(oval, dict):
                        for tkey in oval:
                            if tkey not in tfilter:
                                try:
                                    del(tresult[okey][oval][tkey])
                                except:
                                    pass
                    elif isinstance(oval, list):
                        for x in range(len(oval)):
                            if isinstance(oval[x], dict):
                                for tkey in oval[x]:
                                    if tkey not in tfilter:
                                        try:
                                            del(tresult[okey][x][tkey])
                                        except:
                                            pass
                            else:
                                try:
                                    del(tresult[okey][x])
                                except:
                                    pass
            filtered_result = tresult

        def print_result_json(result):
            self.clientprint(json.dumps(result,
                                        sort_keys=True,
                                        indent=2,
                                        ensure_ascii=False,
                                        separators=(',', ': ')))

        print_result_json(filtered_result)

    def clientprint(self, *args):
        output = u""
        try:
            for arg in args:
                if isinstance(type(arg), types.NoneType) or not arg:
                    continue
                if not (isinstance(arg, str) or isinstance(arg, unicode)):
                    arg = unicode(arg)
                output += arg
        except Exception, e:
            print(str(e))

        output = output.encode("utf-8")
        if output.startswith("Error"):
            sys.stderr.write(output + "\n")
            sys.stderr.flush()
        else:
            print output

def main():
    parser = argparse.ArgumentParser(usage="cloudbyte/client/client [options] [commands]",
                                     description=__description__,
                                     epilog="Try cloudbyte/client/client [help|?]")

    parser.add_argument("-v", "--version", action="version",
                        default=argparse.SUPPRESS,
                        version="ecc %s" % __version__,
                        help="show client version and exit")

    parser.add_argument("-c", "--config-file",
                        dest="configFile", default=config_file,
                        help="config file for elasticenter client", metavar="FILE")

    parser.add_argument("-b", "--block-async", action="store_true",
                        help="block and poll result on async API calls")

    parser.add_argument("-n", "--noblock-async", action="store_true",
                        help="do not block on async API calls")

    parser.add_argument("commands", nargs=argparse.REMAINDER,
                        help="API commands")

    argcomplete.autocomplete(parser)
    args = parser.parse_args()

    clientsession = ECClient(sys.argv[0], args.configFile)

    if args.noblock_async:
        clientsession.set_attr("asyncblock", "false")

    if args.block_async:
        clientsession.set_attr("asyncblock", "true")

    if len(args.commands) > 0:
        commandArgs = {}
        commandName = ""
        for command in args.commands:
            split_command = command.split("=", 1)
            if len(split_command) > 1:
                key = split_command[0]
                value = split_command[1]
                if " " not in value or \
                   (value.startswith("\"") and value.endswith("\"")) or \
                   (value.startswith("\'") and value.endswith("\'")):
                    commandArgs[key] = value
                else:
                    commandArgs[key] = value
            else:
                commandName = command
        clientsession.make_cmdrequest( commandName, commandArgs )
        if clientsession.error_on_last_command:
            sys.exit(1)

    try:
        sys.stdout.close()
    except:
        pass
    try:
        sys.stderr.close()
    except:
        pass

if __name__ == "__main__":
    main()
