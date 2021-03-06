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

__version__ = "1.4.0.1"
__description__ = "REST Client for Cloudbyte Elastistor API"
__project__ = "ElastiStor REST Client"
__projectemail__ = "support@cloudbyte.com"
__projecturl__ = "http://cloudbyte.com"

try:
    import os
    import sys

    from ConfigParser import ConfigParser
    from os.path import expanduser
except ImportError, e:
    print "ImportError", e

param_type = ['boolean', 'date', 'float', 'integer', 'short', 'list',
              'long', 'object', 'map', 'string', 'tzdate', 'uuid']

iterable_type = ['set', 'list', 'object']

# cloudbyte display types
display_types = ["json"]

config_dir = expanduser('~/.cbesclient')
config_file = expanduser(config_dir + '/config')

# ElastiStor REST Client Options
mandatory_sections = ['core']
default_profile_name = 'cloudbyte'
config_fields = {'core': {}}

# core
config_fields['core']['asyncblock'] = 'true'
config_fields['core']['history_file'] = expanduser(config_dir + '/history')
config_fields['core']['log_file'] = expanduser(config_dir + '/log')
config_fields['core']['profile'] = default_profile_name

# default profile
default_profile = {}
default_profile['url'] = 'https://172.16.17.135/client/api'
default_profile['timeout'] = '3600'
default_profile['expires'] = '600'
default_profile['username'] = 'admin'
default_profile['password'] = 'test'
default_profile['domain'] = '/'
default_profile['apikey'] = '1Gj5v66KPAKxbRBPaZjk1eDEw0-NW_lcAyV6cWWRmsX5YlIqJn1OnpmINuQss46h65fh483m9oVmrvnE43T4sg'
default_profile['secretkey'] = 'hIG-GbHd1cmvaOp4pTezdry-BeRiZ1altywGcdRXfTVrxVLN9rdg5H81SbvEx-P79zPy-Fj_5we_0Yt_Xx_2oA'
default_profile['verifysslcert'] = 'false'
default_profile['signatureversion'] = '3'


def write_config(get_attr, config_file):
    global config_fields, mandatory_sections
    global default_profile, default_profile_name
    config = ConfigParser()
    if os.path.exists(config_file):
        try:
            with open(config_file, 'r') as cfg:
                config.readfp(cfg)
        except IOError, e:
            print "Error: config_file not found", e

    profile = None
    try:
        profile = get_attr('profile')
    except AttributeError, e:
        pass
    if profile is None or profile == '':
        profile = default_profile_name
    if profile in mandatory_sections:
        print "Server profile name cannot be '%s'" % profile
        sys.exit(1)

    has_profile_changed = False
    profile_in_use = default_profile_name
    try:
        profile_in_use = config.get('core', 'profile')
    except Exception:
        pass
    if profile_in_use != profile:
        has_profile_changed = True

    for section in (mandatory_sections + [profile]):
        if not config.has_section(section):
            try:
                config.add_section(section)
                if section not in mandatory_sections:
                    for key in default_profile.keys():
                        config.set(section, key, default_profile[key])
                else:
                    for key in config_fields[section].keys():
                        config.set(section, key, config_fields[section][key])
            except ValueError, e:
                print "Server profile name cannot be", profile
                sys.exit(1)
        if section in mandatory_sections:
            section_keys = config_fields[section].keys()
        else:
            section_keys = default_profile.keys()
        for key in section_keys:
            try:
                if not (has_profile_changed and section == profile):
                    config.set(section, key, get_attr(key))
            except Exception:
                pass
    with open(config_file, 'w') as cfg:
        config.write(cfg)
    return config


def read_config(get_attr, set_attr, config_file):
    global config_fields, config_dir, mandatory_sections
    global default_profile, default_profile_name
    if not os.path.exists(config_dir):
        os.makedirs(config_dir)

    config_options = reduce(lambda x, y: x + y, map(lambda x:
                            config_fields[x].keys(), config_fields.keys()))
    config_options += default_profile.keys()

    config = ConfigParser()
    if os.path.exists(config_file):
        try:
            with open(config_file, 'r') as cfg:
                config.readfp(cfg)
        except IOError, e:
            print "Error: config_file not found", e
    else:
        config = write_config(get_attr, config_file)

    missing_keys = []
    if config.has_option('core', 'profile'):
        profile = config.get('core', 'profile')
    else:
        global default_profile_name
        profile = default_profile_name

    if profile is None or profile == '' or profile in mandatory_sections:
        print "Server profile cannot be", profile
        sys.exit(1)

    set_attr("profile_names", filter(lambda x: x != "core" and x != "ui",
                                     config.sections()))

    if not config.has_section(profile):
        print ("Selected profile (%s) does not exist," +
               " using default values") % profile
        try:
            config.add_section(profile)
        except ValueError, e:
            print "Server profile name cannot be", profile
            sys.exit(1)
        for key in default_profile.keys():
            config.set(profile, key, default_profile[key])

    for section in (mandatory_sections + [profile]):
        if section in mandatory_sections:
            section_keys = config_fields[section].keys()
        else:
            section_keys = default_profile.keys()
        for key in section_keys:
            try:
                set_attr(key, config.get(section, key))
            except Exception, e:
                if section in mandatory_sections:
                    set_attr(key, config_fields[section][key])
                else:
                    set_attr(key, default_profile[key])
                missing_keys.append("%s = %s" % (key, get_attr(key)))
            # Cosmetic fix for prompt
            if key == 'prompt':
                set_attr(key, get_attr('prompt').strip() + " ")

    if len(missing_keys) > 0:
        print "Missing configuration was set using default values for keys:"
        print "`%s` in %s" % (', '.join(missing_keys), config_file)
        write_config(get_attr, config_file)

    return config_options
