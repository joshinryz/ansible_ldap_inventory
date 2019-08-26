## Ansible ldap inventory script 
## Author: Joshua Robinett (jshinryz)
## This script accesses ldap and queries for a list of machines.

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = '''
     name: ldap_inventory
     plugin_type: inventory
     short_description: LDAP inventory source
     extends_documentation_fragment:
        - inventory_cache
        - constructed
     description:
        - Recursively get inventory from LDAP organizational unit. Creates both hosts and groups from LDAP
        - Create a YAML config file , it's name must end with ldap_inventory.yml or ldap_inventory.yaml.
        - The inventory_hostname is always the 'Name' of the computer object in lowercase. 
     options:
         plugin:
             description: "token that ensures this is a source file for the 'ldap_inventory' plugin"
             required: True
             choices: ['ldap_inventory']
         online_only:
             description: "toggles showing all computer objects vs only machines that can be ICMP pinged"
             type: boolean
         ldap_lastLogontimeStamp_age:
             description: "ldap attribute filter for the last logon timestamp field. This value is generally updated every 14 days. Timestamps older indicate inactive computer accounts. Setting to 0 does causes this to not be checked (default)"
             default: 0
             required: False
         ldap_host:
             description: "ldap connection string for destination server (ldap or ldaps for ssl). Example: ldaps://local.com:636"
             required: True
         ldap_search_ou:
             description: "ldap path to search for computer objects. Example: CN=Computers,DC=local,DC=com"
             required: True
         ldap_bind_dn:
             description: "ldap user account used to bind our ldap search. Example: username@local.com"
             required: True
         ldap_bind_pw:
             description: "ldap user password used to bind our ldap search. Example: Password123!"
             required: True
         ldap_filter:
             description: "filter used to find computer objects. Example: (objectClass=computer)"
             required: False
             default: "(objectClass=Computer)"
         ldap_exclude_groups:
             description: "List of groups to not include. Example: windows_servers,sql_servers"
             required: False
             default: ""
             type: list
         ldap_exclude_hosts: 
             description: "List of computers to not include. Example: host01,host02"
             required: False
             default: ""
             type: list
         validate_certs:
             description: "Controls if verfication is done of SSL certificates for secure (ldaps://) connections."
             default: True
             required: False
         use_fqdn:
             description: "Controls if the hostname is fqdn or shortname"
             default: False
             required: False
             type: bool
'''

EXAMPLES = '''
# Sample configuration file for LDAP dynamic inventory
    plugin: ldap_inventory
    ldap_host: "ldaps://ldapserver.local.com:636"
    ldap_search_ou: "CN=Computers, DC=local, DC=com"
    ldap_bind_dn: username@local.com
    ldap_bind_pw: Password123!
    online_only: True
'''

import os
import re
import subprocess
import multiprocessing
from datetime import datetime, timedelta
try :
    import ldap
    HAS_LDAP = True
except ImportError:
    HAS_LDAP = False

from ansible.plugins.inventory import BaseInventoryPlugin, Constructable
from ansible.utils.display import Display

display = Display()

try:
    cpus = multiprocessing.cpu_count()
except NotImplementedError:
    cpus = 4 #Arbitrary Default

def check_online(hostObject):
    try:
        hostname = hostObject[1]['name'][0]
    except:
        returnObject = hostObject + ({'online':False},)
        return returnObject
    result = subprocess.Popen(["ping -c 1 " + hostname  + ' >/dev/null 2>&1; echo $?'],shell=True,stdout=subprocess.PIPE)
    out,err  = result.communicate()
    out = str(out).replace("\n","")
    err = str(err).replace("\n","")
    if(out == "0"):
        returnObject = hostObject + ({'online':True},)
        return returnObject
    else:
        returnObject = hostObject + ({'online':False},)
        return returnObject

class InventoryModule(BaseInventoryPlugin, Constructable):

    NAME = 'ldap_inventory'
    
    def _set_config(self):
        """
        Set config options
        """
        self.ldap_host = self.get_option('ldap_host')
        self.ldap_bind_dn = self.get_option('ldap_bind_dn')
        self.ldap_bind_pw = self.get_option('ldap_bind_pw')
        self.ldap_search_ou = self.get_option('ldap_search_ou')
        self.ldap_lastLogontimeStamp_age = self.get_option('ldap_lastLogontimeStamp_age')
        self.validate_certs = self.get_option('validate_certs')
        self.online_only = self.get_option('online_only')
        self.group_filter = self.get_option('ldap_exclude_groups')
        self.hostname_filter = self.get_option('ldap_exclude_hosts')
        self.use_fqdn = self.get_option('use_fqdn')        


    def _ldap_bind(self):
        """
        Set ldap binding
        """
        try:
            self.ldap_session = ldap.initialize(self.ldap_host)
            self.ldap_session.set_option(ldap.OPT_PROTOCOL_VERSION,ldap.VERSION3)
            if self.validate_certs is False :
                self.ldap_session.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)
                self.ldap_session.set_option(ldap.OPT_X_TLS_NEWCTX, 0)
            self.ldap_session.bind_s(self.ldap_bind_dn, self.ldap_bind_pw, ldap.AUTH_SIMPLE)

        except ldap.LDAPError:
            print("LDAP ERROR")


    def _detect_group(self, ouString):
        """
        Detect groups in OU string
        """
        groups = []
        foundOUs = re.findall('OU=([A-Za-z0-9 ]{1,})',ouString)
        foundOUs = [x.lower() for x in foundOUs]
        foundOUs = [x.replace("-","_") for x in foundOUs]
        foundOUs = [x.replace(" ","_") for x in foundOUs]
        foundOUs = list(reversed(foundOUs))
        for i in range(len(foundOUs)):
            group = '_'.join(elem for elem in foundOUs[0:i+1])
            groups.append(group)
        return groups

    def verify_file(self, path):
        '''
            :param loader: an ansible.parsing.dataloader.DataLoader object
            :param path: the path to the inventory config file
            :return the contents of the config file
        '''
        if super(InventoryModule, self).verify_file(path):
            if path.endswith(('ldap_inventory.yml', 'ldap_inventory.yaml')):
                return True
        display.debug("ldap inventory filename must end with 'ldap_inventory.yml' or 'ldap_inventory.yaml'")
        return False

    def parse(self, inventory, loader, path, cache=False):
        """
        Parses the inventory file
        """
        if not HAS_LDAP:
            raise AnsibleParserError('Please install "python-ldap" Python module as this is required for ldap dynamic inventory')
        super(InventoryModule, self).parse(inventory, loader, path)

        config_data = self._read_config_data(path)
        self._consume_options(config_data)
        self._set_config()

        #TODO: Get variables from vault and yaml call. Set required options.
        #Setup our variables - TODO: move to function?
        ldap_search_scope = ldap.SCOPE_SUBTREE
        ldap_search_groupFilter = '(objectClass=computer)'
        ldap_search_attributeFilter = ['name','lastLogontimeStamp']
        
        timestamp_daysago = datetime.today() - timedelta(days=self.ldap_lastLogontimeStamp_age)
        timestamp_filter_epoch = timestamp_daysago.strftime("%s")
        windows_tick = 10000000
        windows_to_epoc_sec = 11644473600
        timestamp_filter_windows = ( int(timestamp_filter_epoch) + windows_to_epoc_sec ) * windows_tick
        
        
 
        # Call ldap query 
        self._ldap_bind()
        try:
            ldap_results = self.ldap_session.search_s(self.ldap_search_ou, ldap_search_scope, ldap_search_groupFilter, ldap_search_attributeFilter)
        except ldap.LDAPError:
            print(ldap.LDAPError)
            ldap_results = []

        #Parse the results.
        if self.online_only : 
            pool = multiprocessing.Pool(processes=cpus)
            parsedResult = pool.map(check_online, ldap_results)
        else:
            parsedResult = ldap_results

        for item in parsedResult:

            if self.online_only and item[2]['online'] is False :
                continue

            hostName = str(item[1]['name'][0].decode("utf-8").lower())

            if self.use_fqdn is True :
                domainName = "." + str(item[0]).split('DC=',1)[1].replace(',DC=','.')
                hostName = hostName + domainName.lower()
            
            item_time = int(item[1]['lastLogonTimestamp'][0])
            
            #Check for hostname filter
            if hostName in self.hostname_filter :
                display.debug("Skipping " + hostName + " as it was found in ldap_exclude_hosts")
                continue

            #Check age of lastLogontime vs supplied expiration window.
            if self.ldap_lastLogontimeStamp_age > 0  and timestamp_filter_windows > item_time and item_time > 0:
                display.debug("[" + hostName + "] appears to be expired. lastLogontime: " + str(item_time) + " comparison timestamp: " + str(timestamp_filter_windows))
                continue
            
            groups = self._detect_group(item[0])
            
            #Check for groupname filter
            display.debug(groups[-1])
            if groups[-1] in self.group_filter :
                display.debug("Skipping " + hostName + " as group " + groups[-1] + " was found in ldap_exclude_groups")
                continue

            self.inventory.add_host(hostName)
            
            for i in range(len(groups)):
                if i > 0 :
                    self.inventory.add_group(groups[i])
                    self.inventory.add_child(groups[i-1], groups[i])
                else: 
                    self.inventory.add_group(groups[i])
                    self.inventory.add_child('all', groups[i])
                if groups[i] == groups[-1]:
                    self.inventory.add_child(groups[i], hostName)



