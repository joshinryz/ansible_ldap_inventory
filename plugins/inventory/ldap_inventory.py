# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = '''
     name: ldap_inventory
     author: Joshua Robinett (@jshinryz)
     plugin_type: inventory
     short_description: LDAP Inventory Source
     description:
        - Recursively get inventory from LDAP organizational unit. Creates both hosts and groups from LDAP
        - Setup by creating a YAML config file , it's name must end with ldap_inventory.yml or ldap_inventory.yaml.
        - The inventory_hostname is pulled from the 'Name' LDAP attribute.
     options:
         plugin:
             description: "Token that ensures this is a source file for the 'ldap_inventory' plugin"
             required: True
             choices: ['ldap_inventory']
         online_only:
             description: 
                - "Enables checking of hosts using ICMP ping before adding to inventory"
                - "Note: This may not be compatabile with bubblewrap , which is enabled by default in Ansible Tower"
             default: False
             type: boolean
             required: False             
         group_membership:
             description:
                - "Enables parsing the ldap groups that the computer account is a memberOf"
                - "Groups are returned lower case."
             default: False
             type: boolean
             required: False
         group_membership_filter:
             description:
                - When we query for Group membership of the computer object, this allows you to only include names that match the pattern provided.
                - For example, if you only wanted groups that start with security-*
                - "  group_membership_filter: security-*"
             required: False
             default: "*"
             type: str
         account_age:
             description: 
                - "LDAP attribute filter for the lastLogonTimestamp field. This value is generally updated every 14 days."
                - "Timestamps older indicate inactive computer accounts. Setting to 0 disables check. Value is in days"
             default: 0
             required: False
         domain:
             description:
                - The domain to search in to retrieve the LAPS password.
                - This could either be a Windows domain name visible to the Ansible controller from DNS or a specific domain controller FQDN.
                - Supports either just the domain/host name or an explicit LDAP URI with the domain/host already filled in.
                - If the URI is set, I(port) and I(scheme) are ignored.
                - "Examples: "
                - "  local.com" 
                - "  dc1.local.com"
                - "  ldaps://dc1.local.com:636"
                - "  ldap://dc1.local.com"
             required: True
             type: str
         port: 
             description: 
                - Port used to connect to Domain Controller (389 for ldap, 636 for ldaps)
                - If I(kdc) is already an LDAP URI then this is ignored.
             required: False
             type: int
         scheme:
             description: 
                - The LDAP scheme to use.
                - When using C(ldap), it is recommended to set C(auth=gssapi), or C(start_tls=yes), otherwise traffic will be in plaintext.
                - If I(kdc) is already an LDAP URI then this is ignored.
             choices:
                - ldap
                - ldaps
             default: ldap
             type: str
             required: False
         search_ou:
             description: 
                - "LDAP path to search for computer objects." 
                - "Example: CN=Computers,DC=local,DC=com"
             env:
                - name: SEARCH_OU
             required: True
         username:
             description: 
                - "LDAP user account used to bind our LDAP search when auth_type is set to simple" 
                - "Examples:"
                - "  username@local.com"
                - "  domain\\\\username"
             env:
               - name: LDAP_USER
             required: False
         password:
             description: 
                - "LDAP user password used to bind our LDAP search."
                - "Example: Password123!"
             env:
               - name: LDAP_PASS
             required: False
         ldap_filter:
             description: 
                - "Filter used to find computer objects."
                - "Example: (objectClass=computer)"
             required: False
             default: "(objectClass=Computer)"
         exclude_groups:
             description: 
                - "List of groups to not include." 
                - "Example: "
                - "   exclude_groups: "
                - "      - group1"
                - "      - group2"
             type: list
             required: False
             default: []
         exclude_hosts: 
             description: 
                - "List of computers to not include."
                - "Example: "
                - "   exclude_hosts: "
                - "      - host01"
                - "      - host02"
             type: list
             required: False
             default: []
         validate_certs:
             description: "Controls if verfication is done of SSL certificates for secure (ldaps://) connections."
             default: True
             required: False
         fqdn_format:
             description: "Controls if the hostname is returned to the inventory as FQDN or shortname"
             default: False
             required: False
             type: bool
         auth_type:
             description: 
                - Defines the type of authentication used when connecting to Active Directory (LDAP).
                - When using C(simple), the I(username) and (password) options must be set. This requires support of LDAPS (SSL)
                - When using C(gssapi), run C(kinit) before running Ansible to get a valid Kerberos ticket. 
             choices:
                - simple
                - gssapi
             type: str
         extra_groups:
             description: "A list of additional groups to add under 'all' and contain all discovered hosts."
             default: []
             required: False
             type: list
'''

EXAMPLES = '''
# Sample configuration file for LDAP dynamic inventory
    plugin: ldap_inventory
    domain: ldaps://ldapserver.local.com:636
    search_ou: CN=Computers,DC=local,DC=com
    auth_type: simple
    username: username@local.com
    password: Password123!
'''

import os
import re
import traceback
import subprocess
import multiprocessing
from datetime import datetime, timedelta
from ansible.plugins.inventory import BaseInventoryPlugin, Constructable
from ansible.utils.display import Display
from ansible.errors import AnsibleError
from ansible.module_utils._text import to_native
from ansible.module_utils.basic import missing_required_lib

LDAP_IMP_ERR = None
try :
    import ldap
    import ldapurl
    HAS_LDAP = True
except ImportError:
    HAS_LDAP = False
    LDAP_IMP_ERR = traceback.format_exc()

hostname_field = "name"

display = Display()

try:
    cpus = multiprocessing.cpu_count()
except NotImplementedError:
    cpus = 4 #Arbitrary Default

if not HAS_LDAP:
    msg = missing_required_lib("python-ldap", url="https://pypi.org/project/python-ldap/")
    msg += ". Import Error: %s" % LDAP_IMP_ERR
    raise AnsibleError(msg)

class PagedResultsSearchObject:
  page_size = 50

  def paged_search_ext_s(self,base,scope,filterstr='(objectClass=Computer)',attrlist=None,attrsonly=0,serverctrls=None,clientctrls=None,timeout=-1,sizelimit=0):
    """
    Behaves exactly like LDAPObject.search_ext_s() but internally uses the
    simple paged results control to retrieve search results in chunks.
    
    This is non-sense for really large results sets which you would like
    to process one-by-one
    """
    req_ctrl = ldap.controls.SimplePagedResultsControl(True,size=self.page_size,cookie='')

    # Send first search request
    msgid = self.search_ext(
      base,
      ldap.SCOPE_SUBTREE,
      filterstr,
      attrlist,
      serverctrls=(serverctrls or [])+[req_ctrl]
    )

    result_pages = 0
    all_results = []
    
    while True:
      rtype, rdata, rmsgid, rctrls = self.result3(msgid)
      all_results.extend(rdata)
      result_pages += 1
      # Extract the simple paged results response control
      pctrls = [
        c
        for c in rctrls
        if c.controlType == ldap.controls.SimplePagedResultsControl.controlType
      ]
      if pctrls:
        if pctrls[0].cookie:
            # Copy cookie from response control to request control
            req_ctrl.cookie = pctrls[0].cookie
            msgid = self.search_ext(
              base,
              ldap.SCOPE_SUBTREE,
              filterstr,
              attrlist,
              serverctrls=(serverctrls or [])+[req_ctrl]
            )
        else:
            break
    return result_pages,all_results


class MyLDAPObject(ldap.ldapobject.LDAPObject,PagedResultsSearchObject):
  pass




def check_online(hostObject):
    try:
        hostname = hostObject[1][hostname_field][0].decode('utf-8')
    except:
        returnObject = hostObject + ({'online':False},)
        return returnObject
    result = subprocess.Popen(["ping -c 1 " + hostname  + ' >/dev/null 2>&1; echo $?'],shell=True,stdout=subprocess.PIPE)
    out,err  = result.communicate()
    out = out.decode('utf-8').replace("\n","")
    try :
        err = err.decode('utf-8').replace("\n","")
    except: 
        err = ""
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
        self.domain = self.get_option('domain')
        self.port = self.get_option('port')
        self.username = self.get_option('username')
        self.password = self.get_option('password')
        self.search_ou = self.get_option('search_ou')
        self.group_membership = self.get_option('group_membership')
        self.account_age = self.get_option('account_age')
        self.validate_certs = self.get_option('validate_certs')
        self.online_only = self.get_option('online_only')
        self.exclude_groups = self.get_option('exclude_groups')
        self.exclude_hosts = self.get_option('exclude_hosts')
        self.use_fqdn = self.get_option('fqdn_format')
        self.auth_type = self.get_option('auth_type')        
        self.scheme = self.get_option('scheme')  
        self.ldap_filter = self.get_option('ldap_filter')
        self.group_membership_filter = self.get_option('group_membership_filter')
        self.extra_groups = self.get_option('extra_groups')


    def _ldap_bind(self):
        """
        Set LDAP binding
        """

        #ldap.set_option(ldap.OPT_DEBUG_LEVEL, 4095)

        if self.auth_type == 'gssapi' :
            if not ldap.SASL_AVAIL:
                raise AnsibleLookupError("Cannot use auth=gssapi when SASL is not configured with the local LDAP install")
            if self.username or self.password:
                raise AnsibleError("Explicit credentials are not supported when auth_type='gssapi'. Call kinit outside of Ansible")
        elif self.auth_type == 'simple' and not (self.username and  self.password):
            raise AnsibleError("The username and password values are required when auth_type=simple")
        else:
            if self.username and  self.password:
                self.auth_type = 'simple'
            elif ldap.SASL_AVAIL:
                self.auth_type == 'gssapi'
            else:
                raise AnsibleError("Invalid auth_type value '%s': expecting either 'gssapi', or 'simple'" % self.auth_type)
        
        if ldapurl.isLDAPUrl(self.domain):
            ldap_url = ldapurl.LDAPUrl(ldapUrl=self.domain)
        else:
            self.port = self.port if self.port else 389 if self.scheme == 'ldap' else 636
            ldap_url = ldapurl.LDAPUrl(hostport="%s:%d" % (self.domain, self.port), urlscheme=self.scheme)             
        
        if self.validate_certs is False :
            ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_ALLOW) 
        
        if not ldap.TLS_AVAIL and ldap_url.urlscheme == 'ldaps':
            raise AnsibleLookupError("Cannot use TLS as the local LDAP installed has not been configured to support it")
        
        conn_url = ldap_url.initializeUrl()
        #self.ldap_session = MyLDAPObject(conn_url, trace_level=3)  # higher trace levels
        self.ldap_session = MyLDAPObject(conn_url)
        self.ldap_session.page_size = 900
        self.ldap_session.set_option(ldap.OPT_PROTOCOL_VERSION, 3)
        self.ldap_session.set_option(ldap.OPT_REFERRALS, 0)
 
        if self.auth_type == 'simple':
            try:
                self.ldap_session.bind_s(self.username, self.password, ldap.AUTH_SIMPLE)
            except ldap.LDAPError as err:
                raise AnsibleError("Failed to simple bind against LDAP host '%s': %s " % (conn_url, to_native(err)))
        else:
            # Windows AD does not allow seal/sign when over TLS
            if ldap_url.urlscheme == 'ldaps':
                self.ldap_session.set_option(ldap.OPT_X_SASL_SSF_MAX, 0)

            try:
                self.ldap_session.sasl_gssapi_bind_s()
            except ldap.AUTH_UNKNOWN as err:
                # The SASL GSSAPI binding is not installed, e.g. cyrus-sasl-gssapi. Give a better error message than what python-ldap provides
                raise AnsibleError("Failed to do a sasl bind against LDAP host '%s', the GSSAPI mech is not installed: %s" % (conn_url, to_native(err)))
            except ldap.LDAPError as err:
                raise AnsibleError("Failed to do a sasl bind against LDAP host '%s': %s" % (conn_url, to_native(err)))                
     
       



    def _detect_group(self, ouString):
        """
        Detect groups in OU string
        """
        groups = []
        foundOUs = re.findall('(?u)OU=([^,]+)',ouString)
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
        display.debug("DEBUG: ldap inventory filename must end with 'ldap_inventory.yml' or 'ldap_inventory.yaml'")
        return False

    def parse(self, inventory, loader, path, cache=False):
        """
        Parses the inventory file
        """
        super(InventoryModule, self).parse(inventory, loader, path)

        self._read_config_data(path)
        self._set_config()

        if not self.search_ou:
            raise AnsibleError("Search base not set in search_ou config option or SEARCH_OU environmental variable")
        
        ldap_search_scope = ldap.SCOPE_SUBTREE
        if not self.ldap_filter:
            ldap_type_groupFilter = '(objectClass=Computer)'
        else:
            ldap_type_groupFilter = self.ldap_filter  # Todo check if query is valid
        
        if self.account_age > 0:
            ldap_search_attributeFilter = [hostname_field,'lastLogontimeStamp']
        else:
            ldap_search_attributeFilter = [hostname_field]
        
        timestamp_daysago = datetime.today() - timedelta(days=self.account_age)
        timestamp_filter_epoch = timestamp_daysago.strftime("%s")
        windows_tick = 10000000
        windows_to_epoc_sec = 11644473600
        timestamp_filter_windows = ( int(timestamp_filter_epoch) + windows_to_epoc_sec ) * windows_tick
        
        
 
        # Call LDAP query 
        self._ldap_bind()

        try:
            pages, ldap_results = self.ldap_session.paged_search_ext_s(base=self.search_ou, scope=ldap_search_scope, filterstr=ldap_type_groupFilter, attrlist=ldap_search_attributeFilter)
        
        except ldap.LDAPError as err:
            raise AnsibleError("Unable to perform query against LDAP server '%s' reason: %s" % (self.domain, to_native(err)))
            ldap_results = []
        display.debug('DEBUG: ldap_results Received %d results in %d pages.' % (len(ldap_results),pages) )
        
        #Parse the results.
        if self.online_only : 
            pool = multiprocessing.Pool(processes=cpus)
            parsedResult = pool.map(check_online, ldap_results)
        else:
            parsedResult = ldap_results

        for item in parsedResult:
            if isinstance(item[1],dict) is False or len(item[1]) != len(ldap_search_attributeFilter) :
                display.debug("DEBUG: Skipping an possible corrupt object " + str(item[1]) + " " + str(item[0]))
                continue
            if self.online_only and item[2]['online'] is False :
                continue
            hostName = item[1][hostname_field][0].decode("utf-8").lower()
            display.debug("DEBUG: " + hostName + " processing host")
            pattern = re.compile('^DC')
            root_split = item[0].split(',')
            root_match = [s for s in root_split if pattern.match(s) ]
            root_ou = ','.join(root_match)
            #root_ou = "OU=Groups,%s" % root_ou
            ldapGroups = []

            if self.use_fqdn is True :
                domainName = "." + item[0].split('DC=',1)[1].replace(',DC=','.')
                hostName = hostName + domainName.lower()
            
            if self.account_age > 0:
                item_time = int(item[1]['lastLogonTimestamp'][0])
            


            #Check for hostname filter
            if any(sub in hostName for sub in self.exclude_hosts) :
                display.debug("DEBUG: Skipping " + hostName + " as it was found in exclude_hosts")
                continue
            #Check age of lastLogontime vs supplied expiration window.
            if self.account_age > 0  and timestamp_filter_windows > item_time and item_time > 0:
                display.debug("DEBUG: [" + hostName + "] appears to be expired. lastLogontime: " + str(item_time) + " comparison timestamp: " + str(timestamp_filter_windows))
                continue
            
            ouGroups = self._detect_group(item[0])
            
            
            if self.group_membership:
                groupFilter = "(&(objectClass=group)(member:1.2.840.113556.1.4.1941:=%s)(name=%s))" % (item[0], self.group_membership_filter)
                try:
                    ldapSearch = self.ldap_session.search_ext_s(base=root_ou, scope=ldap_search_scope, filterstr=groupFilter, attrlist=["cn"])
                except ldap.LDAPError as err:
                    raise AnsibleError("Unable to perform query against LDAP server '%s' reason: %s" % (self.domain, to_native(err)))
                if len(ldapSearch) > 0 : 
                    for g in ldapSearch : 
                        if re.search("^cn", str(g[0]).lower()):
                            groupName = g[0].replace("-","_").replace(" ","_").lower().split(",",1)[0][3:]
                            ldapGroups.append(groupName)
                #Debug the search settings used to find groups. 
                display.debug("DEBUG: ldap search for groups using settings - base=%s, scope=%s, filterstr=%s" % (root_ou,ldap_search_scope,groupFilter) )

            #Check for groupname filter
            display.debug("DEBUG: Primary group for  %s detected as %s" % (hostName, ouGroups[-1]))
            
            if any(sub in ouGroups[-1] for sub in self.exclude_groups) :
                display.debug("DEBUG: Skipping %s as group %s was found in ldap_exclude_groups" % (hostName, sub))
                continue
            
            if any(sub in ldapGroups for sub in self.exclude_groups) :
                display.debug("DEBUG: Skipping %s as group %s was found in ldap_exclude_groups" % (hostName, sub))
                continue
            
            
            if (len(ouGroups) < 1) and (len(ldapGroups) < 1): 
                display.debug('DEBUG: No Groups were detected for %s' % hostName)
                continue
            

            self.inventory.add_host(hostName)
            
            for i in range(len(ouGroups)):
                if i > 0 :
                    self.inventory.add_group(ouGroups[i])
                    self.inventory.add_child(ouGroups[i-1], ouGroups[i])
                else: 
                    self.inventory.add_group(ouGroups[i])
                    self.inventory.add_child('all', ouGroups[i])
                if ouGroups[i] == ouGroups[-1]:
                    self.inventory.add_child(ouGroups[i], hostName)
            
            for group in ldapGroups:
                    self.inventory.add_group(group)
                    self.inventory.add_child(group, hostName)

            for eg in self.extra_groups:
                self.inventory.add_group(eg)
                self.inventory.add_child('all', eg)
                self.inventory.add_child(eg, hostName)
