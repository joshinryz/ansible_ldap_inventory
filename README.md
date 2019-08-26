# Ansible LDAP Inventory Plugin

This plugin was designed to query active directory and get a list of machines to use as an inventory.
Groups are auto generated off of OU structure. So for example `cn=computer1,ou=servers,ou=windows,dc=mycompany,dc=local` would create the following inventory :
```
    "all": {
        "children": [
            "windows"
        ]
    },
    "windows": {
        "children": [
            "windows_servers"
        ]
    },
    "windows_servers": {
        "hosts": [
            "computer1"
        ]
    }
```

## Prerequisites

The ldap inventory works with python2 and python3.

**The following package is required :**
* [`python-ldap`](https://www.python-ldap.org/en/latest/) 

It can be installed in one of the following ways : 

`pip install -r requirements.txt`

or

`pip install python-ldap`

### Configuration
Place the file `ldap_inventory.py` into your base folder under `.\plugins\inventory\`

Create a file that ends with `ldap_inventory.yaml` in your base directory. 
It is recommended you vault the entire file (until ansible supports vaulted strings in config files) `ansible-vault edit ldap_inventory.yaml`

Example `ldap_inventory.yaml` :
```(yaml)
---
plugin: ldap_inventory
ldap_host: 'ldaps://adserver.domain.local:636'
ldap_bind_dn: user@domain.local
ldap_bind_pw: "password"
ldap_search_ou: "OU=Servers,OU=Windows,DC=domain,DC=local"
```
Additional options:
```(yaml)
validate_certs: True 
online_only: False  
ldap_lastLogontimeStamp_age: 15 
ldap_exclude_groups: "windows_group1,windows_group2"
ldap_exclude_hosts: "hostname1,hostname2"
use_fqdn: False

```
**validate_certs** - allows disabling of validation of the SSL cert of the domain controller.
**online_only** - performs a ping check of the machine before adding to inventory. Note: Does not work under bubblewrap (Tower) due to setuid flag of ping.
**ldap_lastLogontimeStamp_age** - By default AD objects are updated every 14 days. Sett
**ldap_exclude_hosts** - exclude a list of hosts from being included in the inventory
**ldap_exclude_groups** - exclude a list of groups from being included in the inventory
**use_fqdn** - specifies if we should use FQDN instead of shortname for hosts


### Testing the inventory with Ansible

`ansible-inventory -i ldap_inventory --list`
`ansible-inventory -i ldap_inventory --list --vault-id=@prompt` (when vaulted)

** Running a playbook **

`ansible-playbook -i ldap_inventory.yaml adhoc.yaml --vault-id@prompt `
