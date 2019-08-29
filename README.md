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
domain: 'ldaps://adserver.domain.local:636'
username: user@domain.local
password: "password"
search_ou: "OU=Servers,OU=Windows,DC=domain,DC=local"
```
Additional options:
```(yaml)
validate_certs: True 
online_only: False  
account_age: 15 
exclude_groups: "windows_group1,windows_group2"
exclude_hosts: "hostname1,hostname2"
fqdn_format: False

```
**validate_certs** - allows disabling of validation of the SSL cert of the domain controller.
**online_only** - performs a ping check of the machine before adding to inventory. Note: Does not work under bubblewrap (Tower) due to setuid flag of ping.
**account_age** - By default AD objects are updated every 14 days. This is the lastLogontimeStamp field on an object. Set to 0 to disable.
**exclude_hosts** - exclude a list of hosts from being included in the inventory. This will match substrings.
**exclude_groups** - exclude a list of groups from being included in the inventory. This wil match substrings.
**port** - used to specify the port for LDAP (usually 389 for non-ssl , 636 for ssl)
**scheme** - the ldap scheme to use. (ldap or ldaps). This is not required and can be determined from the URI or Port.
**auth_type** - the type of authentication to use. (gssapi or simple)
**ldap_filter** - LDAP filter used to find objects. Default : objectClass=Computer . You should not usually need to change this.
**fqdn_format** - specifies if we should use FQDN instead of shortname for hosts. Default is False.


### Testing the inventory with Ansible

`ansible-inventory -i ldap_inventory --list`
`ansible-inventory -i ldap_inventory --list --vault-id=@prompt` (when vaulted)

** Running a playbook **

`ansible-playbook -i ldap_inventory.yaml adhoc.yaml --vault-id@prompt `
