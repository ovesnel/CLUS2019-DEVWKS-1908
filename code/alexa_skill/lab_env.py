from os import getenv

IN_AWS = getenv('IN_AWS', None)

if not IN_AWS:
    import set_env

DNAC_HOST = getenv('DNAC_HOST', 'sandboxdnac2.cisco.com')
DNAC_PORT = getenv('DNAC_PORT', '8080')
DNAC_USER = getenv('DNAC_USER', 'devnetuser')
DNAC_PASSWORD = getenv('DNAC_PASSWORD', 'Cisco123!')
APIC_HOST = getenv('APIC_HOST', 'sandboxapicdc.cisco.com')
APIC_PORT = getenv('APIC_PORT', '443')
APIC_USER = getenv('APIC_USER', 'admin')
APIC_PASSWORD = getenv('APIC_PASSWORD', 'ciscopsdt')
