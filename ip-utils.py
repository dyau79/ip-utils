def ip_utils(ip_address):
    """
    Utility function to validate and get information about an IP address.
    
    Args:
        ip_address (str): The IP address to analyze.
        
    Returns:
        dict: A dictionary containing the following keys:
            'valid' (bool): True if the IP address is valid, False otherwise.
            'version' (int): The IP version (4 or 6).
            'broadcast' (str): The broadcast address (for IPv4 only).
            'network' (str): The network address.
            'gateway' (str): The gateway address.
    """
    # IPv4 address format: x.x.x.x, where x is an integer between 0 and 255
    ipv4_pattern = r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$'
    
    # IPv6 address format: xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx
    # where x is a hexadecimal digit (0-9, a-f, A-F)
    ipv6_pattern = r'^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$'
    
    import re
    
    if re.match(ipv4_pattern, ip_address):
        # Valid IPv4 address
        octets = [int(octet) for octet in ip_address.split('.')]
        network = '.'.join([str(octet) for octet in octets[:3] + [0]])
        broadcast = '.'.join([str(octet) for octet in octets[:3] + [255]])
        gateway = '.'.join([str(octet) for octet in octets[:3] + [1]])
        return {
            'valid': True,
            'version': 4,
            'broadcast': broadcast,
            'network': network,
            'gateway': gateway
        }
    elif re.match(ipv6_pattern, ip_address):
        # Valid IPv6 address
        network = ip_address.split('::')[0] + '::' if '::' in ip_address else ip_address
        gateway = network.rsplit(':', 1)[0] + ':1'
        return {
            'valid': True,
            'version': 6,
            'broadcast': None,
            'network': network,
            'gateway': gateway
        }
    else:
        # Invalid IP address
        return {
            'valid': False,
            'version': None,
            'broadcast': None,
            'network': None,
            'gateway': None
        }