"""
This small program is to help you understand and learn how wildcards function when writing a Cisco ACL

The program will continuously loop asking you to enter an IP address range specifier in Cisco ACL format, this means
one of:

  host a.b.c.d     (single host)
  any              (all hosts)
  a.b.c.f w.x.y.z  (ip address and wildcard mask option)

The program will then decode the entered information and list all matching ip addresses

Written by Jason But, Copyright 2024

Code is not available for public re-use
"""

# Regular Expression library is used to check formatting of entered string for correctness
import re

# Some functions to help manipulate data while contructing the IP address list
import itertools

# These two classes allow manipulation of IP addresses and manage display/printing
from ipaddress import IPv4Address, IPv4Network


def get_address_range() -> str:
    """
    Asks the user to input the address range to decode and returns the string

    :return: String entered by the user
    """
    print('\n---------------------------------------------------------------------------------------------------')
    print('Please enter a valid IP address range for a Cisco ACL. Valid options include:')
    print('   host a.b.c.d    - matches only the IP address a.b.c.d')
    print('   any             - matches all IP addresses (0.0.0.0/0 or 0.0.0.0-255.255.255.255')
    print('   a.b.c.d w.x.y.z - match IP addresses when wildcard mask w.x.y.z is applied to IP address a.b.c.d')
    print('   q               - quit program')
    return input('User input:').strip()


def validate_address_range(ip_range: str) -> bool:
    """
    Validates that the string is properly formatted and returns the outcome of the validation

    Uses Python Regular Expressions to parse the string and return whether it is correctly formed or not

    :param ip_range: Complete ip specifier as specified in ACL

    :return: True if the string is a valid IP Range specifier
    """
    # Matches an IP address
    _ip_address_rx = (
        r'(?:'
        r'(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}'
        r'(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])'
    )

    # Matches "host <ip_address>" OR "<ip address> <ip address>" OR "any"
    _network_statement_rx = (
        f'(?:host\s+({_ip_address_rx}))'
        r'|'
        f'(?:({_ip_address_rx}\s+{_ip_address_rx}))'
        r'|'
        r'(?:any)'
    )

    # Match _network_statement_rx and store in variable called range
    _address_range_rx = f'(?P<range>{_network_statement_rx})$'

    re_obj = re.compile(_address_range_rx, re.I)
    match = re_obj.match(ip_range)
    if not match:
        print(f'\n\nERROR: Badly formed ip range match statement ({ip_range})')
        return False

    return True


def decode_address(ip_range: str) -> list[IPv4Network]:
    """
    Decodes the provided ACL address range string and returns a list of IPv4Network structures containing matched IP addresses

    In most cases, this list will contain one element as we usually write rules to match a continuous range of addresses

    There will be more than one range IF the requirements are "different" such as all odd addresses

    Otherwise, a return list with multiple elements is likely to be an error in the wildcard mask

    :param ip_range: Complete ip specifier as specified in ACL

    :return: List of IP Address range tuples specifying ranges of included addresses
    """
    # Split ip_range into component parts (host <add> OR any OR <add> <wildcard>) - length and values can vary
    parts: list[str] = ip_range.split()

    # Special cases, any maps to 0.0.0.0/0 and host maps to <parts[1]/32. Reset values for processing into list
    match parts[0]:
        case 'any':
            print(f'\n  Converting {ip_range} to "0.0.0.0 255.255.255.255"')
            parts[0] = '0.0.0.0'
            parts.append('255.255.255.255')
        case 'host':
            print(f'\n  Converting {ip_range} to "{parts[1]} 0.0.0.0"')
            parts[0] = parts[1]
            parts[1] = '0.0.0.0'

    # We work in 32 bit integers to access bitwise operators

    # Extract wildcard parameter as 32 bit integer
    wildcard: int = int(IPv4Address(parts[1]))

    # Find first possible address (set wildcard bits to 0)
    ip_first: int = int(IPv4Address(parts[0])) & (~wildcard)

    print(f'\n  IP Address:    {parts[0]:<15}:   binary({IPv4Address(parts[0]):b})')
    print(f'  Wildcard Mask: {parts[1]:<15}:   binary({IPv4Address(parts[1]):b})')

    if ip_first != int(IPv4Address(parts[0])):
        print(f'\nWARNING: Possible mistake entering rule: IP address in range {parts[0]} is not the first matched address')

    # Convert wildcard to a list of integers representing each bit
    mask_bits = [int(x) for x in format(wildcard, F"0{32}b")]

    # Calculate host bits of all ranges mapped by wildcard (non standard wildcard will map to many non-consecutive ranges, but all will be the same size)
    # Host bits is number of consecutive 1-bits at end of wildcard
    if wildcard & 1:
        # LSB of wildcard is 1, so each range will be bigger than 1
        #  - [list(.) ... groupby(...] will create runs of [0,0,...] and [1,1,...] from wildcard
        #  - the last element is the run of consecutive bits at end of mask
        #  - len will determine size of each range (host_bits)
        host_bits = len([list(y) for x, y in itertools.groupby(mask_bits)][-1])
    else:
        # LSB of wildcard is 0, each range only contains one address (host_bits is zero - /32)
        host_bits = 0

    # How many to add to network address of range to find final address in range (each range is same size)
    # - Size of subnet based on host_bits - 1 (eg. subnet /24 = 2^8 - 1 = 255, final address is 0 + 255 = 255)
   # final_address_mask = 2**host_bits - 1

    # Calculate integer values of all other wildcard bits EXCEPT those excluded by host_bits
    # - enumerate(reversed) if bit_value generates a list of pairs mapping bit-index to value but only for 1-bits in mask
    # - Comprehension will raise each index to power of two to calculate mask value
    # - Strip excluded host_bits from start of list
    other_mask_bits = [2 ** index for index, bit_value in enumerate(reversed(mask_bits)) if bit_value == 1][host_bits:]

    # Reverse order back to normal - MSB is first
    other_mask_bits.reverse()

    # Calculate the total number of distinct ranges of size host_bits we will create
    num_ranges = 2 ** len(other_mask_bits)

    # Ordered list of binary representatives of all possible combinations of num_ranges bits
    all_bit_masks = [[int(x) for x in format(y, F"0{len(other_mask_bits)}b")] for y in range(num_ranges)]

    # Ordered list of all masks to apply to ip_first to generate network addresses
    # - Inner comprehension will create a list of masks multiplied by one combination)
    # - Outer comprehension will sum these masks for each possible combination
    all_masks = [sum([a * b for a, b in zip(other_mask_bits, all_bit_masks[i])]) for i in range(num_ranges)]

    # Calculate all the subnets matched by the rule, for each mask, OR it with ip_first to find all network addresses, then apply the common range subnet mask
    return [IPv4Network((ip_first | mask, 32 - host_bits)) for mask in all_masks]


def parse_wildcard(range_str: str) -> None:
    """
    Validate and parse the provided ACL IP range string including wildcards

    Validate string for correctness, then decode the string and print the matched IP addresses

    :param range_str: String containing wildcard to validate and parse
    """
    # If the provided string is invalid, just return
    # validate_address_range() will print an error message if the string is invalidated
    if not validate_address_range(input_str): return

    print(f'\nProcessing Input: {input_str}')

    # Get the list of matched IP subnets
    matched_ranges = decode_address(input_str)

    # Print warning if multiple contigouous ranges are calculated
    if len(matched_ranges) > 1:
        print('\nWARNING: Possible mistake entering rule, more than one continuous range of addresses. If you are not trying to do something like odd or even addresses, this is likely wrong')

    # Display matched addresses. If each subnet is of size one, display single IP address, otherwise print ranges
    print('\n  Matched IP Addresses')
    for match in matched_ranges:
        if match.prefixlen == 32:
            print(f'    {str(match):<18} : {str(match.network_address):<15}')
        else:
            print(f'    {str(match):<18} : {str(match.network_address):<15} - {match.broadcast_address}')


# Execute program if run as program, do nothing if imported as library
if __name__ == "__main__":
    print('\n\nCisco ACL Wildcard Parser')
    print('\nDeveloped by Jason But for use in TNE20002/TNE70003')

    while True:
        # Get input from user
        input_str: str = get_address_range()

        # If user chooses to terminate the program, simply return
        if input_str in ['q', 'Q']: break

        parse_wildcard(input_str)

