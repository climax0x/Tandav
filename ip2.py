import shodan
import argparse
import subprocess

# Function to get all IPs for a domain
def get_ips(api_key, domain):
    # Initialize the Shodan API
    api = shodan.Shodan(api_key)

    # Perform the search
    try:
        results = api.search('hostname:{}'.format(domain))
        ips = [result['ip_str'] for result in results['matches']]
        unique_ips = list(set(ips)) # Remove duplicates
        return unique_ips
    except shodan.APIError as e:
        print('Error: {}'.format(e))

# Function to resolve IP addresses using httpx
def resolve_ips(ips):
    resolved_ips = []
    for ip in ips:
        try:
            result = subprocess.check_output(['httpx', '-json', '-follow-redirects', ip])
            if result:
                resolved_ip = result.decode('utf-8').split('\n')[-2] # Get the last line of the output
                resolved_ips.append(resolved_ip)
            else:
                resolved_ips.append(ip) # If httpx fails, use the original IP
        except subprocess.CalledProcessError:
            resolved_ips.append(ip) # If httpx fails, use the original IP
    return resolved_ips
    
# Parse the arguments
parser = argparse.ArgumentParser(description='Find all IP addresses associated with a domain using Shodan API')
group = parser.add_mutually_exclusive_group(required=True)
group.add_argument('-d', '--domain', help='The domain to search for')
group.add_argument('-l', '--domain-list', help='The path to the file containing a list of domains')
args = parser.parse_args()

# Shodan API key
api_key = 'your_api_key'

# Get the IPs for the domain(s)
if args.domain:
    domains = [args.domain]
else:
    with open(args.domain_list, 'r') as f:
        domains = f.read().splitlines()

all_ips = []
for domain in domains:
    ips = get_ips(api_key, domain)

    # Add a check to skip None values
    if ips is not None:
        all_ips.extend(ips)

# Remove duplicates
unique_ips = list(set(all_ips))

# Resolve the IPs using httpx
resolved_ips = resolve_ips(unique_ips)

# Print the results
for ip in resolved_ips:
    print(ip)
