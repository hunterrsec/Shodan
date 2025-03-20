import shodan
import csv
import time
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

# 🔥 Replace with your Shodan API key
API_KEY = "KEYiiSOALSOODNIDEYEOASOEJL"

# Maximum Shodan results
MAX_RESULTS = 1000

# Output CSV file
OUTPUT_FILE = "advanced_shodan_results.csv"

# Initialize Shodan API
api = shodan.Shodan(API_KEY)

# Logging setup
logging.basicConfig(filename="shodan_errors.log", level=logging.ERROR)

def search_shodan(query, max_results=500):
    """ Perform Shodan search with multi-threading. """
    results = []
    
    try:
        print(f"\n[🔍] Searching Shodan for: {query}")
        response = api.search(query, limit=max_results)

        print(f"[✅] Found {response['total']} results\n")

        for result in response['matches']:
            # Extract details
            ip = result.get('ip_str', 'N/A')
            ports = ', '.join(map(str, result.get('ports', [])))
            vulns = ', '.join(result.get('vulns', {}).keys()) if 'vulns' in result else 'None'
            org = result.get('org', 'N/A')
            isp = result.get('isp', 'N/A')
            country = result.get('location', {}).get('country_name', 'N/A')
            city = result.get('location', {}).get('city', 'N/A')
            
            # Extract subdomains and URLs
            subdomains = ', '.join(result.get('hostnames', ['N/A']))
            affected_urls = []
            
            if 'http' in result and 'host' in result['http']:
                affected_urls.append(result['http']['host'])

            # Extract HTTP details
            http_info = result.get('http', {})
            server = http_info.get('server', 'N/A')
            status_code = http_info.get('status', 'N/A')

            results.append({
                "IP": ip,
                "Subdomains": subdomains,
                "Ports": ports,
                "Vulnerabilities": vulns,
                "Org": org,
                "ISP": isp,
                "Country": country,
                "City": city,
                "Affected URLs": ', '.join(affected_urls) if affected_urls else "N/A",
                "Server": server,
                "Status Code": status_code
            })

        return results

    except shodan.APIError as e:
        logging.error(f"Shodan API Error: {e}")
        print(f"[❌] Shodan API Error: {e}")
        return []

def save_to_csv(data, filename):
    """ Save results to a CSV file. """
    if data:
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = [
                "IP", "Subdomains", "Ports", "Vulnerabilities", 
                "Org", "ISP", "Country", "City", 
                "Affected URLs", "Server", "Status Code"
            ]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

            writer.writeheader()
            writer.writerows(data)

        print(f"\n[✅] Results saved to {filename}")
    else:
        print("[❌] No results to save.")

def threaded_shodan_search(domain):
    """ Multi-threaded Shodan search with error handling. """
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(search_shodan, f"hostname:{domain}", MAX_RESULTS)]
        results = []

        for future in as_completed(futures):
            try:
                results.extend(future.result())
            except Exception as e:
                logging.error(f"[❌] Error in thread: {e}")

        return results

if __name__ == "__main__":
    domain = input("\n[🌐] Enter the domain name: ").strip()

    print("\n[🚀] Starting Shodan Advanced Domain Search...")
    start_time = time.time()

    # Perform Shodan search
    shodan_data = threaded_shodan_search(domain)

    if shodan_data:
        save_to_csv(shodan_data, OUTPUT_FILE)
    else:
        print("[❌] No data found or an error occurred.")
    
    end_time = time.time()
    print(f"\n[⏱️] Scan completed in {end_time - start_time:.2f} seconds.")
