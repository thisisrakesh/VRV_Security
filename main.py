#import all the necessary modules into our program 
import csv 
from collections import defaultdict
import re

FAILED_LOGIN_THRESHOLD = 10

ip_requests = defaultdict(int)
endpoints = defaultdict(int)
failed_logins = defaultdict(int)

def process_log(file_name):
    ''' 
    This function processes the log file to extract and also it does the following tasks:
    --> IP address and its associated request count
    --> Access count for each endpoint
    --> Failed login attempts for suspicious activity detection
    '''
    with open(file_name, 'r') as file:
        for line in file:
            # Extract the IP address using the regular expressions
            ip = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
            # Extract HTTP status code (e.g., 200 for success, 401 for failed login)
            status = re.search(r'HTTP/\S+ (\d+)', line)
            # Extract the endpoint (URL or resource path)
            endpoint = re.search(r'\"(GET|POST)\s([^\s]+)', line)

            # If all the components (IP, status, and endpoint) are found in the line, then we will process 
            if ip and status and endpoint:
                ip_address = ip.group(1)
                status_code = status.group(1)
                endpoint_url = endpoint.group(2)

                # Increment the request count for this IP address 
                ip_requests[ip_address] += 1 

                # Increment the count for this endpoint 
                endpoints[endpoint_url] += 1 

                # If the status code is 401, it means it is a failed login attempt
                if status_code == "401":
                    failed_logins[ip_address] += 1 

def display_results():
    ''' 
    This function displays the analysis results in the terminal:
    It will print the following things:
    --> Requests per IP address
    --> Most accessed endpoint 
    --> Suspicious Activity (IPs with failed login attempts exceeding the threshold)
    '''
    
    # Printing the IP requests
    print("IP Address          Request Count")
    for ip, count in ip_requests.items():
        print(f"{ip:<20}        {count:<4}")

    print()

    # Printing the most accessed endpoint
    print("Most Frequently Accessed Endpoint:")
    most_accessed_endpoint = max(endpoints, key=endpoints.get)
    print(f"{most_accessed_endpoint}   (Accessed {endpoints[most_accessed_endpoint]:<3} times)")

    print()

    # Printing suspicious activity (IPs with failed logins exceeding threshold)
    print("Suspicious Activity Detected:")
    print("IP Address           Failed Login Attempts")
    for ip, failed_count in failed_logins.items():
        if failed_count > FAILED_LOGIN_THRESHOLD:
            print(f"{ip:<25}{failed_count:<2}")

def save_to_csv():
    '''
    This function saves the result of the analysis to a CSV file: 
    --> IP requests
    --> Most accessed endpoints
    --> Suspicious Activity
    '''
    with open('log_analysis_results.csv', mode='w', newline='') as file:
        writer = csv.writer(file)

        # Write all the headers for requests per IP 
        writer.writerow(['IP Address', 'Request Count'])
        for ip, count in ip_requests.items():
            writer.writerow([ip, count])
        
        writer.writerow([])
        writer.writerow(["Most Accessed Endpoint", f"/{max(endpoints, key=endpoints.get)}", 
                         f"Accessed {endpoints[max(endpoints, key=endpoints.get)]} times"])

        # Write suspicious activity (IPs with failed logins exceeding threshold)
        writer.writerow([])
        writer.writerow(["IP Address", "Failed Login Count"])
        for ip, failed_count in failed_logins.items():
            if failed_count > FAILED_LOGIN_THRESHOLD:
                writer.writerow([ip, failed_count])

# Name of the file
log_file = 'sample.log'

# Calling the function to process the log_file to extract and analyze the data
process_log(log_file)

# Calling the Display function to display the results
display_results()

# Saving the results into a csv file 
save_to_csv()

