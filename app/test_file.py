import requests
import time
from tabulate import tabulate
import json

BASE_URL = "http://localhost:8000"

test_results = []

def get_authentication(username, password):
    response = requests.post(
        f"{BASE_URL}/login",
        data={"username": username, "password": password}
    )

    token = response.json().get("access_token")
    return token

admin_access = get_authentication("admin", "admin")
user2_access = get_authentication("john", "john")
user3_access = get_authentication("bob", "bob")

def match_which_vulnerability(method, endpoint):
    parts = endpoint.split('/')
    endpoint_type = parts[0]
    resource_id = None
    additional_parameter = None
    if len(parts) > 1:
        resource_id = parts[1]
    if len(parts) > 2:
        additional_parameter = parts[2]


    if method == "GET":
        if endpoint_type == "users" and resource_id and additional_parameter != "orders":
            return "BOLA 1"
        elif endpoint_type == "users" and resource_id and not additional_parameter:
            return "BOLA 1"
        elif endpoint_type == "orders" and not resource_id:
            return "BOLA 2"
        elif endpoint_type == "orders" and resource_id:
            return "BOLA 3"
        elif endpoint_type == "users" and resource_id and additional_parameter == "orders":
            return "BOLA 6"
    elif method == "PUT":
        if endpoint_type == "orders" and resource_id:
            return "BOLA 4"
        elif endpoint_type == "product" and resource_id:
            return "BOLA 5"
    elif method == "DELETE" and endpoint_type == "orders":
        return "BOLA 7"
    
    return "Other"

def test_endpoint(method, endpoint, token, expected_status, username, pattern=None, data=None):
    start_time = time.time()

    url = f"{BASE_URL}/{endpoint}"
    if pattern == "404_First":
        url = f"{url}/alt-path"
    elif pattern == "Query_Focused":
        url = f"{url}/alt-path2"

    headers={"Authorization": f"Bearer {token}"} # To get through current_user

    if method == "GET":
        response = requests.get(url,headers=headers)
    elif method == "PUT":
        response = requests.put(url, json=data, headers=headers)
        if response.status_code == 422:
            response = requests.put(url, params=data, headers=headers)
    elif method == "DELETE":
        response = requests.delete(url, headers=headers)
    elif method == "POST":
        response = requests.post(url, headers=headers)
    else:
        response = requests.get(url,headers=headers)
        print(f"!!!!! Error with {method} @ {endpoint} | {token}!")
    
    duration = time.time() - start_time

    vulnerability = match_which_vulnerability(method, endpoint)

    result = {
        "vulnerability": vulnerability,
        "method": method,
        "pattern": pattern,
        "endpoint": endpoint,
        "url": url,
        "username": username,
        "status_code": response.status_code,
        "response_time": round(duration * 1000, 2),
        "expected_status": expected_status,
        "passed": response.status_code == expected_status
    }

    return result

admin_access = get_authentication("admin", "admin")
user2_access = get_authentication("john", "john")
user3_access = get_authentication("bob", "bob")



# Check User 2's Own Access - Should Succeed, e.g., Return 200
test_results.append(test_endpoint("GET", "users/2", user2_access, 200, "john", "403_First"))
test_results.append(test_endpoint("GET", "users/2", user2_access, 200, "john", "404_First"))
test_results.append(test_endpoint("GET", "users/2", user2_access, 200, "john", "Query_Focused"))

# User 2 Accessing User 3's - Should Fail
test_results.append(test_endpoint("GET", "users/3", user2_access, 403, "john", "403_First"))
test_results.append(test_endpoint("GET", "users/3", user2_access, 403, "john", "404_First"))
test_results.append(test_endpoint("GET", "users/3", user2_access, 404, "john", "Query_Focused"))

# User 3 Accessing their Own Order - Should Succeed 
test_results.append(test_endpoint("GET", "orders/1", user2_access, 200, "john", "403_First"))
test_results.append(test_endpoint("GET", "orders/1", user2_access, 200, "john", "404_First"))
test_results.append(test_endpoint("GET", "orders/1", user2_access, 200, "john", "Query_Focused"))

# User 2 Accessing Order owned by User 3
test_results.append(test_endpoint("GET", "orders/5", user2_access, 403, "john", "403_First"))
test_results.append(test_endpoint("GET", "orders/5", user2_access, 403, "john", "404_First"))
test_results.append(test_endpoint("GET", "orders/5", user2_access, 404, "john", "Query_Focused"))

# User 3 Accessing User 2's Access - Should Fail
test_results.append(test_endpoint("GET", "users/2", user3_access, 403, "bob", "403_First"))
test_results.append(test_endpoint("GET", "users/2", user3_access, 403, "bob", "404_First"))
test_results.append(test_endpoint("GET", "users/2", user3_access, 404, "bob", "Query_Focused"))

# User 3 Accessing their Orders Owned by User 2
test_results.append(test_endpoint("GET", "orders/1", user3_access, 403, "bob", "403_First"))
test_results.append(test_endpoint("GET", "orders/1", user3_access, 403, "bob", "404_First"))
test_results.append(test_endpoint("GET", "orders/1", user3_access, 404, "bob", "Query_Focused"))

# User 3 Accessing their own Order
test_results.append(test_endpoint("GET", "orders/4", user3_access, 200, "bob", "403_First"))
test_results.append(test_endpoint("GET", "orders/4", user3_access, 200, "bob", "404_First"))
test_results.append(test_endpoint("GET", "orders/4", user3_access, 200, "bob", "Query_Focused"))

# Admin tests should succeed
test_results.append(test_endpoint("GET", "users/2", admin_access, 200, "admin", "403_First"))
test_results.append(test_endpoint("GET", "users/2", admin_access, 200, "admin", "404_First"))
test_results.append(test_endpoint("GET", "users/2", admin_access, 200, "admin", "Query_Focused"))
test_results.append(test_endpoint("GET", "orders/2", admin_access, 200, "admin", "403_First"))
test_results.append(test_endpoint("GET", "orders/2", admin_access, 200, "admin", "404_First"))
test_results.append(test_endpoint("GET", "orders/2", admin_access, 200, "admin", "Query_Focused"))

# test if user 2 can access user 3's orders
test_results.append(test_endpoint("GET", "users/3/orders", user2_access, 403, "john", "403 *"))
test_results.append(test_endpoint("GET", "users/2/orders", user2_access, 200, "john", "403 *"))
test_results.append(test_endpoint("GET", "users/2/orders", user3_access, 403, "bob", "403 *"))
test_results.append(test_endpoint("GET", "users/3/orders", user3_access, 200, "bob", "403 *"))

# Test if vulnerable to Path Traversal
test_results.append(test_endpoint("GET", "users/2/../3", user2_access, 403, "john", "Path_Traversal"))

# Test if john can modify bob's order
test_results.append(test_endpoint("PUT", "orders/5", user2_access, 403, "john", "404 *", {"status": "Shipped"}))

# Test if bob can modify bob's order
test_results.append(test_endpoint("PUT", "orders/5", user3_access, 200, "bob", "404 *", {"status": "Shipped"}))

# Test if john can delete bob's order
test_results.append(test_endpoint("DELETE", "orders/4", user2_access, 403, "john", "404 *"))

# Test if bob can delete his own order (should succeed)
test_results.append(test_endpoint("DELETE", "orders/4", user3_access, 200, "bob", "404 *"))

# Test HTTP method confusion (trying to bypass with different HTTP methods)
test_results.append(test_endpoint("POST", "orders/4", user2_access, 405, "john"))

# Test parameter pollution (access via query param instead of path)
test_results.append(test_endpoint("GET", "orders?id=4", user2_access, 404, "john"))

# Test if regular user can modify admin-controlled resources
test_results.append(test_endpoint("PUT", "product/1", user2_access, 403, "john", "404 *", {"price": 0.01}))

print(tabulate(test_results, headers="keys", tablefmt="grid"))


def enumeration_test(patterns, endpoint, token):
    results = {}

    for pattern in patterns:
        status_codes = {}

        for i in range(0,4):
            url = f"{BASE_URL}/{endpoint}/{i}"
            if pattern == "404_First":
                url = f"{url}/alt-path"
            elif pattern == "Query_Focused":
                url = f"{url}/alt-path2"

            response = requests.get(
                url,
                headers={"Authorization": f"Bearer {token}"} # To get through current_user
            )
            status = response.status_code
            if status not in status_codes:
                status_codes[status] = []
            status_codes[status].append(i)

        results[pattern] = status_codes


    return results


def run_enumeration_tests(users_dict, patterns, endpoints):
    results = {}

    for endpoint in endpoints:
        print(f"Testing Enumeration: {endpoint}..")
        endpoint_results = {}

        for username, token in users_dict.items():
            pattern_results = enumeration_test(patterns, endpoint, token)
            endpoint_results[username] = pattern_results

        results[endpoint] = endpoint_results

    return results

users = {
    "admin": admin_access,
    "john": user2_access,
    "bob": user3_access
}

all_enum_results = run_enumeration_tests(
    users,
    ["403_First", "404_First", "Query_Focused"],
    ["users", "orders"]

)

def analyse_tests(enumeration_results):
    analysis = {}

    for resource_type, resource_data in enumeration_results.items():
        print(f"Resource type: {resource_type}")
        resource_analysis = {}

        for username, username_data in  resource_data.items():
            print(f"   Username: {username}")
            pattern_results = {}

            for pattern, patterns_data in username_data.items():
                # print(f"      Pattern: {patterns}")

                if 403 in patterns_data:
                    discovered_IDs_data = patterns_data[403]

                    valid_range = list(range(1,6)) ## EDIT IF LATER HAVE MORE IDs THAN THIS -- would have a more comprehensive function in an actual testing system
                    discovered_ID = []
                    for id in discovered_IDs_data:
                        if id in valid_range:
                            discovered_ID.append(id)

                    discovery_rate = len(discovered_ID) / len(valid_range) * 100
                    print(f"      {pattern} method as {username}: Could discover {len(discovered_ID)}/{len(valid_range)} resources = {discovery_rate}%")
                else:
                    print(f"      {pattern} method as {username}: Protected from Enumeration")
                    discovered_ID = []
                    discovery_rate = 0

                pattern_results[pattern] = {
                    "discovered_ids": discovered_ID,
                    "discovery_rate": discovery_rate
                }
        
            resource_analysis[username] = pattern_results

        analysis[resource_type] = resource_analysis

    return analysis

            

test_analysis = analyse_tests(all_enum_results)
print(json.dumps(analyse_tests(all_enum_results), indent=2))



print(json.dumps(all_enum_results, indent=2))
with open("test_results.json", "w") as f:
    f.write("//BOLA VULNERABILITIES LOG REPORT\n\n")

    f.write("//Endpoint Test Results (Table):\n")
    f.write(tabulate(test_results, headers="keys", tablefmt="grid"))

    f.write("\n\n//Endpoint Test Results (Raw):\n")
    json.dump(test_results, f, indent=2)

    f.write("\n\n\n\n//Enumeration Test Results:\n")
    json.dump(all_enum_results, f, indent=2)






