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

def test_endpoint(pattern, endpoint, token, expected_status, username):
    start_time = time.time()
    url = f"{BASE_URL}/{endpoint}"
    if pattern == "404_First":
        url = f"{url}/alt-path"
    elif pattern == "Query_Focused":
        url = f"{url}/alt-path2"

    response = requests.get(
        url,
        headers={"Authorization": f"Bearer {token}"} # To get through current_user
    )
    duration = time.time() - start_time

    result = {
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
test_results.append(test_endpoint("403_First", "users/2", user2_access, 200, "john"))
test_results.append(test_endpoint("404_First", "users/2", user2_access, 200, "john"))
test_results.append(test_endpoint("Query_Focused", "users/2", user2_access, 200, "john"))

# User 2 Accessing User 3's - Should Fail
test_results.append(test_endpoint("403_First", "users/3", user2_access, 403, "john"))
test_results.append(test_endpoint("404_First", "users/3", user2_access, 403, "john"))
test_results.append(test_endpoint("Query_Focused", "users/3", user2_access, 404, "john"))

# User 3 Accessing their Own Order - Should Succeed 
test_results.append(test_endpoint("403_First", "orders/1", user2_access, 200, "john"))
test_results.append(test_endpoint("404_First", "orders/1", user2_access, 200, "john"))
test_results.append(test_endpoint("Query_Focused", "orders/1", user2_access, 200, "john"))

# User 2 Accessing their User 3's Order
test_results.append(test_endpoint("403_First", "orders/4", user2_access, 403, "john"))
test_results.append(test_endpoint("404_First", "orders/4", user2_access, 403, "john"))
test_results.append(test_endpoint("Query_Focused", "orders/4", user2_access, 404, "john"))

# User 3 Accessing User 2's Access - Should Fail
test_results.append(test_endpoint("403_First", "users/2", user3_access, 403, "bob"))
test_results.append(test_endpoint("404_First", "users/2", user3_access, 403, "bob"))
test_results.append(test_endpoint("Query_Focused", "users/2", user3_access, 404, "bob"))

# User 3 Accessing their User1's Order
test_results.append(test_endpoint("403_First", "orders/1", user3_access, 403, "bob"))
test_results.append(test_endpoint("404_First", "orders/1", user3_access, 403, "bob"))
test_results.append(test_endpoint("Query_Focused", "orders/1", user3_access, 404, "bob"))

# User 3 Accessing their own Order
test_results.append(test_endpoint("403_First", "orders/4", user3_access, 200, "bob"))
test_results.append(test_endpoint("404_First", "orders/4", user3_access, 200, "bob"))
test_results.append(test_endpoint("Query_Focused", "orders/4", user3_access, 200, "bob"))

# Admin tests should succeed
test_results.append(test_endpoint("403_First", "users/2", admin_access, 200, "admin"))
test_results.append(test_endpoint("404_First", "users/2", admin_access, 200, "admin"))
test_results.append(test_endpoint("Query_Focused", "users/2", admin_access, 200, "admin"))
test_results.append(test_endpoint("403_First", "orders/2", admin_access, 200, "admin"))
test_results.append(test_endpoint("404_First", "orders/2", admin_access, 200, "admin"))
test_results.append(test_endpoint("Query_Focused", "orders/2", admin_access, 200, "admin"))

print(tabulate(test_results, headers="keys", tablefmt="grid"))



def enumeration_test(patterns, endpoint, token):
    results = {}

    for pattern in patterns:
        status_codes = {}

        for i in range(-1,8):
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



# users_user2_enumeration = enumeration_test(
#     ["403_First", "404_First", "Query_Focused"],
#     "users",
#     user2_access
# )

# users_user3_enumeration = enumeration_test(
#     ["403_First", "404_First", "Query_Focused"],
#     "users",
#     user3_access
# )

# users_admin_enumeration = enumeration_test(
#     ["403_First", "404_First", "Query_Focused"],
#     "users",
#     admin_access
# )

# orders_user2_enumeration = enumeration_test(
#     ["403_First", "404_First", "Query_Focused"],
#     "orders",
#     user2_access
# )

# orders_user3_enumeration = enumeration_test(
#     ["403_First", "404_First", "Query_Focused"],
#     "orders",
#     user3_access
# )

# orders_admin_enumeration = enumeration_test(
#     ["403_First", "404_First", "Query_Focused"],
#     "orders",
#     admin_access
# )

print(json.dumps(all_enum_results, indent=2))
with open("test_results.json", "w") as f:
    f.write("//BOLA VULNERABILITIES LOG REPORT\n\n")

    f.write("//Endpoint Test Results (Table):\n")
    f.write(tabulate(test_results, headers="keys", tablefmt="grid"))

    f.write("\n\n//Endpoint Test Results (Raw):\n")
    json.dump(test_results, f, indent=2)

    f.write("\n\n\n\n//Enumeration Test Results:\n")
    json.dump(all_enum_results, f, indent=2)






