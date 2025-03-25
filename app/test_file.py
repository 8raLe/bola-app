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

    user_id = response.json().get("user_id")
    return user_id

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

def test_endpoint(method, endpoint, user_id, username, description, data=None):
    start_time = time.time()

    url = f"{BASE_URL}/{endpoint}"

    if method == "GET":
        response = requests.get(url)
    elif method == "PUT":
        response = requests.put(url, json=data)
        if response.status_code == 422:
            response = requests.put(url, params=data)
    elif method == "DELETE":
        response = requests.delete(url)
    elif method == "POST":
        response = requests.post(url)
    else:
        response = requests.get(url)
        print(f"!!!!! Error with {method} @ {endpoint} | {token}!")
    
    duration = time.time() - start_time

    vulnerability = match_which_vulnerability(method, endpoint)

    expected_status = 200

    result = {
        "vulnerability": vulnerability,
        "method": method,
        "endpoint": endpoint,
        "url": url,
        "username": username,
        "status_code": response.status_code,
        "response_time": round(duration * 1000, 2),
        "expected_status": expected_status,
        "passed": response.status_code == expected_status,
        "description": description
    }

    return result


test_results.append(test_endpoint("GET", "users/2", user2_access, "john", "user2 accessing their own data")) # user2 accessing their own data
test_results.append(test_endpoint("GET", "users/3", user2_access, "john", "user2 accessing user3's data")) # user2 accessing user3's data
test_results.append(test_endpoint("GET", "orders", user2_access, "john", "user2 accessing all orders")) # user2 accessing all orders
test_results.append(test_endpoint("GET", "orders/1", user2_access, "john", "user2 accessing details of his own order")) #user2 accessing details of his own order
test_results.append(test_endpoint("GET", "users/3/orders", user2_access, "john", "user2 accessing the orders of user3")) # user2 accessing the orders of user3
test_results.append(test_endpoint("PUT", "orders/3", user2_access, "john", "user2 modify user3's order", {"status": "Cancelled"})) # user2 modify user3's order
test_results.append(test_endpoint("PUT", "product/1", user2_access, "john", "user2 changing details of a product", {"price": 0.01})) # user2 changing details of a product
test_results.append(test_endpoint("DELETE", "orders/3", user2_access, "john", "user2 delete user3 order")) #user2 delete user3 order

print(tabulate(test_results, headers="keys", tablefmt="grid"))

with open("vulnerable_test_results.json", "w") as f:
    f.write("//BOLA VULNERABILITY PRE-PATCH TESTS\n\n")
    f.write(tabulate(test_results, headers="keys", tablefmt="grid"))
    f.write("\n\n//Raw Results\n")
    json.dump(test_results, f, indent=2)