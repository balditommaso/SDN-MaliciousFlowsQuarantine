import requests
import json
from six.moves import input

ROOT_REST_API = "http://127.0.0.1:8080/mfq"


def mark_flow(client, server):
    api_url = ROOT_REST_API + "/flows/json"
    payload = {"client": client, "server": server}
    response = requests.post(api_url, json=payload)
    print(response.text)
    
    
def unmark_flow():
    print("\n\n# ---------------------------------------------------------------------------- #\n" + 
            "#                                   UNMARK                                     #\n" +
            "# ---------------------------------------------------------------------------- #\n\n")
    flow = get_flow()
    
    # check flow
    if flow == -1:
        print("Error: Not valid index!")
        return
    
    # check mode
    print("\nSelect the mode:\n\n1.\tclear\n\n2.\tflush\n")
    index = input(">> ")
    try:
        index = int(index)
    except ValueError:
        print("Error: Not valid index!")
        return
    if index != 1 and index != 2:
        print("Error: Not valid index!")
        return
    
    mode = "clear"
    if index == 2:
        mode = "flush"
        
    # send REST request
    api_url = ROOT_REST_API + "/flows/json"
    payload = {"client": flow['clientIP'], "server": flow['serverIP'], "mode": mode}
    response = requests.post(api_url, json=payload)
    print(response.text)
    
    
def get_flow():
    api_url = ROOT_REST_API + "/flows/json"
    response = requests.get(api_url)
    flows = json.loads(response.text)
    for index, flow in enumerate(flows):
        print(str(index) + ".\t[ " + flow['clientIP'] + " -> " + flow['serverIP'] + "] size = " + str(flow['bufferSize']))
        
    print("\nSelect the flow (index):\n\n")
    index = input(">> ")
    try:
        index = int(index)
    except ValueError:
        print("Error: Not valid index!")
        return -1
    
    if index < 0 or index >= len(flows):
        print("Error: Not valid index!")
        return -1
    
    return flows[index]


def change_size():
    print("\n\n# ---------------------------------------------------------------------------- #\n" + 
            "#                              CHANGE SIZE                                     #\n" +
            "# ---------------------------------------------------------------------------- #\n\n")
    flow = get_flow()
    
    # check flow
    if flow == -1:
        print("Error: Not valid index!")
        return
    
    print("\nSelect the new size:\n\n")
    size = input(">> ")
    try:
        size = int(size)
    except ValueError:
        print("Error: Not valid index!")
        return -1
    
    if size < 0 or size >= 10000:
        print("Error: Not valid index!")
        return -1
    
    
    api_url = ROOT_REST_API + "/quarantine/" + flow["id"] + "/json"
    payload = {"size": size}
    response = requests.post(api_url, json=payload)
    print(response.text)

    
def get_quarantine_packets():
    print("\n\n# ---------------------------------------------------------------------------- #\n" + 
            "#                              QUARANTINE                                      #\n" +
            "# ---------------------------------------------------------------------------- #\n\n")
    flow = get_flow()
    # check flow
    if flow == -1:
        print("Error: Not valid index!")
        return
    api_url = ROOT_REST_API + "/quarantine/" + flow["id"] + "/json"
    response = requests.get(api_url)
    print("\n\n>> Buffer = " + response.text + "/" + str(flow['bufferSize']))
    
    
def print_help():
    print("\n\n# ---------------------------------------------------------------------------- #\n" + 
          "#                                     HELP                                     #\n" +
          "# ---------------------------------------------------------------------------- #\n\n")
    
    print("\t-\tquit\t\t\t\tExit from the application. \n")
    print("\t-\tmark <client IP> <server IP>\tMark a flow as malicious. \n")
    print("\t-\tunmark\t\t\t\tUnmark a flow, mode can be 'clear' or 'flush'. \n")
    print("\t-\tsize\t\t\t\tChange the size of the quarantine buffer of the flow.\n")
    print("\t-\tquarantine\t\t\tGet the number of buffered packets. \n")
    
    
def main():
    print("\n\n# ---------------------------------------------------------------------------- #\n" + 
          "#                     SDN-based Malicious flows quarantine                     #\n" +
          "# ---------------------------------------------------------------------------- #")
    while (True): 
        print("\n# ---------------------------------------------------------------------------- #\n")   
        # ask the input
        print('Type a command: ("help" for info)\n\n')
        command = input(">> ").split()
        
        # dispatch the function
        if command[0] == "help":
            print_help()
        
        elif command[0] == "quit":
            return
        elif command[0] == "mark":
            if len(command) == 3:
                mark_flow(command[1], command[2])
            else:
                print("Error: not valid command!")
        elif command[0] == "unmark":
            unmark_flow()
        elif command[0] == "size":
            change_size()
        elif command[0] == "quarantine":
            get_quarantine_packets()
        else:
            print("Error: not valid command!")


if __name__ == '__main__':
    main()
    