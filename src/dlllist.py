import re
debug = 0 

def parse_dlllist(dlllist_output):
    dll_set = set()
    lines = dlllist_output.split('\n')

    for line in lines:
        # Use a regular expression to extract the DLL name from the line
        matches = re.findall(r'\b\w+\.dll\b', line, re.IGNORECASE)
        if matches:
            for dll_name in matches:
                dll_set.add(dll_name)

    return dll_set

def compare_dlllist(dlllist_output1, dlllist_output2):
    dlllist1 = parse_dlllist(dlllist_output1)
    dlllist2 = parse_dlllist(dlllist_output2)

    print(dlllist1)
    print(dlllist2)
    diff_dlls = dlllist1 - dlllist2
    for dll in diff_dlls:
        if(debug):
            print(f"DLL present in first output but not in second: {dll}")
    return diff_dlls


