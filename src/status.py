def processing(x):
    if (x=="dll"):
        print("Processing DLLs of provided memory-images....")
    if (x=="mal"):
        print("Processing memory-images for hidden malware entries...")
    if(x=="MMI"):
        print("Employing MMI Heurisitcs among the memory-images...")
    if(x=="vad"):
        print("Processing Virtual address descriptors of provided memory-images...")
    if(x=="anomaly"):
        print("Processing images for Anomaly detection...")
    if(x=="result"):
        print("Generating result....")


def message(x,lines):
    print(f"{x} has {lines} entries")

def Malware(x):
    print("---" * 20)
    print("RESULTS")
    print("---" * 20)
    if x:
        print("[POSITIVE] Found instances of fileless malware in the analyzed memory images!")
    else:
        return("")