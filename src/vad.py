def parse_vadinfo(vadinfo_output):
    lines = vadinfo_output.split('\n')
    vad_dict = {}

    for line in lines:
        parts = line.split()

        if len(parts) == 13:
            start_addr = parts[2]
            end_addr = parts[3]
            pid = parts[1]

            if pid not in vad_dict:
                vad_dict[pid] = []

            vad_dict[pid].append((start_addr, end_addr))

    return vad_dict

def compare_vadinfo(vadinfo_output1, vadinfo_output2):
    vadinfo1 = parse_vadinfo(vadinfo_output1)
    vadinfo2 = parse_vadinfo(vadinfo_output2)
    x = 0

    for pid in vadinfo1:
        if pid in vadinfo2:
            freed_vad_ranges = set(vadinfo1[pid]) - set(vadinfo2[pid])
            x = len(freed_vad_ranges)

            for range in freed_vad_ranges:
                print(f"PID {pid}: VAD range freed: {range}")
    return x
