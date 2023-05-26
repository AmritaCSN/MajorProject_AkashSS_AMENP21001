def count_lines(text):
    l = text.splitlines()
    return len(l)


def find_line_count_difference(text1, text2):
    l1 = text1.splitlines()
    l2 = text2.splitlines()

    count_diff = len(l1) - len(l2)

    return count_diff

def detect_anomalies(text1, text2):
    l1 = text1.splitlines()
    l2 = text2.splitlines()


    min_lines = min(len(l1), len(l2))

    anomalies = []
    for i in range(min_lines):
        if l1[i] != l2[i]:
            anomalies.append(f"Anomaly detected at line {i+1}: '{l1[i]}' != '{l2[i]}'")

    if len(l1) > min_lines:
        for i in range(min_lines, len(l1)):
            anomalies.append(f"Additional line detected in text1 at line {i+1}: '{l1[i]}'")

    if len(l2) > min_lines:
        for i in range(min_lines, len(l2)):
            anomalies.append(f"Additional line detected in text2 at line {i+1}: '{l2[i]}'")

    return anomalies
