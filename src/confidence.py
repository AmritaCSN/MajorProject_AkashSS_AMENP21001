class Confidence:
    def __init__(self):
        self.decisions = []

    def add_decision(self, decision, confidence):
        self.decisions.append((decision, confidence))

    def calculate_average_confidence(self):
        total_confidence = sum(confidence for _, confidence in self.decisions)
        average_confidence = total_confidence / len(self.decisions) if self.decisions else 0.0
        return average_confidence

    def get_total_confidence(self):
        total_confidence = sum(confidence for _, confidence in self.decisions)
        return total_confidence


def confidence_score(x1,x2,s):
    score = s
    diff = max(x1,x2) - min(x1,x2)
    threshold = 0.05 * min(x1,x2)
    if(diff > threshold and diff > 20):
        score += 0.15 * diff
    else:
        score += 1.5 * diff

    return min(100,score)
