def detection_fidelity_score(results: list[dict]) -> float:
    if not results:
        return 0.0
    detected = sum(1 for item in results if item.get("result") in {"Blocked", "Detected"})
    return round((detected / len(results)) * 100, 2)
