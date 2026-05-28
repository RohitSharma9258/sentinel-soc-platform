with open("app.py", "r", encoding="utf-8") as f:
    lines = f.readlines()

for idx, line in enumerate(lines):
    if "@require_" in line or "@app.route" in line:
        # Print the route and the decorator right next to/after it
        print(f"Line {idx+1}: {line.strip()}")
