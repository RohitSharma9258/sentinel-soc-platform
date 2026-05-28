import sys

def main():
    sys.stdout.reconfigure(encoding='utf-8')
    with open('app.py', 'r', encoding='utf-8') as f:
        lines = f.readlines()
    
    print("Searching in app.py...")
    for idx, line in enumerate(lines, 1):
        if 'ai-predictions' in line or 'ai_predictions' in line:
            print(f"Line {idx}: {line.strip()}")

if __name__ == '__main__':
    main()
