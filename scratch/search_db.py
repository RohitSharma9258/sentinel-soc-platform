import sys

def main():
    sys.stdout.reconfigure(encoding='utf-8')
    with open('database.py', 'r', encoding='utf-8') as f:
        content = f.read()
        
    import re
    matches = list(re.finditer('detector', content, re.IGNORECASE))
    print(f"Total matches for 'detector' in database.py: {len(matches)}")
    for m in matches:
        start = max(0, m.start() - 100)
        end = min(len(content), m.end() + 100)
        print(f"  [{m.start()}]: ... {content[start:end].replace('\n', ' ')} ...")
        print("-" * 50)

if __name__ == '__main__':
    main()
