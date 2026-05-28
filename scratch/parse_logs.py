import json
import sys

def main():
    sys.stdout.reconfigure(encoding='utf-8')
    filepath = r"C:\Users\rohit\.gemini\antigravity\brain\8696c718-7c42-4001-af09-1ee901936a5a\.system_generated\steps\103\content.md"
    
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Check if "/ai-predictions" is in the content
    count = content.count('/ai-predictions')
    print("Count of '/ai-predictions':", count)
    
    import re
    for m in re.finditer('/ai-predictions', content):
        start = max(0, m.start() - 100)
        end = min(len(content), m.end() + 200)
        print(f"  [{m.start()}]: ... {content[start:end].replace('\n', ' ')} ...")
        print("-" * 50)

if __name__ == '__main__':
    main()
