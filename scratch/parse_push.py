import sys
import re

def main():
    sys.stdout.reconfigure(encoding='utf-8')
    with open(r'C:\Users\rohit\.gemini\antigravity\brain\8696c718-7c42-4001-af09-1ee901936a5a\.system_generated\steps\38\content.md', 'r', encoding='utf-8') as f:
        text = f.read()
    
    # Search for all strings starting with workspace/
    matches = re.findall(r'workspace/[a-zA-Z0-9_/.-]+', text)
    print("Found matches starting with workspace/:")
    for m in set(matches):
        print("  ", m)

if __name__ == '__main__':
    main()
