import re

def main():
    filepath = r"C:\Users\rohit\.gemini\antigravity-ide\brain\dc161bca-7483-45bb-a8ce-cd6be5399ebc\.system_generated\steps\503\content.md"
    
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()
        
    # Search for workspace/.*\.json
    matches = re.findall(r'workspace/[^\s"\']+\.json', content)
    print("Found JSON evidence paths:")
    for m in set(matches):
        print(f"  - {m}")
        
    # Search for cdn-butterfly-new.betterbugs.io
    cdn_matches = re.findall(r'https://cdn-butterfly-new\.betterbugs\.io/workspace/[^\s"\']+', content)
    print("Found CDN URLs:")
    for cm in set(cdn_matches):
        print(f"  - {cm}")

if __name__ == '__main__':
    main()
