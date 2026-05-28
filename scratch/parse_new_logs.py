import json

def main():
    filepath = r"C:\Users\rohit\.gemini\antigravity-ide\brain\dc161bca-7483-45bb-a8ce-cd6be5399ebc\.system_generated\steps\511\content.md"
    
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()
        
    start_idx = content.find('{')
    data = json.loads(content[start_idx:])
    
    console_logs = data.get("console", [])
    network_logs = data.get("network", [])
    steps = data.get("steps", [])
    
    print(f"Total console items: {len(console_logs)}")
    print(f"Total network items: {len(network_logs)}")
    print(f"Total steps: {len(steps)}")
    
    print("\n=== First 15 console events ===")
    for idx, c in enumerate(console_logs[:15]):
        print(f"[{idx}]: type={c.get('type')} | level={c.get('level')} | args={c.get('args')}")
        
    print("\n=== First 10 network events ===")
    for idx, n in enumerate(network_logs[:10]):
        print(f"[{idx}]: {n.get('method')} {n.get('url')} | status: {n.get('status')} | statusText: {n.get('statusText')}")
        
    print("\n=== Steps ===")
    for idx, s in enumerate(steps):
        print(f"[{idx}]: type={s.get('type')} | action={s.get('action')} | text={s.get('text')} | target={s.get('selector')}")

if __name__ == '__main__':
    main()
