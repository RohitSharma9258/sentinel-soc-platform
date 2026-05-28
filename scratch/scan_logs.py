import sys

def main():
    sys.stdout.reconfigure(encoding='utf-8')
    log_path = r"c:\Users\rohit\OneDrive\Desktop\mini_project\logs\intruder_system.log"
    with open(log_path, 'r', encoding='utf-8') as f:
        lines = f.readlines()
        
    print(f"Total lines in log file: {len(lines)}")
    
    # Check for lines from today: 2026-05-28
    today_lines = [line.strip() for line in lines if '2026-05-28' in line]
    print(f"Total lines from today: {len(today_lines)}")
    for line in today_lines[-20:]:
        print(line)

if __name__ == '__main__':
    main()
