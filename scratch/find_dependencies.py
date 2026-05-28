import os
import sys

def main():
    sys.stdout.reconfigure(encoding='utf-8')
    root_dir = r"c:\Users\rohit\OneDrive\Desktop\mini_project"
    
    # We want to find all occurrences of imports from database.py
    results = []
    for root, dirs, files in os.walk(root_dir):
        for file in files:
            if file.endswith('.py') and not file == 'search_text.py' and not file == 'search_db.py':
                filepath = os.path.join(root, file)
                try:
                    with open(filepath, 'r', encoding='utf-8') as f:
                        for line_num, line in enumerate(f, 1):
                            if 'database' in line and ('import db' in line or 'import Database' in line):
                                results.append((filepath, line_num, line.strip()))
                except Exception:
                    pass
                    
    print(f"Found {len(results)} matches for database imports:")
    for filepath, line_num, line in results:
        print(f"  {filepath}:{line_num} -> {line}")

if __name__ == '__main__':
    main()
