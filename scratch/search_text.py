import os
import sys

def search_files(directory, query):
    results = []
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith(('.js', '.py', '.html', '.css')):
                filepath = os.path.join(root, file)
                try:
                    with open(filepath, 'r', encoding='utf-8') as f:
                        for line_num, line in enumerate(f, 1):
                            if query.lower() in line.lower():
                                results.append((filepath, line_num, line.strip()))
                except Exception:
                    pass
    return results

def main():
    sys.stdout.reconfigure(encoding='utf-8')
    query = "Failed to load AI analysis"
    print(f"Searching for '{query}'...")
    results = search_files(r"c:\Users\rohit\OneDrive\Desktop\mini_project", query)
    print(f"Found {len(results)} occurrences:")
    for filepath, line_num, line in results:
        print(f"  {filepath}:{line_num} -> {line}")

if __name__ == '__main__':
    main()
