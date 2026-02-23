import sys
import zipfile
import json
import signal

# Handle SIGPIPE
signal.signal(signal.SIGPIPE, signal.SIG_DFL)

if len(sys.argv) < 2:
    sys.exit(1)

zip_path = sys.argv[1]
year_filter = sys.argv[2] if len(sys.argv) > 2 else None

try:
    with zipfile.ZipFile(zip_path, 'r') as z:
        # Get list of files first
        all_files = z.namelist()
        target_files = []

        for filename in all_files:
            # Check extension
            if not filename.endswith('.json'):
                continue

            # Check year filter (e.g., "2023" in "cvelistV5-main/cves/2023/1xxx/CVE-2023-1234.json")
            if year_filter:
                if f'/cves/{year_filter}/' not in filename:
                    continue

            target_files.append(filename)

        # Sort to ensure deterministic processing order
        target_files.sort()

        for filename in target_files:
            try:
                with z.open(filename) as f:
                    content = f.read().decode('utf-8')
                    # Parse and re-dump to ensure single-line JSON
                    data = json.loads(content)
                    print(json.dumps(data))
                    sys.stdout.flush()
            except Exception as e:
                # Log to stderr but continue processing other files
                sys.stderr.write(f"Error processing {filename}: {str(e)}\n")
                continue

except Exception as e:
    sys.stderr.write(str(e))
    sys.exit(1)
