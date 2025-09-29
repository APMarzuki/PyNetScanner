import sqlite3
import sys

DB_FILE = "pynyscanner.db"


def check_database():
    """Connects to the database and prints summaries of the stored data."""
    print(f"[*] Attempting to connect to database: {DB_FILE}")
    conn = None
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()

        # 1. Check Scan Sessions
        cursor.execute("SELECT COUNT(*), MAX(scan_start_time) FROM scan_sessions")
        session_count, latest_scan = cursor.fetchone()

        print("\n--- Scan Sessions Summary ---")
        if session_count > 0:
            print(f"[+] Total scan sessions found: {session_count}")
            print(f"[+] Latest scan started at: {latest_scan}")
        else:
            print("[-] No scan sessions found in the database.")

        # 2. Check File Records
        cursor.execute("SELECT COUNT(*), COUNT(DISTINCT hash_sha256) FROM files")
        file_count, unique_hash_count = cursor.fetchone()

        print("\n--- File Records Summary ---")
        if file_count > 0:
            print(f"[+] Total file records found: {file_count}")
            print(f"[+] Total unique hashes stored: {unique_hash_count}")
        else:
            print("[-] No file records found in the database.")

        # 3. Check for Actual Data in the 'files' table (First 5 records)
        print("\n--- Sample File Records (First 5) ---")
        cursor.execute("SELECT path, filename, hash_sha256 FROM files LIMIT 5")
        sample_files = cursor.fetchall()

        if sample_files:
            for path, filename, hash_sha256 in sample_files:
                print(f"  Path: {path}")
                print(f"  Filename: {filename}")
                print(f"  Hash: {hash_sha256[:15]}...")
                print("-" * 10)
        else:
            print("  No sample data to display.")


    except sqlite3.Error as e:
        print(f"\n[!!!] Database connection or query error: {e}", file=sys.stderr)
        print("    -> Make sure the file scanner has run at least once.")
    except Exception as e:
        print(f"\n[!!!] An unexpected error occurred: {e}", file=sys.stderr)
    finally:
        if conn:
            conn.close()
            print("\nDatabase connection closed.")


if __name__ == "__main__":
    check_database()