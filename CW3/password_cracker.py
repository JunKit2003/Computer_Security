import json
import subprocess
import os
import time
import re
from datetime import datetime
import sys # Needed for sys.exit

# --- Configuration ---
HASHCAT_FOLDER_NAME = "hashcat-6.2.6" 
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__)) 
HASHCAT_DIR = os.path.join(SCRIPT_DIR, HASHCAT_FOLDER_NAME)
HASHCAT_PATH = os.path.join(HASHCAT_DIR, "hashcat.exe")
WORDLIST_PATH = os.path.join(SCRIPT_DIR, "wordlist.txt")
PASSWORD_FILE = os.path.join(SCRIPT_DIR, "password_storage.json") 
HASH_FILE = os.path.join(SCRIPT_DIR, "hash_to_crack.txt") 
OUTPUT_FILE = os.path.join(SCRIPT_DIR, "cracked_results.txt")    
REPORT_FILE = os.path.join(SCRIPT_DIR, "cracking_report.txt")    

# --- NEW FUNCTION: Load users and prompt for selection ---
def select_target_user():
    """Loads users from JSON, prompts user to select one, and returns the username and hash."""
    print(f"[+] Loading users from {os.path.basename(PASSWORD_FILE)}...")
    
    try:
        if not os.path.exists(PASSWORD_FILE):
             print(f"[!] Error: Password file not found at {PASSWORD_FILE}")
             return None, None

        with open(PASSWORD_FILE, "r") as f:
            try:
                password_data = json.load(f)
            except json.JSONDecodeError as e:
                print(f"[!] Error decoding JSON from {os.path.basename(PASSWORD_FILE)}: {e}")
                return None, None
        
        if not password_data:
            print(f"[!] Error: No users found in {os.path.basename(PASSWORD_FILE)}.")
            return None, None

        print("\nAvailable users:")
        usernames = list(password_data.keys())
        for i, name in enumerate(usernames):
            print(f"{i + 1}. {name}")

        while True:
            try:
                choice = input(f"Enter the number or name of the user to crack (1-{len(usernames)}): ")
                target_username = None
                # Check if input is a number
                if choice.isdigit():
                    index = int(choice) - 1
                    if 0 <= index < len(usernames):
                        target_username = usernames[index]
                    else:
                        print("[!] Invalid number selection.")
                # Check if input matches a username directly
                elif choice in usernames:
                    target_username = choice
                else:
                     print(f"[!] Username '{choice}' not found.")

                if target_username:
                    target_hash = password_data[target_username]
                    # Validate hash format before returning
                    if isinstance(target_hash, str) and target_hash.startswith(("$2a$", "$2b$", "$2y$")):
                        print(f"[+] Selected user '{target_username}' for cracking.")
                        return target_username, target_hash
                    else:
                        print(f"[!] Error: Invalid hash format stored for user '{target_username}'. Cannot proceed.")
                        return None, None # Indicate error
            except ValueError:
                print("[!] Invalid input. Please enter a number or username.")
            except KeyboardInterrupt:
                 print("\n[!] User cancelled selection.")
                 return None, None # Indicate cancellation

    except Exception as e:
        print(f"[!] Error during user selection: {e}")
        return None, None

# --- NEW FUNCTION: Prepare hash file for a single hash ---
def prepare_single_hash_file(target_hash):
    """Writes the selected single hash to the temporary file for hashcat."""
    try:
        with open(HASH_FILE, "w") as f_out:
            f_out.write(f"{target_hash}\n")
        print(f"[+] Target hash written to {os.path.basename(HASH_FILE)}")
        return True
    except Exception as e:
        print(f"[!] Error writing single hash to {os.path.basename(HASH_FILE)}: {e}")
        return False

# --- MODIFIED FUNCTION: Run Hashcat ---
def run_hashcat_dictionary_attack():
    """Runs hashcat with dictionary attack, ignoring potfile, on the single hash file."""
    print("\n[+] Starting dictionary attack with hashcat...")
    print(f"[+] Using wordlist: {os.path.basename(WORDLIST_PATH)}")
    print(f"[+] Hashcat executable: {HASHCAT_PATH}")
    print(f"[+] Target hash file: {os.path.basename(HASH_FILE)}")
    print("[+] Allowing Hashcat to auto-select best device (GPU/CUDA expected).")
    print("[+] Potfile (--potfile-disable) is DISABLED for this run.") # Notify user

    # Pre-run Checks (simplified as hash file check is done after selection)
    if not os.path.exists(HASHCAT_PATH):
        return 0, "", f"Hashcat executable not found: {HASHCAT_PATH}"
    if not os.path.exists(WORDLIST_PATH):
        return 0, "", f"Wordlist not found: {WORDLIST_PATH}"
    if not os.path.exists(HASH_FILE) or os.path.getsize(HASH_FILE) == 0:
         return 0, "", f"Target hash file '{os.path.basename(HASH_FILE)}' missing or empty."

    # Remove previous cracked results file
    if os.path.exists(OUTPUT_FILE):
        try:
            os.remove(OUTPUT_FILE)
            print(f"[+] Removed existing output file: {os.path.basename(OUTPUT_FILE)}")
        except Exception as e:
            print(f"[!] Warning: Could not remove {os.path.basename(OUTPUT_FILE)}: {e}")

    # --- Hashcat Command MODIFIED ---
    cmd = [
        HASHCAT_PATH,
        "--potfile-disable", # <--- ADDED: Ignore previously cracked hashes
        "-m", "3200",        
        "-a", "0",           
        "-o", OUTPUT_FILE,   
        "--status",          
        "-w", "3",           
        HASH_FILE,           # File now contains only the single target hash
        WORDLIST_PATH        
    ]

    print(f"[+] Running command: {' '.join(cmd)}")
    hashcat_working_dir = HASHCAT_DIR
    print(f"[+] Setting Hashcat working directory to: {hashcat_working_dir}") 
    
    start_time = time.time()
    process = None
    stdout = ""
    stderr = ""

    try:
        process = subprocess.Popen(cmd, 
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, 
                                   text=True, encoding='utf-8', errors='ignore',
                                   cwd=hashcat_working_dir) 

        print("[+] Hashcat process started. Waiting for completion... Press Ctrl+C to interrupt.")
        stdout, stderr = process.communicate() 
        end_time = time.time()
        elapsed_time = end_time - start_time
        
        if stderr and "./OpenCL/: No such file or directory" not in stderr: # Ignore the OpenCL dir warning
            print("\n HASHCAT STDERR ".center(60, "=")); print(stderr); print("=" * 60)
        elif "./OpenCL/: No such file or directory" in stderr:
             print("\n(Ignoring non-fatal stderr: './OpenCL/: No such file or directory')") # Explicitly ignore

        print("\n HASHCAT STDOUT ".center(60, "=")); print(stdout if stdout else "(No stdout)"); print("=" * 60)
        return elapsed_time, stdout, stderr

    # Keep KeyboardInterrupt and other exception handling same as before
    except KeyboardInterrupt:
        print("\n[!] Attack stopped by user (Ctrl+C).")
        # ... (termination logic remains the same) ...
        return elapsed_time, stdout + "\n\n[Attack stopped by user]", stderr
    except FileNotFoundError:
        error_msg = f"FATAL ERROR: Command not found. Check HASHCAT_PATH: {HASHCAT_PATH}"
        print(f"[!] {error_msg}")
        return 0, "", error_msg
    except Exception as e:
        error_msg = f"Error running hashcat: {e}"
        print(f"[!] {error_msg}")
        # ... (stderr capturing during exception remains same) ...
        return 0, stdout, f"{error_msg}\n{stderr}"

# --- MODIFIED FUNCTION: Parse Results ---
def parse_results(target_username, elapsed_time, stdout, stderr, total_hashes_attempted=1): # Added target_username
    """Parse hashcat output and generate the final report for the single targeted hash."""
    print("\n[+] Analyzing results...")

    error_message = ""
    # Simplified error checking since we expect the OpenCL dir warning
    if "No devices found/left" in stderr or "No CUDA devices found" in stderr:
        error_message = "Hashcat Error: No usable compute devices found. Check drivers (NVIDIA/CUDA) and `hashcat -I`."
    # Add other critical error checks as needed...
    elif "Cannot read input file" in stderr:
         error_message = f"Hashcat Error: Cannot read an input file. Check paths/permissions."
    # Add a check for successful completion message in stdout
    elif "INFO: All hashes found as potfile" in stdout and "--potfile-disable" in ' '.join(sys.argv): # Check if potfile message appears even when disabled (shouldn't happen often)
         print("[!] Warning: Hashcat reported potfile hit even with --potfile-disable. This is unexpected.")
    elif elapsed_time < 2 and "Recovered" not in stdout and "Exhausted" not in stdout and "Stopped" not in stdout:
         # Check for very quick exit without success or dictionary exhaustion
         error_message = f"Hashcat Error: Exited quickly without clear result. Check STDERR/STDOUT above. Stderr snippet: {stderr.strip()[:100]}..."

    if error_message:
        print(f"[!] Potential Hashcat Error Detected: {error_message}")

    cracked_password = None
    num_cracked = 0
    cracked_file_exists = os.path.exists(OUTPUT_FILE)
    if cracked_file_exists:
        try:
            with open(OUTPUT_FILE, "r", encoding='utf-8', errors='ignore') as f:
                for line in f: # Should only be one line if cracked
                    line = line.strip()
                    if not line: continue
                    parts = line.split(':', 1)
                    if len(parts) == 2:
                        _, cracked_password = parts # Get the password part
                        num_cracked = 1
                        break # Found it
        except Exception as e:
            print(f"[!] Warning: Could not read {os.path.basename(OUTPUT_FILE)}: {e}")

    # --- Calculate Metrics ---
    hours, remainder = divmod(elapsed_time, 3600)
    minutes, seconds = divmod(remainder, 60)
    time_str = f"{int(hours)}h {int(minutes)}m {seconds:.2f}s"
    success_rate = 100.0 if num_cracked > 0 else 0.0

    speed = "Unknown" # Extract speed (same logic as before)
    speed_lines = [line for line in stdout.splitlines() if "Speed" in line and "Avg" not in line] 
    if speed_lines:
         match = re.search(r"Speed\.#\d+\.*:\s*([\d\.]+\s*[kMGT]?H/s)", speed_lines[-1])
         if match: speed = match.group(1).strip()

    # --- Generate Report File ---
    print(f"[+] Generating report file: {os.path.basename(REPORT_FILE)}")
    try:
        with open(REPORT_FILE, "w", encoding='utf-8') as f:
            f.write("=== PASSWORD CRACKING REPORT ===\n\n")
            f.write(f"Date Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Target User: {target_username}\n") 
            f.write(f"Tool Used: Hashcat ({HASHCAT_FOLDER_NAME})\n")
            f.write(f"Attack Mode: Dictionary Attack (-a 0)\n")
            f.write(f"Target Hash Type: bcrypt (-m 3200)\n")
            f.write(f"Potfile Usage: Disabled (--potfile-disable)\n") 
            f.write(f"Compute Device: Auto-Selected \n") 
            try: wordlist_size_mb = os.path.getsize(WORDLIST_PATH)/1024/1024
            except OSError: wordlist_size_mb = -1
            f.write(f"Wordlist Used: {os.path.basename(WORDLIST_PATH)} ({wordlist_size_mb:.2f} MB)\n\n") 

            if error_message:
                 f.write(f"!!! HASHCAT ERROR DETECTED !!!\n{error_message}\nProcess may have failed.\n\n")
            elif "Stopped by user" in stdout:
                 f.write("!!! PROCESS INTERRUPTED BY USER !!!\nResults below reflect progress until interruption.\n\n")

            f.write("== CRACKING RESULTS ==\n")
            f.write(f"Target Hash Attempted: 1 (for user '{target_username}')\n")
            f.write(f"Successfully Cracked: {num_cracked}\n")
            f.write(f"Success Rate: {success_rate:.1f}%\n")
            f.write(f"Total Time Elapsed: {time_str}\n")
            f.write(f"Approximate Cracking Speed: {speed}\n")
            f.write(f"Output File Generated: '{os.path.basename(OUTPUT_FILE)}' (" + ("Exists" if cracked_file_exists else "Not Found") + ")\n\n")

            f.write("== CRACKED PASSWORD ==\n") # Changed section title
            if cracked_password:
                 f.write(f"- Cracked Password for '{target_username}': {cracked_password}\n") 
            elif elapsed_time > 2 and "Exhausted" in stdout: # Check if dictionary finished without finding it
                 f.write(f"Password for '{target_username}' was NOT found in the dictionary.\n")
            elif not error_message:
                 f.write(f"Password for '{target_username}' was not cracked (process may have been stopped or failed silently).\n")
            else: # Error occurred
                 f.write(f"Password for '{target_username}' was not cracked due to process error.\n")
            f.write("\n")

            f.write("== ANALYSIS OF PASSWORD STRENGTH ==\n") # Updated Analysis
            if error_message:
                 f.write("Analysis hindered by Hashcat error.\n")
            elif cracked_password:
                 f.write(f"The password ('{cracked_password}') for user '{target_username}' was found in the dictionary.\n")
                 f.write("This password is considered WEAK due to its presence in a common password list.\n")
                 f.write("It is highly vulnerable to dictionary attacks.\n")
            elif elapsed_time > 2: # Ran for a bit but didn't find it
                 f.write(f"The password for user '{target_username}' was NOT found in the provided dictionary ({os.path.basename(WORDLIST_PATH)}).\n")
                 f.write("This suggests it might be stronger than common passwords found in this list.\n")
                 f.write("However, its strength against other attacks (brute-force, larger dictionaries) is not guaranteed.\n")
                 f.write(f"Note: Bcrypt (cost 12) cracking speed was ~{speed}. Time taken depends on password position in dictionary.\n")
            else: # Didn't run long
                 f.write("Analysis incomplete. Process did not run significantly or failed.\n")
            f.write("\n")

            # Recommendations remain largely the same, just general advice now
            f.write("== GENERAL PASSWORD POLICY RECOMMENDATIONS ==\n") 
            f.write("1.  **Enforce Complexity:** Minimum 12-15+ chars, mix of types.\n")
            # ... (keep recommendations 2-10 as before) ...
            f.write("10. **Credential Monitoring:** Monitor for credential exposure.\n")

    except Exception as e:
        print(f"[!] Error writing report file {os.path.basename(REPORT_FILE)}: {e}")
    
    # --- Final Console Summary ---
    print("\n=== CRACKING SUMMARY ===")
    if error_message: print(f"[!] NOTE: Hashcat reported an error: {error_message}")
    elif "Stopped by user" in stdout: print("[!] NOTE: Process was stopped manually.")
        
    print(f"Target User: {target_username}")
    print(f"Successfully Cracked: {'Yes' if cracked_password else 'No'}")
    print(f"Time Elapsed: {time_str}")
    print(f"Approximate Cracking Speed: {speed}")
    if cracked_password: print(f"Cracked Password: {cracked_password}")
    print(f"\nDetailed report saved to: {os.path.basename(REPORT_FILE)}")

# --- MODIFIED FUNCTION: Main ---
def main():
    """Main function to select user, prepare hash, run cracker, and report."""
    print("=== Bcrypt Password Cracker Script ===")
    print(f"Using Hashcat from: {HASHCAT_PATH}")

    # Step 1: Select User and Get Hash
    target_username, target_hash = select_target_user()
    if not target_username or not target_hash:
        print("[!] No valid user selected or hash obtained. Exiting.")
        # Optional: Write minimal error report
        sys.exit(1) # Exit with error code

    # Step 2: Prepare the single hash file
    if not prepare_single_hash_file(target_hash):
        print("[!] Failed to prepare hash file for Hashcat. Exiting.")
        sys.exit(1)

    # Step 3: Check wordlist exists
    if not os.path.exists(WORDLIST_PATH):
         print(f"[!] FATAL ERROR: Wordlist file not found: {WORDLIST_PATH}")
         # Optional: Write minimal error report
         sys.exit(1) 

    # Step 4: Run Hashcat (now with --potfile-disable)
    elapsed_time, stdout, stderr = run_hashcat_dictionary_attack()

    # Step 5: Parse results and generate report (passing target_username)
    parse_results(target_username, elapsed_time, stdout, stderr) 

    print("\n[+] Password cracking simulation complete.")

if __name__ == "__main__":
    main()
