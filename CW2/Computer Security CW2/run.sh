#!/bin/bash

# Output log file
LOG_FILE="output_log.txt"

# Clear previous output
echo "===== Coursework Run Log =====" > "$LOG_FILE"
echo "Generated on: $(date)" >> "$LOG_FILE"
echo "" >> "$LOG_FILE"

# Function to compile and run all .c files in a folder
run_folder() {
  folder_name=$1
  echo "---- Entering $folder_name ----" | tee -a "$LOG_FILE"
  cd "$folder_name" || exit

  for file in *.c; do
    exe="${file%.c}"
    echo "" | tee -a "../$LOG_FILE"
    echo ">>> Compiling $file" | tee -a "../$LOG_FILE"
    gcc "$file" -o "$exe" -lcrypto 2>> "../$LOG_FILE"

    if [ $? -eq 0 ]; then
      echo ">>> Running $exe" | tee -a "../$LOG_FILE"
      echo "---------------------------------" | tee -a "../$LOG_FILE"
      ./"$exe" | tee -a "../$LOG_FILE"
      echo "---------------------------------" | tee -a "../$LOG_FILE"
    else
      echo "!!! Compilation failed for $file" | tee -a "../$LOG_FILE"
    fi
  done

  cd ..
  echo "---- Leaving $folder_name ----" | tee -a "$LOG_FILE"
  echo "" | tee -a "$LOG_FILE"
}

# Run in order
run_folder "RSA"
run_folder "Diffie-Hellman"
run_folder "El-Gamal"

echo "===== All Tasks Completed =====" | tee -a "$LOG_FILE"
