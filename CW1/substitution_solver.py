import math, random, multiprocessing
from collections import Counter


letters = "abcdefghijklmnopqrstuvwxyz"
english_freq_order = "etaonrishdlfcmugypwbvkxqjz"  # Common freq ordering
NUM_PROCESSES = 4  # Adjust to the number of CPU cores/threads you want to use

# Set retry parameters
MAX_ATTEMPTS = 5
SCORE_THRESHOLD = -28791  # If score is below this, retry

#sample text for trigram scoring
sample_text = """In the grand halls of history, civilizations have risen and fallen, leaving behind echoes of their achievements. 
The written word has been the cornerstone of knowledge, preserving ideas across generations. From the philosophers 
of ancient Greece to the scholars of the Renaissance, the pursuit of wisdom has been relentless.

Scientific discoveries have reshaped human existence. The understanding of gravity, the laws of motion, and 
the structure of the atom have unlocked the mysteries of the universe. Medicine, once bound by superstition, 
now thrives on the principles of biology and chemistry, extending human life beyond what was once imaginable.

Great minds such as Isaac Newton, Albert Einstein, and Marie Curie have illuminated the path of discovery, 
challenging conventions and revolutionizing thought. Literature, too, has played its role in shaping society, 
offering profound insights into the human condition. The words of Shakespeare, Austen, and Orwell 
continue to inspire and provoke deep reflection.

Meanwhile, the industrial revolution transformed economies, leading humanity from agrarian societies to 
technological marvels. The steam engine, electricity, and the advent of computers propelled civilization 
into an era of unprecedented progress. Yet, with every leap forward, ethical dilemmas have emerged, 
forcing society to confront the consequences of innovation.

The digital age has further accelerated change, bridging continents through instantaneous communication. 
Artificial intelligence, once a concept of science fiction, now influences daily life, from healthcare to 
autonomous vehicles. The balance between convenience and privacy has become a topic of global debate, 
as technological advancements shape the future.

Despite the complexity of the modern world, fundamental values remain. The quest for truth, justice, and 
understanding persists, uniting humanity in an ongoing narrative of growth and enlightenment. 
Through the study of history, science, and literature, we continue to decode the past, navigate the present, 
and anticipate the future.
"""

sample_text = sample_text.lower()
sample_text_clean = "".join(ch for ch in sample_text if ch.isalpha() or ch.isspace())
sample_text_joined = "".join(sample_text_clean.split())

def get_trigrams(text):
    trigrams = {}
    for i in range(len(text)-2):
        tri = text[i:i+3]
        trigrams[tri] = trigrams.get(tri, 0) + 1
    return trigrams

trigrams_sample = get_trigrams(sample_text_joined)
total_trigrams = sum(trigrams_sample.values())
trigram_probs = {
    tri: math.log(count / total_trigrams) for tri, count in trigrams_sample.items()
}
min_log_prob = math.log(1.0 / (total_trigrams * 100))  # penalty for unseen trigrams

def score_text(plaintext):
    pt = "".join(ch for ch in plaintext.lower() if ch.isalpha())
    s = 0
    for i in range(len(pt) - 2):
        tri = pt[i:i+3]
        s += trigram_probs.get(tri, min_log_prob)
    return s

def decrypt(cipher, key_map):
    # key_map: dict cipher_letter -> plain_letter
    result = []
    for ch in cipher:
        if ch in key_map:
            result.append(key_map[ch])
        else:
            # Non-alpha or unknown chars remain as is (punctuation, spaces, etc.)
            result.append(ch)
    return "".join(result)


# 1) Frequency Analysis for Initial Key
def frequency_analysis_key(ciphertext):
    # Count frequency of each letter in ciphertext
    c_count = Counter(ch for ch in ciphertext.lower() if ch.isalpha())
    # Sort letters by frequency descending
    most_common_cipher_letters = [p[0] for p in c_count.most_common()]
    
    # If some letters never appear, add them to the end
    for alpha in letters:
        if alpha not in most_common_cipher_letters:
            most_common_cipher_letters.append(alpha)
    
    # Build mapping: ciphertext's highest freq letter -> 'e', 2nd -> 't', etc.
    # (english_freq_order is your best guess ordering for plaintext frequencies)
    key_map = {}
    for i, ciph_letter in enumerate(most_common_cipher_letters):
        if i < len(english_freq_order):
            key_map[ciph_letter] = english_freq_order[i]
        else:
            # If we run out of positions, map leftover letters arbitrarily
            key_map[ciph_letter] = random.choice(letters)
    
    return key_map


# 2) Pattern Matching
def refine_with_pattern(ciphertext, key_map):
    """
    Example approach:
    - We look for bigrams/trigrams or a known word (e.g. "the") in the plaintext.
    - If substituting certain pairs of letters yields more occurrences of these words,
      that might be an improvement.
    """
    original_score = score_text(decrypt(ciphertext, key_map))
    best_map = dict(key_map)
    best_score = original_score
    
    # We'll attempt a small number of random letter swaps
    TRIES = 10000
    for _ in range(TRIES):
        # pick two random letters in the key_map
        a, b = random.sample(letters, 2)
        
        # swap their plaintext assignments
        cipher_for_a = None
        cipher_for_b = None
        for k, v in best_map.items():
            if v == a:
                cipher_for_a = k
            elif v == b:
                cipher_for_b = k
        
        if cipher_for_a is None or cipher_for_b is None:
            continue
        
        # Make a local copy for testing
        test_map = dict(best_map)
        test_map[cipher_for_a], test_map[cipher_for_b] = b, a
        
        test_score = score_text(decrypt(ciphertext, test_map))
        if test_score > best_score:
            best_score = test_score
            best_map = test_map
    
    return best_map


# 3) Parallel refinement worker function
def parallel_refine_worker(args):
    """
    Each worker:
    - Takes ciphertext + an initial key_map
    - Does some random swaps or small hill climbing
    - Returns best local result
    """
    ciphertext, initial_map, rounds = args
    best_map = dict(initial_map)
    best_score = score_text(decrypt(ciphertext, best_map))
    
    for _ in range(rounds):
        a, b = random.sample(letters, 2)
        
        cipher_for_a = None
        cipher_for_b = None
        for k, v in best_map.items():
            if v == a:
                cipher_for_a = k
            elif v == b:
                cipher_for_b = k
        
        if not cipher_for_a or not cipher_for_b or cipher_for_a == cipher_for_b:
            continue
        
        new_map = dict(best_map)
        new_map[cipher_for_a], new_map[cipher_for_b] = b, a
        
        new_score = score_text(decrypt(ciphertext, new_map))
        if new_score > best_score:
            best_map = new_map
            best_score = new_score
            
    return best_map, best_score


if __name__ == "__main__":
    attempt = 0
    best_overall_score = float("-inf")
    best_overall_map = None

    while attempt < MAX_ATTEMPTS:
        attempt += 1
        print(f"\n=== Attempt {attempt} ===")

        # Load ciphertext
        with open("ciphertext.txt", "r") as f:
            ciphertext = f.read().strip()

        # Step A: Frequency-analysis-based initial key
        freq_key_map = frequency_analysis_key(ciphertext)

        # Step B: Minor pattern-based refinement (single-threaded)
        refined_map = refine_with_pattern(ciphertext, freq_key_map)
        refined_score = score_text(decrypt(ciphertext, refined_map))
        print(f"Score after single-threaded pattern refinement: {refined_score}")

        # Step C: Parallel processes to further improve the mapping
        rounds_per_process = 20000
        args_list = [(ciphertext, refined_map, rounds_per_process) for _ in range(NUM_PROCESSES)]

        with multiprocessing.Pool(processes=NUM_PROCESSES) as pool:
            results = pool.map(parallel_refine_worker, args_list)

        # Pick the best from all processes
        best_map = None
        best_score = float("-inf")
        for r_map, r_score in results:
            if r_score > best_score:
                best_score = r_score
                best_map = r_map

        # Check if decryption is valid
        if best_score >= SCORE_THRESHOLD:
            best_overall_map = best_map
            best_overall_score = best_score
            break  # Stop retrying if score is good

        print("Decryption failed. Retrying...")

    if best_overall_map is None:
        print("Failed to decrypt after multiple attempts.")
        exit(1)

    # Decrypt with the best key map found
    final_plaintext = decrypt(ciphertext, best_overall_map)

    # Print summary
    print("\n=== Final Decryption Results ===")
    print(f"Best overall score after parallel search: {best_overall_score}")
    print("Decrypted text (first 500 chars):")
    print(final_plaintext[:500], "...")

    print("\nDecryption key mapping (ciphertext -> plaintext):")
    for c in sorted(best_overall_map.keys()):
        print(f"{c} -> {best_overall_map[c]}")

    # Generate encryption key mapping (inverse of decryption)
    encryption_map = {v: k for k, v in best_overall_map.items()}

    # Convert mappings to single-line strings
    encryption_key_str = "".join(encryption_map.get(chr(i), "?") for i in range(ord('a'), ord('z')+1))
    decryption_key_str = "".join(best_overall_map.get(chr(i), "?") for i in range(ord('a'), ord('z')+1))

    # Print encryption and decryption keys
    print(f"\nEncryption key (plaintext to ciphertext): {encryption_key_str}")
    print(f"Decryption key (ciphertext to plaintext): {decryption_key_str}")

    # Write results to file
    # Write results to file
    with open("output.txt", "w", encoding="utf-8") as out:
        out.write(f"=== Substitution Cipher Decryption Results ===\n")
        out.write(f"Best Overall Score: {best_overall_score}\n\n")

        out.write(f"Encryption key (plaintext to ciphertext): {encryption_key_str}\n")
        out.write(f"Decryption key (ciphertext to plaintext): {decryption_key_str}\n\n")

        out.write("\n--- Decrypted Plaintext ---\n")
        
        # Break plaintext into chunks of 170 characters per line
        for i in range(0, len(final_plaintext), 100):
            out.write(final_plaintext[i:i+100] + "\n")

    print("Decryption complete. Results saved in output.txt.")
