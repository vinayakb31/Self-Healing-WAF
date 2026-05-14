import pandas as pd
import numpy as np
import random
import re
import os
from urllib.parse import quote

# --- Configuration ---
DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "data")
INPUT_FILE = os.path.join(DATA_DIR, "csic_database.csv")
OUTPUT_FILE = os.path.join(DATA_DIR, "csic_augmented.csv")
AUGMENTATION_FACTOR_ATTACK = 1  # 1 new mutated version per attack
AUGMENTATION_FACTOR_NORMAL = 1  # 1 new variant per normal request

def mutate_case(text):
    """Randomly change the case of characters."""
    return "".join(c.upper() if random.random() > 0.5 else c.lower() for c in text)

def mutate_comments(text):
    """Inject SQL comments between words."""
    words = text.split()
    if len(words) < 2:
        return text
    idx = random.randint(0, len(words) - 2)
    words[idx] = words[idx] + "/**/"
    return " ".join(words)

def mutate_encoding(text):
    """URL-encode some special characters randomly."""
    chars = list(text)
    for i in range(len(chars)):
        if chars[i] in ["'", "\"", "<", ">", "(", ")", ";", "="] and random.random() > 0.5:
            chars[i] = quote(chars[i])
    return "".join(chars)

def mutate_double_encoding(text):
    """Apply double URL encoding to the entire string."""
    return quote(quote(text))

def mutate_whitespace(text):
    """Replace spaces with tabs, multiple spaces, or '+'."""
    variants = ["  ", "   ", "+", " "]
    return text.replace(" ", random.choice(variants))

def mutate_normal(url):
    """Add harmless noise to normal URLs."""
    if "?" in url:
        return url + f"&cache_id={random.randint(1000, 9999)}"
    return url + f"?v={random.randint(1, 100)}"

def augment_payload(payload, is_attack=True):
    """Apply a random set of mutations to a payload."""
    if not is_attack:
        return mutate_normal(payload)
        
    mutators = [mutate_case, mutate_comments, mutate_encoding, mutate_double_encoding, mutate_whitespace]
    # Apply 1 to 3 random mutators
    chosen_mutators = random.sample(mutators, k=random.randint(1, 3))
    
    mutated = payload
    for m in chosen_mutators:
        mutated = m(mutated)
    return mutated

def main():
    print(f"Loading foundation dataset: {INPUT_FILE}")
    if not os.path.exists(INPUT_FILE):
        print("Error: Input file not found.")
        return

    df = pd.read_csv(INPUT_FILE)
    
    # Identify classes
    majority_class = df['classification'].value_counts().idxmax()
    attacks_df = df[df['classification'] != majority_class].copy()
    normals_df = df[df['classification'] == majority_class].copy()
    
    print(f"Found {len(attacks_df)} attacks and {len(normals_df)} normals. Generating augmented data...")
    
    augmented_rows = []
    
    # Augment Attacks
    for _, row in attacks_df.iterrows():
        original_url = str(row['URL'])
        original_content = str(row['content']) if pd.notna(row['content']) else ""
        
        for _ in range(AUGMENTATION_FACTOR_ATTACK):
            new_row = row.copy()
            new_row['URL'] = augment_payload(original_url, is_attack=True)
            if original_content:
                new_row['content'] = augment_payload(original_content, is_attack=True)
            new_row['classification'] = "augmented_attack"
            augmented_rows.append(new_row)

    # Augment Normals
    for _, row in normals_df.sample(n=min(len(normals_df), 15000)).iterrows():
        original_url = str(row['URL'])
        for _ in range(AUGMENTATION_FACTOR_NORMAL):
            new_row = row.copy()
            new_row['URL'] = augment_payload(original_url, is_attack=False)
            new_row['classification'] = "augmented_normal"
            augmented_rows.append(new_row)
            
    augmented_df = pd.DataFrame(augmented_rows)
    final_df = pd.concat([df, augmented_df], ignore_index=True)
    
    print(f"Augmentation complete. Total records: {len(final_df)} (Added {len(augmented_df)} new attacks)")
    final_df.to_csv(OUTPUT_FILE, index=False)
    print(f"Saved augmented dataset to: {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
