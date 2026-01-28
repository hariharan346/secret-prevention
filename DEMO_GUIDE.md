# 🎬 Secret Leakage Prevention System - Interview Demo Script

**Role**: Senior DevSecOps Engineer
**Goal**: Show the HR/Interviewer that you can build **safety nets** that save the company from hacking attempts.

---

## 🛑 Scenario 1: The "Accidental" Commit (The Hook)
*Context: "I'll show you how the system automatically blocks a developer from leaking an AWS key."*

1.  **Open your terminal** (Git Bash or VS Code Terminal).
2.  **Create a new file** called `leaked_config.py`.
3.  **Paste this content** (A fake AWS Key):
    ```python
    # I am tired, I will just hardcode this for now
    aws_key = "AKIAIOSFODNN7EXAMPLE" 
    ```
4.  **Try to commit it**:
    ```bash
    git add leaked_config.py
    git commit -m "Quick fix for production"
    ```
5.  **👉 SHOW THE RESULT**: 
    - Point to the **RED TEXT**: `❌ BLOCKING: High severity secrets detected.`
    - Say: *"See? The system intercepted the commit locally. The secret never left my laptop."*

---

## 🧠 Scenario 2: Context Awareness (Prod vs Test)
*Context: "Standard tools are noisy. My system is smart—it knows the difference between 'Test' and 'Production'."*

1.  **Modify the file** `leaked_config.py`. change the variable name:
    ```python
    # Just a test password
    test_db_pass = "password123"
    ```
2.  **Run the scanner manually**:
    ```bash
    python src/scan.py leaked_config.py
    ```
3.  **Show the Result**: It says `[MEDIUM] -> Action: WARN`.
    - Say: *"For test passwords, it just warns me but doesn't block me. That improves Developer Experience."*
4.  **NOW, change it to PROD**:
    ```python
    # REAL Production password
    prod_db_pass = "password123"
    ```
5.  **Run the scanner again**:
    ```bash
    python src/scan.py leaked_config.py
    ```
6.  **👉 SHOW THE RESULT**: It upgraded to `[HIGH] -> Action: BLOCK`.
    - Say: *"Because I added the word 'prod', the system upgraded the severity and blocked it. That's context-aware security."*

---

## ☁️ Scenario 3: The "Cloud Check" (The Wow Factor)
*Context: "Detected keys might be old or inactive. My tool can verify them."*

1.  **Run the validation command**:
    ```bash
    python src/scan.py --validate tests/test_secrets.txt
    ```
2.  **👉 SHOW THE OUTPUT**:
    - Look for: `Cloud Check: ✅ (Test Key)`
    - Say: *"It simulates an API call to AWS/GitHub to check if the key is actually live. If it is, we trigger an immediate rotation alert."*

---

## 🧪 Scenario 4: The Entropy Check (Hidden Secrets)
*Context: "Hackers try to hide secrets. Regex isn't enough."*

1.  **Show** `tests/test_entropy.txt`.
    - Point to: `high_entropy = "7Fz/3x9@1qP#m$Lk"`
2.  **Run the scanner**:
    ```bash
    python src/scan.py tests/test_entropy.txt
    ```
3.  **👉 SHOW THE RESULT**: `High Entropy String (Score: 4.xx)`.
    - Say: *"This string didn't look like an AWS key, but the math algorithm detected it was too random to be normal text. This finds zero-day secrets."*

---

## 🏁 Closing Statement for HR
*"I built this not just to find strings, but to build a culture of security. It catches mistakes locally, enforces rules globally via CI/CD, and prioritizes real threats over noise."*
