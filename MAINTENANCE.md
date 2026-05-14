# Self-Healing WAF: Maintenance & Operations Guide

This guide ensures your WAF continues to learn and evolve effectively. All commands should be executed from the **repository root**.

## 1. The Daily Self-Healing Loop
To keep the AI sharp, follow this 3-step cycle:

### Step A: Bridge New Data
Move logs from the live `shadow_log.db` to the quarantine database for review:
```powershell
python scripts/bridge_quarantine.py
```

### Step B: Manual Verification (The "Human-in-the-Loop")
Open your SQLite manager (e.g., DB Browser for SQLite) and review `waf_quarantine.db`:
- Table: `blocked_requests`
- Change `status` from `PENDING` to:
    - `VERIFIED_ATTACK`: If the WAF correctly identified a threat.
    - `VERIFIED_NORMAL`: If the WAF made a mistake (False Positive).

### Step C: Trigger Retraining
Once you have verified at least 1-5 new logs, trigger the brain upgrade:
```powershell
python scripts/retrain_brain.py
```
*Note: The script will only promote the new model if it passes the security guardrails (Promotion Gate).*

---

## 2. Dataset Management
The WAF's intelligence relies on the files in the `data/` directory.

| Dataset | File | Purpose |
| :--- | :--- | :--- |
| **CIC-IDS2018** | `cic_ids_2018.csv` | Teaches Behavioral/Network patterns. |
| **Juice Shop** | `juice_shop_attacks.csv` | Teaches Modern API & NoSQL attacks. |
| **CSIC Augmented** | `csic_augmented.csv` | The base "HTTP Vocabulary". |

**To update Juice Shop payloads**:
Run `python scripts/generate_juice_payloads.py` to refresh the modern API attack surface.

---

## 3. Monitoring & Performance
To verify that the live model is still performing within your required bounds:

```powershell
python scripts/evaluate_model.py
```
This generates an `evaluation_report.txt` showing Accuracy, Recall (Detection Rate), and Latency.

---

## 4. API Operations
**Starting the API**:
```powershell
uvicorn core.waf_api:app --reload
```
**Hot-Reloading**:
The API automatically checks for a new `models/waf_brain_v2.onnx` every few seconds. You **do not** need to restart the API after retraining; the "v2.0 Elite Brain" will swap in automatically.

---

## 5. Security Guardrails (Promotion Gate)
If retraining fails with "Promotion gate failed," check the output. It usually means:
- The new model is overreacting (False Positives).
- To fix: Add the failing URL to the `PROMOTION_NORMALS` list in `retrain_brain.py` and run it again.

---

**Your WAF is now a living, learning security system. Keep it fed with verified data, and it will remain nearly impossible to bypass.**
