# Self-Healing AI Web Application Firewall (WAF) v2.0

![Status](https://img.shields.io/badge/Status-Production--Ready-success)
![ML](https://img.shields.io/badge/Model-Random%20Forest%20+%20ONNX-blue)
![Security](https://img.shields.io/badge/Security-Adversarial--Hardened-red)

An industrial-grade, closed-loop security system that detects web attacks with **97.9% accuracy** and automatically "heals" its own knowledge gaps through validated feedback loops and adversarial data augmentation.

## 🚀 Overview

This project is a high-performance **Hybrid WAF** that bridges the gap between traditional signature-based security and modern AI. It features an inference engine capable of classifying HTTP traffic in **<1.6ms**, a recursive normalization layer to defeat evasion, and an automated pipeline that learns from modern API and behavioral datasets.

### The "v2 Elite" Brain
Unlike traditional WAFs, this system is trained on a **tri-source dataset**:
1.  **CSE-CIC-IDS2018 (65%)**: Teaches behavioral network flow patterns.
2.  **OWASP Juice Shop (35%)**: Teaches modern REST API and NoSQL attacks.
3.  **CSIC Augmented (Baseline)**: Provides a foundational HTTP attack vocabulary.

---

## 🛡️ Key Features

*   **97.9% Accuracy**: Hardened against SQLi, XSS, Path Traversal, Log4j, and SSRF.
*   **Adversarial Resilience**: Built-in mutation engine (`augment_data.py`) generates 40,000+ variants of attacks (Double Encoding, Comment Injection) to prevent bypasses.
*   **Hybrid Risk Engine**: Combines ML confidence scores with deterministic signature matching and recursive normalization.
*   **Sub-2ms Latency**: Optimized using **ONNX Runtime** for high-throughput production environments.
*   **Self-Healing Loop**: Automatically bridges quarantined logs, allows for human verification, and triggers a "Promotion Gate" protected retraining.

---

## 🏗️ Project Structure

The project follows a professional, modular architecture:

*   📂 **`core/`**: The heart of the WAF.
    *   `waf_api.py`: FastAPI inference server with hot-reloading.
    *   `risk_engine.py`: Hybrid logic with recursive unquoting.
*   📂 **`models/`**: Centralized ML artifacts (ONNX models, Scalers, Vectorizers).
*   📂 **`scripts/`**: Automation & Intelligence.
    *   `retrain_brain.py`: The self-healing training pipeline.
    *   `augment_data.py`: Adversarial data mutation engine.
    *   `generate_juice_payloads.py`: Modern API attack generator.
    *   `evaluate_model.py`: Comprehensive benchmark suite.
*   📂 **`data/`**: Training sets and behavioral logs.

---

## 📊 Performance Benchmarks

| Metric | Result | Target |
| :--- | :--- | :--- |
| **Detection Rate (Recall)** | **97.99%** | > 95% |
| **OWASP Top 10 Coverage** | **100.0%** | 100% |
| **False Positive Rate** | **2.00%** | < 5% |
| **Median Latency** | **1.52 ms** | < 30ms |
| **Status** | **ALL TARGETS MET** | ✅ |

---

## 🛠️ Quick Start

### 1. Installation
```powershell
pip install -r requirements.txt
```

### 2. Start the WAF (Enforcement Mode)
```powershell
uvicorn core.waf_api:app --reload
```

### 3. Test a Payload
```powershell
# Normal Request
curl "http://127.0.0.1:8000/api/products?id=1"

# Evasive SQLi (Blocked)
curl "http://127.0.0.1:8000/login?user=admin%2527%2520OR%25201%253D1%2520--"
```

---

## 🔁 Maintenance & Self-Healing

The WAF is designed to evolve. To maintain the system:
1.  **Bridge**: Move live logs to quarantine: `python scripts/bridge_quarantine.py`.
2.  **Verify**: Manually approve/reject logs in `waf_quarantine.db`.
3.  **Retrain**: Update the AI: `python scripts/retrain_brain.py`.

*For detailed instructions, see [MAINTENANCE.md](MAINTENANCE.md).*

---

## 📜 License
MIT License - See [LICENSE](LICENSE) for details.
