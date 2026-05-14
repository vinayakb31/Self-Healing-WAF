======================================================================
  SELF-HEALING WAF — MODEL EVALUATION REPORT
  Generated: 2026-05-14 19:21:27
======================================================================

[Phase 1] Loading v2 model and preprocessors...
  Model: waf_brain_v2.onnx (1005 features)
  Preprocessors: tfidf_vectorizer_v2.pkl, standard_scaler_v2.pkl
  [DONE] All assets loaded successfully

----------------------------------------------------------------------
[Phase 2] CSIC Dataset Evaluation (Train/Test Split)
----------------------------------------------------------------------
  Total samples: 61065
  Normal (0): 36000
  Anomalous (1): 25065

  Running inference on 12213 test samples...

  Classification Report:
                precision    recall  f1-score   support
  
        Normal       0.98      0.98      0.98      7200
     Anomalous       0.97      0.98      0.97      5013
  
      accuracy                           0.98     12213
     macro avg       0.98      0.98      0.98     12213
  weighted avg       0.98      0.98      0.98     12213
  

  Confusion Matrix:
                    Predicted Normal  Predicted Anomalous
  Actual Normal           7056               144
  Actual Anomalous         111              4902

  Overall Accuracy: 0.9791 (97.91%)
  Detection Rate (Anomalous Recall): 0.9779 (97.79%)
  [PASS] Detection rate >= 95% (Roadmap target met)
  False Positive Rate: 0.0200 (2.00%)

----------------------------------------------------------------------
[Phase 3] OWASP Top 10 Synthetic Attack Detection
----------------------------------------------------------------------

  [OK] SQL Injection (UNION-based): ANOMALOUS (86.2% confidence)
  [OK] SQL Injection (OR 1=1): ANOMALOUS (80.2% confidence)
  [OK] SQL Injection (DROP TABLE): ANOMALOUS (84.2% confidence)
  [OK] SQL Injection (INSERT INTO): ANOMALOUS (89.4% confidence)
  [OK] XSS (script tag): ANOMALOUS (94.3% confidence)
  [OK] XSS (img onerror): ANOMALOUS (77.6% confidence)
  [OK] XSS (event handler): ANOMALOUS (84.9% confidence)
  [OK] Path Traversal (../../etc/passwd): ANOMALOUS (94.6% confidence)
  [OK] Path Traversal (..\..\win.ini): ANOMALOUS (89.0% confidence)
  [OK] Command Injection (; cat /etc/passwd): ANOMALOUS (68.6% confidence)
  [OK] Command Injection (| whoami): ANOMALOUS (81.4% confidence)
  [OK] SSRF (internal IP): ANOMALOUS (86.0% confidence)
  [OK] Log4Shell (JNDI lookup): ANOMALOUS (89.6% confidence)
  [OK] LDAP Injection: ANOMALOUS (65.3% confidence)
  [OK] XXE-style payload: ANOMALOUS (90.3% confidence)

  OWASP Detection Rate: 15/15 (100%)

  --- False Positive Check (Normal Traffic) ---
  [OK] Normal: Homepage: NORMAL (99.5% confidence)
  [OK] Normal: Product page: NORMAL (87.1% confidence)
  [OK] Normal: Login page: NORMAL (78.5% confidence)
  [OK] Normal: Image request: NORMAL (99.3% confidence)
  [OK] Normal: Cart checkout: NORMAL (99.2% confidence)

  Normal Traffic Accuracy: 5/5 (100%)

----------------------------------------------------------------------
[Phase 4] Inference Latency Benchmark
----------------------------------------------------------------------

  Iterations: 200
  Mean latency:   1.61 ms
  Median latency: 1.52 ms
  P95 latency:    1.90 ms
  P99 latency:    2.21 ms
  Min latency:    1.42 ms
  Max latency:    2.61 ms
  [PASS] Median latency < 30ms (Roadmap target met)

======================================================================
  SUMMARY
======================================================================
  Model:                waf_brain_v2.onnx
  Dataset Accuracy:     97.91%
  Detection Rate:       97.79%
  False Positive Rate:  2.00%
  OWASP Detection:      100%
  Median Latency:       1.52 ms
  Status:               ALL TARGETS MET
======================================================================