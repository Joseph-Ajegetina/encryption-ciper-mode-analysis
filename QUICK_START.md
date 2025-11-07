# Quick Start Guide

## Run the Complete Lab in 3 Steps

### Step 1: Activate Virtual Environment
```bash
source venv/bin/activate
```

### Step 2: Run the Lab Demo
```bash
python3 lab_demo.py
```

When prompted about missing files, press `y` to continue.

### Step 3: View Results
```bash
# View generated visualizations
open output/ecb_vulnerability_demo.png
open output/key_reuse_analysis.png
open output/ecb_pattern_attack.png

# View encrypted files
ls -lh output/*.enc

# Read the comprehensive report
cat LAB_REPORT.md

# Read the one-page summary
cat DELIVERABLE_3_SUMMARY.md
```

---

## What Each Script Does

### `crypto_tool.py`
Core encryption engine - tests basic AES/DES encryption
```bash
python3 crypto_tool.py
```

### `image_crypto.py`
Image encryption demonstration - shows ECB vulnerability
```bash
python3 image_crypto.py
```

### `crypto_analysis.py`
Attack demonstrations - key reuse and pattern analysis
```bash
python3 crypto_analysis.py
```

### `lab_demo.py`
Complete lab - runs all three parts sequentially
```bash
python3 lab_demo.py
```

---

## Expected Output

The lab will generate:

**In `output/` directory:**
- `ecb_vulnerability_demo.png` - Visual proof of ECB pattern leakage
- `key_reuse_analysis.png` - Statistical analysis charts
- `ecb_pattern_attack.png` - Simulated attack results
- `mode_comparison.png` - Side-by-side mode comparisons
- `*.enc` files - Encrypted test files
- `*_decrypted.*` files - Decrypted results

**Console Output:**
- Detailed analysis of each cipher mode
- Encryption/decryption test results
- Security vulnerability explanations
- Statistical metrics and findings

---

## Deliverables Checklist

✅ **Deliverable 1:** Working encryption/decryption tool
   - See: `crypto_tool.py`, `image_crypto.py`

✅ **Deliverable 2:** Attack demonstrations with screenshots
   - See: `output/` directory + `LAB_REPORT.md` Part 2

✅ **Deliverable 3:** One-page summary
   - See: `DELIVERABLE_3_SUMMARY.md`

---

## Troubleshooting

**Problem:** Module not found error
**Solution:** Make sure virtual environment is activated:
```bash
source venv/bin/activate
```

**Problem:** Missing image files
**Solution:** Ensure `Tux.png`, `plaintext.txt`, and `studentdata.csv` are in the directory

**Problem:** Matplotlib display issues
**Solution:** Images are saved to `output/` directory - view them directly

---

## Quick Demo (No Prompts)

For a fully automated demo, modify the cipher modes or run individual components:

```bash
# Quick test of all modules
source venv/bin/activate
python3 crypto_tool.py
python3 image_crypto.py  # Will create visualizations
python3 crypto_analysis.py  # Will perform attacks
```

---

**Need Help?** Refer to `README.md` for comprehensive documentation.
