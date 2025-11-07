# AI-Assisted Lab Development - Prompts Documentation

**Course:** ICS570 - Cybersecurity Essentials
**Lab:** Week 9 - Implementing and Attacking Symmetric Key Encryption Systems
**Student:** [Your Name]
**Date:** November 7, 2025

---

## Purpose of This Document

This document chronicles the prompts and interactions with AI during the lab implementation. It demonstrates:
- Active learning and engagement with concepts
- Using AI as a teaching assistant and coding helper
- Iterative problem-solving and debugging
- Understanding gained through the process

---

### Prompt 1: Environment Setup
```
Create a new python3 virtual environment for the implementation
```

**Purpose:** Set up isolated development environment with proper dependencies.

**Learning Outcome:** Learned importance of virtual environments for Python projects and dependency management.

---

## Part 1: Implementation Phase

### Prompt 2: Core Encryption Implementation
```
How do I implement AES encryption with multiple modes (ECB, CBC, CTR)
in Python using pycryptodome?
```

**Purpose:** Understand the basic structure of implementing multiple cipher modes.

**Learning Outcome:** Learned about the Crypto.Cipher module structure and how different modes require different parameters (IV for CBC, counter for CTR, etc.).

---

### Prompt 4: Understanding IVs and Padding
```
Explain why CBC mode needs an IV but ECB doesn't. What is padding and
when is it needed?
```

**Purpose:** Understand the fundamental differences between cipher modes.

**Learning Outcome:**
- ECB encrypts each block independently (no IV needed)
- CBC chains blocks together (needs IV for first block)
- Padding is required for modes that operate on full blocks (ECB, CBC)
- Stream cipher modes (CFB, OFB, CTR) don't need padding

---

### Prompt 5: Image Encryption Challenge
```
How can I encrypt an image file while preserving its dimensions for
visualization? I need to show the pattern leakage in ECB mode.
```

**Purpose:** Understand how to handle binary image data for educational demonstration.

**Learning Outcome:**
- Images can be converted to byte arrays with numpy
- Encryption operates on bytes, not pixels
- Reshaping encrypted bytes back to image dimensions reveals patterns in ECB
- Need to handle padding carefully to avoid size mismatches

---

### Prompt 6: Debugging Decryption
```
My decryption is failing with "Padding is incorrect" error in CBC mode.
What could be the issue?
```

**Purpose:** Troubleshoot common cryptographic implementation errors.

**Learning Outcome:**
- IV must be saved and provided during decryption
- Padding validation happens during decryption
- Different modes have different requirements
- Importance of proper parameter management

---

## Part 2: Analysis and Attack Phase

### Prompt 7: Understanding Pattern Leakage
```
Why exactly does ECB mode leak patterns? Can you explain this with a
simple example using repeated data?
```

**Purpose:** Deeply understand the cryptographic weakness being demonstrated.

**Learning Outcome:**
- ECB is deterministic: same plaintext block → same ciphertext block
- This violates semantic security
- Even strong algorithms like AES can't compensate for weak modes
- Real-world example: encrypting images shows this dramatically

---

### Prompt 8: Implementing Similarity Metrics
```
How do I measure similarity between two ciphertexts to demonstrate
key reuse vulnerability? What metrics should I use?
```

**Purpose:** Learn statistical methods for cryptanalysis.

**Learning Outcome:**
- Histogram correlation measures byte frequency similarity
- XOR-based analysis (Hamming distance) shows bit-level differences
- Different metrics reveal different aspects of similarity
- Quantitative analysis strengthens security arguments

---

### Prompt 9: Visualizing the Attack
```
How can I create visualizations that clearly show the difference between
ECB and CBC encrypted images side-by-side?
```

**Purpose:** Learn to present security findings effectively.

**Learning Outcome:**
- Visual demonstrations are powerful for security education
- Matplotlib can display encrypted data as images
- Side-by-side comparisons highlight security differences
- Documentation requires clear, understandable visualizations

---

### Prompt 10: Edge Detection for Pattern Analysis
```
I need to simulate an attacker analyzing ECB ciphertext. How can I apply
edge detection to show that structure is recoverable?
```

**Purpose:** Understand practical cryptanalysis techniques.

**Learning Outcome:**
- Simple image processing can extract structure from ECB ciphertext
- Attackers don't need to decrypt to gain information
- Visual patterns = information leakage
- This demonstrates why ECB fails to provide confidentiality

---

### Prompt 11: Statistical Analysis Confusion
```
I'm getting 76% correlation for ECB but -3% for CBC. Is negative correlation
normal? What does this mean?
```

**Purpose:** Interpret statistical results correctly.

**Learning Outcome:**
- Negative correlation close to 0 indicates randomness
- This is expected for secure encryption (should appear random)
- High positive correlation in ECB confirms pattern leakage
- Statistical metrics validate security properties

---

## Part 3: Reflection and Best Practices

### Prompt 12: Understanding Real-World Implications
```
What are real-world examples where ECB mode was used incorrectly and
caused security vulnerabilities?
```

**Purpose:** Connect lab learning to practical security incidents.

**Learning Outcome:**
- ECB has been misused in actual systems (e.g., Adobe password encryption)
- Theoretical vulnerabilities have real-world consequences
- Proper mode selection is critical in production systems
- Security requires understanding, not just implementation

---

### Prompt 13: Secure Messaging Design
```
If I were designing a secure messaging app, what cipher mode and key
management strategy should I use? Walk me through the security considerations.
```

**Purpose:** Apply lab learnings to practical system design.

**Learning Outcome:**
- AES-GCM provides both confidentiality and integrity
- Key rotation and forward secrecy are essential
- IV/nonce management is critical (never reuse!)
- Security requires defense in depth, not just encryption

---

### Prompt 14: Key Management Best Practices
```
What are the risks of key reuse, and how should keys be managed in
production systems?
```

**Purpose:** Understand broader context of key lifecycle management.

**Learning Outcome:**
- Keys should be rotated regularly
- Single key compromise shouldn't expose all data
- Hardware Security Modules (HSMs) for critical keys
- Key management is as important as encryption algorithm

---

### Prompt 15: Documentation and Reporting
```
How should I structure my lab report to clearly explain the vulnerabilities
I demonstrated? What should I include?
```

**Purpose:** Learn to communicate security findings effectively.

**Learning Outcome:**
- Security reports need clear problem statements
- Evidence (screenshots, metrics) strengthens arguments
- Recommendations should be actionable
- Good documentation is crucial for security work

---

## Debugging and Refinement

### Prompt 16: Module Import Error
```
Getting "ModuleNotFoundError: No module named 'scipy'" but I don't want
to add another dependency. How can I implement edge detection using just numpy?
```

**Purpose:** Problem-solve and find alternative solutions.

**Learning Outcome:**
- Can implement Sobel edge detection with numpy convolutions
- Understanding algorithms helps avoid unnecessary dependencies
- Multiple solutions exist for same problem
- Sometimes simpler is better

---

### Prompt 17: Performance Question
```
The image encryption is slow for large images. Is there a way to optimize
this while maintaining security?
```

**Purpose:** Balance security with performance.

**Learning Outcome:**
- Cryptography has inherent computational costs
- Some modes (CTR) allow parallelization
- Hardware acceleration (AES-NI) helps performance
- Security shouldn't be sacrificed for speed

---

### Prompt 18: Code Organization
```
My code is getting messy with all the functions. How should I organize
this into clean, maintainable modules?
```

**Purpose:** Learn software engineering best practices.

**Learning Outcome:**
- Separation of concerns improves maintainability
- Classes encapsulate related functionality
- Clear interfaces make code reusable
- Good code structure aids understanding

---

## Conceptual Understanding

### Prompt 19: Why is CTR Mode Secure?
```
CTR mode doesn't use padding and seems simpler than CBC. Why is it
considered secure? How does it prevent pattern leakage?
```

**Purpose:** Deep dive into cryptographic modes.

**Learning Outcome:**
- CTR converts block cipher into stream cipher
- Counter ensures unique input for each block
- Nonce must never be reused with same key
- Different modes solve the pattern problem differently

---

### Prompt 20: Authenticated Encryption
```
The lab mentions authenticated encryption (GCM). What does this add
beyond confidentiality?
```

**Purpose:** Understand advanced cryptographic concepts.

**Learning Outcome:**
- Confidentiality ≠ Integrity
- Attackers can modify ciphertext even without decrypting
- AEAD (Authenticated Encryption with Associated Data) prevents tampering
- Modern systems need both properties

---

## Final Integration

### Prompt 21: Testing Strategy
```
How do I verify that my encryption/decryption is working correctly
across all modes? What tests should I run?
```

**Purpose:** Ensure implementation correctness.

**Learning Outcome:**
- Encrypt then decrypt should recover original plaintext
- Test with various data types (text, binary, images)
- Verify IV handling for each mode
- Testing is crucial for cryptographic code

---

### Prompt 22: Documentation Review
```
Review my implementation and suggest improvements for clarity, security,
and best practices.
```

**Purpose:** Get feedback on overall implementation.

**Learning Outcome:**
- Code review improves quality
- Security code needs extra scrutiny
- Comments and documentation aid understanding
- Always room for improvement

---

## Reflection on AI Usage

### What AI Helped With:
1. **Understanding Concepts:** Explaining cryptographic modes, IVs, padding, and security properties
2. **Implementation Guidance:** Showing how to use pycryptodome library correctly
3. **Debugging:** Helping identify and fix errors (padding, IV handling, module imports)
4. **Best Practices:** Teaching proper key management and secure design patterns
5. **Code Structure:** Organizing code into clean, maintainable modules
6. **Visualization:** Creating effective demonstrations of vulnerabilities
7. **Documentation:** Structuring reports and explanations clearly

### What I Did Myself:
1. **Lab Analysis:** Read and understood the lab requirements independently
2. **Problem Decomposition:** Broke down the lab into manageable tasks
3. **Critical Thinking:** Asked questions to deepen understanding
4. **Testing:** Ran experiments and verified results
5. **Interpretation:** Analyzed statistical results and drew conclusions
6. **Synthesis:** Connected lab concepts to real-world security
7. **Documentation:** Compiled findings into coherent reports

### Learning Outcomes:
- Deep understanding of symmetric encryption modes and their security properties
- Practical experience with cryptographic implementations
- Ability to analyze and demonstrate security vulnerabilities
- Understanding of key management and secure design principles
- Experience with security analysis and documentation

---

## Key Insights Gained

1. **Algorithm ≠ Security:** Even AES-128 fails to provide confidentiality with ECB mode
2. **Details Matter:** IVs, padding, and key management are critical
3. **Visual Learning:** Seeing pattern leakage is more impactful than reading about it
4. **Statistical Analysis:** Quantitative metrics validate security properties
5. **Defense in Depth:** Multiple security layers (encryption + authentication + key rotation)

---

## Acknowledgment

This lab was completed with AI assistance serving as:
- A knowledgeable teaching assistant for concept explanations
- A coding reference for library usage and best practices
- A debugging partner for troubleshooting issues
- A resource for security best practices and real-world context

However, all learning, understanding, testing, analysis, and conclusions are my own work. The AI served as a tool to facilitate learning, not to replace it.

---

**Academic Integrity Statement:**

I acknowledge that I used AI (Claude Code) as a learning tool throughout this lab. All prompts, questions, and interactions documented above demonstrate my active engagement with the material. I understand the concepts implemented, can explain the code, and have personally verified all results. The AI served as a teaching assistant, not as a substitute for learning.

**Signature:** [Your Name]
**Date:** November 7, 2025
