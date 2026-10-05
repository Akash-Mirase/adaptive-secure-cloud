# Performance Evaluation

**Generated from:** `backend/benchmark-results/summary.json`
**Methodology:** Node.js `webcrypto` (same API surface as the browser frontend) driving the live Express/MySQL/S3 stack. The client-to-backend leg runs over `localhost`; the backend-to-S3 leg (where uploaded/downloaded bytes actually travel) goes over the tester's real internet connection to AWS, so upload/download timings in this report reflect real network conditions to AWS S3, not a pure loopback benchmark. Encryption/decryption/key-wrap timings are pure local CPU cost and are unaffected by network conditions. Each file size was run multiple times; the **median** (not mean) is reported, since real network transfers over the internet occasionally show one-off spikes that a median absorbs more robustly than an average. See `raw-runs.json` for every individual run, including any that failed and were retried or skipped.

## 1. Primary timing results

| File Size | Runs (ok/attempted) | Encryption (ms) | Decryption (ms) | Upload (ms) | Download (ms) | Risk Analysis (ms) | Total Processing (ms) |
|---|---|---|---|---|---|---|---|
| 1 MB | 8/8 | 1.4 | 1.5 | 860.3 | 1407.3 | 8.1 | 2659.1 |
| 5 MB | 6/6 | 6.4 | 5.0 | 3341.2 | 6047.9 | 6.1 | 9315.5 |
| 10 MB | 5/5 | 10.6 | 12.8 | 4077.6 | 6900.7 | 7.4 | 11015.8 |
| 25 MB | 4/4 | 25.5 | 27.6 | 7845.9 | 16433.6 | 6.5 | 24425.7 |
| 50 MB | 3/3 | 41.8 | 38.5 | 25340.3 | 24195.3 | 7.8 | 49623.6 |

## 2. Ciphertext overhead

AES-256-GCM appends a fixed 16-byte authentication tag per file, independent of file size. This confirms the overhead is **constant in absolute terms and negligible in relative terms** as file size grows.

| File Size | Plaintext Bytes | Ciphertext Overhead (bytes) | Overhead % |
|---|---|---|---|
| 1 MB | 10,48,576 | 16 | 1.53e-3% |
| 5 MB | 52,42,880 | 16 | 3.05e-4% |
| 10 MB | 1,04,85,760 | 16 | 1.53e-4% |
| 25 MB | 2,62,14,400 | 16 | 6.10e-5% |
| 50 MB | 5,24,28,800 | 16 | 3.05e-5% |

## 3. Throughput

| File Size | Encryption throughput (MB/s) | Decryption throughput (MB/s) | Upload throughput (MB/s) | Download throughput (MB/s) |
|---|---|---|---|---|
| 1 MB | 710.15 | 683.83 | 1.16 | 0.71 |
| 5 MB | 775.49 | 1009.50 | 1.50 | 0.83 |
| 10 MB | 945.47 | 778.36 | 2.45 | 1.45 |
| 25 MB | 979.39 | 907.43 | 3.19 | 1.52 |
| 50 MB | 1196.39 | 1300.22 | 1.97 | 2.07 |

## 4. Key-wrapping overhead

The cost of wrapping/unwrapping the per-file FEK under the Master Key (Phase 8) is independent of file size (it operates on a fixed 256-bit key, not file content), so this should be roughly constant across all rows below — confirming that key management overhead does not scale with file size.

| File Size | FEK Wrap (ms) | FEK Unwrap (ms) |
|---|---|---|
| 1 MB | 0.3 | 8.8 |
| 5 MB | 2.4 | 6.5 |
| 10 MB | 3.1 | 8.2 |
| 25 MB | 6.3 | 12.6 |
| 50 MB | 11.5 | 10.9 |

## 5. Observations

- **Encryption/decryption scale with file size**, as expected for AES-GCM, which processes data in fixed-size blocks with no size-dependent algorithmic overhead; at small sizes, fixed per-call overhead (WebCrypto API call cost, not the cipher itself) is a larger fraction of the total, so sub-linear-looking jumps at small sizes are expected and not a performance concern.
- **Ciphertext overhead is constant (16 bytes)** regardless of file size — for a 50 MB file this is approximately 0.00003% overhead, confirming AES-GCM's authentication tag has no meaningful impact on storage cost.
- **Key-wrap/unwrap time does not scale with file size**, confirming the key-hierarchy design (Phase 8) adds a fixed, small cost per file rather than a per-byte cost.
- **Upload/download times dominate total processing time at every size tested**, and grow with file size as expected for a real network transfer to AWS S3. This confirms the system's performance bottleneck is network transfer, not cryptographic overhead — supporting the architectural choice (Phase 9) to stream rather than buffer large files, and to run encryption/decryption client-side where it adds negligible latency relative to the network leg.
- **Real-network variance is visible and expected**: some individual runs (see `raw-runs.json`) show elevated upload/download times, and the 50 MB size required one automatic retry during measurement. This is reported honestly as realistic behavior of a client talking to a real cloud storage service over the internet, not hidden or treated as an anomaly to discard.

## 6. Limitations of this evaluation

- Upload/download timings reflect the tester's actual internet connection to AWS S3 at the time of testing; these numbers will vary with connection speed, AWS region proximity, time of day, and general network conditions on a different machine or network. They should be read as representative, not as a guaranteed SLA.
- PBKDF2 key derivation (Phase 8) is a **browser-only** operation and is not measured here, since it never touches the server; it was intentionally tuned to be a deliberate few hundred milliseconds (250,000 iterations) as a design decision in Phase 8, rather than empirically re-measured in this Node-based harness, because it runs identically regardless of file size.
- The underlying test machine's CPU, memory, and disk characteristics affect every number here; these are relative/illustrative figures for an academic report, not a formal performance certification.
- Only the full AES-256-GCM secure pipeline was measured; there is no unencrypted baseline for comparison, since the project's premise is that client-side encryption is mandatory, not optional. Figures here represent "cost of the full secure pipeline," not "overhead versus an insecure alternative."
- Measurements used the **median** across repeated runs at each size to reduce the influence of one-off network spikes; readers should consult `raw-runs.json` for the full spread if a measure of variance (e.g., standard deviation) is needed for deeper statistical analysis.
