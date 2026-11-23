| Window | Variant | Run-level BA (AUC) | Attacks alarmed | Benign alarmed | First alarm (median) | Alarmed before any traffic | Floods blocked (mean) | Malware blocked (mean) |
|---|---|---|---|---|---|---|---|---|
| 0.50 s | 12B (110 runs) | 0.837 (0.972) | 67/67 | 14/43 | 0.50 s | 14 | 55% | 89% |
| 0.50 s | 12B, alarms only on traffic | 0.837 (0.972) | 67/67 | 14/43 | 0.50 s | 0 | 55% | 82% |
| 0.50 s | trained on all 240, the 110 | 0.837 (0.997) | 67/67 | 14/43 | 0.50 s | 0 | 55% | 82% |
| 0.50 s | trained on all 240, all 240 | 0.738 (0.694) | 67/114 | 14/126 | 0.50 s | 0 | 55% | 82% |
| 0.25 s | 12B (110 runs) | 0.830 (0.969) | 67/67 | 14/43 | 0.25 s | 14 | 71% | 89% |
| 0.25 s | 12B, alarms only on traffic | 0.830 (0.969) | 67/67 | 14/43 | 0.25 s | 0 | 71% | 82% |
| 0.25 s | trained on all 240, the 110 | 0.837 (0.997) | 67/67 | 14/43 | 0.25 s | 0 | 71% | 82% |
| 0.25 s | trained on all 240, all 240 | 0.738 (0.694) | 67/114 | 14/126 | 0.25 s | 0 | 71% | 82% |
| 0.10 s | 12B (110 runs) | 0.837 (0.969) | 67/67 | 14/43 | 0.10 s | 16 | 83% | 89% |
| 0.10 s | 12B, alarms only on traffic | 0.837 (0.969) | 67/67 | 14/43 | 0.10 s | 0 | 78% | 82% |
| 0.10 s | trained on all 240, the 110 | 0.837 (0.997) | 67/67 | 14/43 | 0.10 s | 0 | 78% | 82% |
| 0.10 s | trained on all 240, all 240 | 0.738 (0.694) | 67/114 | 14/126 | 0.10 s | 0 | 78% | 82% |
