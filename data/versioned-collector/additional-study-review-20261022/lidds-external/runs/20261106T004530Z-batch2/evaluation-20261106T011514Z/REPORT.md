# LID-DS 2021 check of the host, network and hybrid detectors

From `evaluation-20261106T011514Z` (protocol SHA-256 `d689c084bb3186fddcebfde8013965464b100b784efa80a8d140855d3bc0f444`). Offline; no VM, nothing executed.

## Data

LID-DS 2021 (Leipzig University) records real exploits against services in Docker containers, with
benign users whose timing comes from real web-server logs. Each recording has the victim container's
system calls and packet capture. All of its 15 scenarios were used:

| Scenario | Recordings | Attack windows | Normal windows | Skipped (shorter than 10 s) |
|---|---:|---:|---:|---:|
| Password brute force (CWE-307) | 1177 | 137 | 1038 | 2 |
| MySQL login bypass (CVE-2012-2122) | 1152 | 115 | 1032 | 5 |
| Heartbleed (CVE-2014-0160) | 1148 | 118 | 1028 | 2 |
| CouchDB privilege escalation + RCE (CVE-2017-12635/12636) | 1138 | 119 | 1017 | 2 |
| nginx range overflow (CVE-2017-7529) | 1110 | 72 | 923 | 115 |
| Sprockets path traversal (CVE-2018-3760) | 1129 | 121 | 1007 | 1 |
| Rails file disclosure (CVE-2019-5418) | 1150 | 110 | 1030 | 10 |
| Apache Unomi RCE (CVE-2020-13942) | 1145 | 100 | 1027 | 18 |
| CVE-2020-23839 | 1147 | 120 | 1027 | 0 |
| Tomcat session deserialization (CVE-2020-9484) | 1149 | 119 | 1029 | 1 |
| SQL injection (CWE-89) | 1150 | 120 | 1030 | 0 |
| EPS file upload (CWE-434) | 1150 | 120 | 1029 | 1 |
| OWASP Juice Shop | 1151 | 120 | 1030 | 1 |
| PHP upload to web shell (CWE-434) | 1147 | 115 | 1029 | 3 |
| ZipSlip archive path traversal | 1147 | 115 | 1029 | 3 |

One 10-s observation (20 windows of 0.5 s) per recording, with the paper's 90 host and 145 network
columns: the host features from the call-entry events of the victim's processes (`features/host_model.py`),
the network features from the frames of the victim's Ethernet interface through `features/switch_model.py`
(loopback frames dropped: a switch never sees them). Attack windows start 2 s before the logged attack
time; normal windows follow the same rule around a pseudo attack time drawn from the same scenario's
attack offsets. Controls: a second window of every normal recording placed near its end the way attack
windows are; never trained on.

## E1. Unseen attack type: leave one scenario out (primary)

Mean over the 15 held-out scenarios:

| Detector | Bal. acc. | Attack recall | False alarms (normal) | False alarms (end control) | AUC |
|---|---:|---:|---:|---:|---:|
| host-only | 51.9% | 5.7% | 1.9% | 2.2% | 0.730 |
| network-only | 59.6% | 25.4% | 6.2% | 9.3% | 0.760 |
| hybrid | 64.8% | 57.3% | 27.7% | 28.1% | 0.753 |
| concatenated | 58.6% | 21.9% | 4.8% | 6.4% | 0.780 |
| activity-only | 53.1% | 12.7% | 6.5% | 7.8% | 0.572 |
| position-only | 80.9% | 66.7% | 4.8% | 18.5% | 0.940 |

**Held out: Password brute force (CWE-307)**

| Detector | Bal. acc. | Attack recall | False alarms (normal) | False alarms (end control) | AUC |
|---|---:|---:|---:|---:|---:|
| host-only | 51.1% | 2.2% | 0.0% | 0.1% | 0.978 |
| network-only | 93.4% | 86.9% | 0.0% | 0.0% | 1.000 |
| hybrid | 98.1% | 96.4% | 0.1% | 0.2% | 0.999 |
| concatenated | 94.2% | 88.3% | 0.0% | 0.0% | 0.999 |
| activity-only | 59.1% | 19.7% | 1.4% | 0.8% | 0.488 |
| position-only | 90.4% | 81.0% | 0.2% | 6.2% | 0.998 |
**Held out: MySQL login bypass (CVE-2012-2122)**

| Detector | Bal. acc. | Attack recall | False alarms (normal) | False alarms (end control) | AUC |
|---|---:|---:|---:|---:|---:|
| host-only | 50.0% | 0.0% | 0.0% | 0.0% | 0.735 |
| network-only | 82.6% | 65.2% | 0.0% | 0.0% | 0.921 |
| hybrid | 82.5% | 65.2% | 0.2% | 1.0% | 0.763 |
| concatenated | 80.0% | 60.0% | 0.0% | 0.0% | 0.967 |
| activity-only | 50.0% | 0.0% | 0.0% | 0.0% | 0.821 |
| position-only | 88.4% | 78.3% | 1.6% | 2.4% | 0.991 |
**Held out: Heartbleed (CVE-2014-0160)**

| Detector | Bal. acc. | Attack recall | False alarms (normal) | False alarms (end control) | AUC |
|---|---:|---:|---:|---:|---:|
| host-only | 50.0% | 0.0% | 0.0% | 0.0% | 0.683 |
| network-only | 51.9% | 4.2% | 0.4% | 1.0% | 0.826 |
| hybrid | 50.9% | 5.1% | 3.2% | 4.5% | 0.790 |
| concatenated | 50.0% | 0.0% | 0.0% | 0.0% | 0.826 |
| activity-only | 50.0% | 0.0% | 0.0% | 0.0% | 0.464 |
| position-only | 89.5% | 80.5% | 1.6% | 36.9% | 0.992 |
**Held out: CouchDB privilege escalation + RCE (CVE-2017-12635/12636)**

| Detector | Bal. acc. | Attack recall | False alarms (normal) | False alarms (end control) | AUC |
|---|---:|---:|---:|---:|---:|
| host-only | 50.0% | 0.0% | 0.0% | 0.0% | 0.971 |
| network-only | 100.0% | 100.0% | 0.0% | 0.0% | 1.000 |
| hybrid | 99.8% | 100.0% | 0.4% | 2.1% | 1.000 |
| concatenated | 94.1% | 88.2% | 0.0% | 0.0% | 1.000 |
| activity-only | 49.9% | 0.0% | 0.3% | 1.2% | 0.481 |
| position-only | 67.0% | 35.3% | 1.4% | 26.4% | 0.937 |
**Held out: nginx range overflow (CVE-2017-7529)**

| Detector | Bal. acc. | Attack recall | False alarms (normal) | False alarms (end control) | AUC |
|---|---:|---:|---:|---:|---:|
| host-only | 50.7% | 1.4% | 0.0% | 0.0% | 0.998 |
| network-only | 42.2% | 1.4% | 16.9% | 28.7% | 0.498 |
| hybrid | 64.2% | 98.6% | 70.2% | 60.3% | 0.831 |
| concatenated | 47.4% | 0.0% | 5.2% | 6.1% | 0.435 |
| activity-only | 79.0% | 65.3% | 7.3% | 4.7% | 0.874 |
| position-only | 81.2% | 98.6% | 36.3% | 71.1% | 0.884 |
**Held out: Sprockets path traversal (CVE-2018-3760)**

| Detector | Bal. acc. | Attack recall | False alarms (normal) | False alarms (end control) | AUC |
|---|---:|---:|---:|---:|---:|
| host-only | 50.0% | 0.0% | 0.0% | 0.0% | 0.469 |
| network-only | 57.9% | 15.7% | 0.0% | 1.4% | 0.726 |
| hybrid | 58.7% | 45.5% | 28.1% | 26.6% | 0.633 |
| concatenated | 57.9% | 15.7% | 0.0% | 1.8% | 0.824 |
| activity-only | 49.7% | 2.5% | 3.2% | 7.9% | 0.474 |
| position-only | 84.3% | 69.4% | 0.9% | 18.6% | 0.994 |
**Held out: Rails file disclosure (CVE-2019-5418)**

| Detector | Bal. acc. | Attack recall | False alarms (normal) | False alarms (end control) | AUC |
|---|---:|---:|---:|---:|---:|
| host-only | 50.0% | 0.0% | 0.0% | 0.0% | 0.457 |
| network-only | 50.0% | 0.0% | 0.0% | 0.0% | 0.609 |
| hybrid | 51.3% | 2.7% | 0.2% | 1.5% | 0.505 |
| concatenated | 50.0% | 0.0% | 0.0% | 0.0% | 0.798 |
| activity-only | 52.9% | 6.4% | 0.5% | 0.2% | 0.489 |
| position-only | 89.7% | 82.7% | 3.4% | 5.0% | 0.987 |
**Held out: Apache Unomi RCE (CVE-2020-13942)**

| Detector | Bal. acc. | Attack recall | False alarms (normal) | False alarms (end control) | AUC |
|---|---:|---:|---:|---:|---:|
| host-only | 50.0% | 0.0% | 0.0% | 0.0% | 0.686 |
| network-only | 51.6% | 4.0% | 0.9% | 0.3% | 0.720 |
| hybrid | 51.0% | 18.0% | 16.1% | 2.0% | 0.722 |
| concatenated | 50.0% | 0.0% | 0.0% | 0.0% | 0.643 |
| activity-only | 49.8% | 0.0% | 0.5% | 3.9% | 0.502 |
| position-only | 93.5% | 87.0% | 0.0% | 6.3% | 1.000 |
**Held out: CVE-2020-23839**

| Detector | Bal. acc. | Attack recall | False alarms (normal) | False alarms (end control) | AUC |
|---|---:|---:|---:|---:|---:|
| host-only | 57.9% | 15.8% | 0.0% | 0.0% | 0.705 |
| network-only | 50.8% | 1.7% | 0.0% | 0.0% | 0.951 |
| hybrid | 75.5% | 51.7% | 0.6% | 0.5% | 0.836 |
| concatenated | 50.4% | 0.8% | 0.0% | 0.0% | 0.894 |
| activity-only | 49.6% | 0.0% | 0.8% | 1.2% | 0.578 |
| position-only | 53.4% | 20.0% | 13.2% | 11.9% | 0.589 |
**Held out: Tomcat session deserialization (CVE-2020-9484)**

| Detector | Bal. acc. | Attack recall | False alarms (normal) | False alarms (end control) | AUC |
|---|---:|---:|---:|---:|---:|
| host-only | 50.0% | 0.0% | 0.0% | 0.0% | 0.926 |
| network-only | 52.0% | 72.3% | 68.2% | 88.0% | 0.502 |
| hybrid | 56.7% | 88.2% | 74.9% | 91.5% | 0.611 |
| concatenated | 45.7% | 58.0% | 66.6% | 87.7% | 0.497 |
| activity-only | 47.1% | 68.9% | 74.6% | 88.7% | 0.467 |
| position-only | 75.2% | 52.1% | 1.7% | 13.1% | 0.980 |
**Held out: SQL injection (CWE-89)**

| Detector | Bal. acc. | Attack recall | False alarms (normal) | False alarms (end control) | AUC |
|---|---:|---:|---:|---:|---:|
| host-only | 50.1% | 0.8% | 0.7% | 0.7% | 0.852 |
| network-only | 50.4% | 0.8% | 0.0% | 0.0% | 0.998 |
| hybrid | 64.1% | 30.0% | 1.8% | 4.9% | 0.965 |
| concatenated | 50.8% | 1.7% | 0.0% | 0.0% | 0.997 |
| activity-only | 49.8% | 0.8% | 1.2% | 1.4% | 0.557 |
| position-only | 52.5% | 5.8% | 0.8% | 0.7% | 0.835 |
**Held out: EPS file upload (CWE-434)**

| Detector | Bal. acc. | Attack recall | False alarms (normal) | False alarms (end control) | AUC |
|---|---:|---:|---:|---:|---:|
| host-only | 55.8% | 11.7% | 0.1% | 3.7% | 0.521 |
| network-only | 50.2% | 0.8% | 0.5% | 4.6% | 0.799 |
| hybrid | 51.1% | 99.2% | 97.0% | 96.3% | 0.711 |
| concatenated | 50.8% | 1.7% | 0.0% | 0.1% | 0.871 |
| activity-only | 50.0% | 1.7% | 1.7% | 1.7% | 0.548 |
| position-only | 92.7% | 85.8% | 0.4% | 14.9% | 0.998 |
**Held out: OWASP Juice Shop**

| Detector | Bal. acc. | Attack recall | False alarms (normal) | False alarms (end control) | AUC |
|---|---:|---:|---:|---:|---:|
| host-only | 50.4% | 0.8% | 0.0% | 0.2% | 0.591 |
| network-only | 52.4% | 11.7% | 6.8% | 15.8% | 0.527 |
| hybrid | 53.4% | 35.0% | 28.3% | 42.5% | 0.556 |
| concatenated | 50.0% | 0.0% | 0.0% | 0.0% | 0.551 |
| activity-only | 51.5% | 3.3% | 0.3% | 1.5% | 0.623 |
| position-only | 83.0% | 70.0% | 4.0% | 12.3% | 0.954 |
**Held out: PHP upload to web shell (CWE-434)**

| Detector | Bal. acc. | Attack recall | False alarms (normal) | False alarms (end control) | AUC |
|---|---:|---:|---:|---:|---:|
| host-only | 52.4% | 5.2% | 0.4% | 0.0% | 0.722 |
| network-only | 57.8% | 15.7% | 0.0% | 0.0% | 0.667 |
| hybrid | 61.3% | 24.3% | 1.8% | 0.0% | 0.692 |
| concatenated | 57.0% | 13.9% | 0.0% | 0.0% | 0.779 |
| activity-only | 50.4% | 1.7% | 1.0% | 0.3% | 0.618 |
| position-only | 86.3% | 73.0% | 0.5% | 2.7% | 0.996 |
**Held out: ZipSlip archive path traversal**

| Detector | Bal. acc. | Attack recall | False alarms (normal) | False alarms (end control) | AUC |
|---|---:|---:|---:|---:|---:|
| host-only | 60.0% | 47.0% | 27.0% | 27.6% | 0.655 |
| network-only | 50.0% | 0.0% | 0.0% | 0.0% | 0.659 |
| hybrid | 54.0% | 100.0% | 92.0% | 87.1% | 0.680 |
| concatenated | 50.0% | 0.0% | 0.0% | 0.0% | 0.613 |
| activity-only | 57.7% | 20.9% | 5.4% | 4.3% | 0.595 |
| position-only | 87.2% | 80.9% | 6.5% | 49.0% | 0.967 |

## E2. Seen attack types: 5-fold cross-validation over the pooled scenarios

Pooled:

| Detector | Bal. acc. | Attack recall | False alarms (normal) | False alarms (end control) | AUC |
|---|---:|---:|---:|---:|---:|
| host-only | 85.8% | 71.8% | 0.1% | 0.9% | 0.982 |
| network-only | 88.4% | 76.8% | 0.1% | 0.3% | 0.991 |
| hybrid | 96.1% | 94.2% | 2.0% | 5.9% | 0.995 |
| concatenated | 91.2% | 82.5% | 0.0% | 0.2% | 0.996 |
| activity-only | 70.4% | 42.1% | 1.3% | 2.0% | 0.807 |
| position-only | 84.0% | 70.7% | 2.7% | 17.6% | 0.970 |

**Password brute force (CWE-307)**

| Detector | Bal. acc. | Attack recall | False alarms (normal) | False alarms (end control) | AUC |
|---|---:|---:|---:|---:|---:|
| host-only | 98.2% | 96.4% | 0.0% | 0.1% | 0.999 |
| network-only | 99.3% | 98.5% | 0.0% | 0.0% | 1.000 |
| hybrid | 99.9% | 100.0% | 0.3% | 0.3% | 1.000 |
| concatenated | 98.9% | 97.8% | 0.0% | 0.0% | 1.000 |
| activity-only | 96.6% | 93.4% | 0.2% | 0.1% | 0.997 |
| position-only | 93.3% | 86.9% | 0.3% | 6.6% | 0.998 |
**MySQL login bypass (CVE-2012-2122)**

| Detector | Bal. acc. | Attack recall | False alarms (normal) | False alarms (end control) | AUC |
|---|---:|---:|---:|---:|---:|
| host-only | 98.7% | 97.4% | 0.0% | 0.0% | 1.000 |
| network-only | 98.7% | 97.4% | 0.0% | 0.0% | 1.000 |
| hybrid | 99.9% | 100.0% | 0.2% | 0.2% | 1.000 |
| concatenated | 99.1% | 98.3% | 0.0% | 0.0% | 1.000 |
| activity-only | 82.5% | 65.2% | 0.3% | 0.3% | 0.817 |
| position-only | 89.7% | 80.9% | 1.6% | 2.3% | 0.993 |
**Heartbleed (CVE-2014-0160)**

| Detector | Bal. acc. | Attack recall | False alarms (normal) | False alarms (end control) | AUC |
|---|---:|---:|---:|---:|---:|
| host-only | 80.0% | 60.2% | 0.1% | 0.0% | 0.988 |
| network-only | 99.6% | 99.2% | 0.0% | 0.0% | 1.000 |
| hybrid | 99.8% | 100.0% | 0.5% | 0.5% | 1.000 |
| concatenated | 99.6% | 99.2% | 0.0% | 0.0% | 1.000 |
| activity-only | 58.4% | 18.6% | 1.8% | 1.8% | 0.705 |
| position-only | 94.2% | 89.0% | 0.7% | 37.5% | 0.997 |
**CouchDB privilege escalation + RCE (CVE-2017-12635/12636)**

| Detector | Bal. acc. | Attack recall | False alarms (normal) | False alarms (end control) | AUC |
|---|---:|---:|---:|---:|---:|
| host-only | 99.6% | 99.2% | 0.0% | 0.0% | 1.000 |
| network-only | 100.0% | 100.0% | 0.0% | 0.0% | 1.000 |
| hybrid | 100.0% | 100.0% | 0.0% | 0.2% | 1.000 |
| concatenated | 100.0% | 100.0% | 0.0% | 0.0% | 1.000 |
| activity-only | 99.5% | 99.2% | 0.1% | 0.1% | 1.000 |
| position-only | 70.7% | 42.9% | 1.5% | 29.7% | 0.969 |
**nginx range overflow (CVE-2017-7529)**

| Detector | Bal. acc. | Attack recall | False alarms (normal) | False alarms (end control) | AUC |
|---|---:|---:|---:|---:|---:|
| host-only | 97.2% | 94.4% | 0.0% | 0.0% | 1.000 |
| network-only | 99.3% | 98.6% | 0.0% | 0.0% | 1.000 |
| hybrid | 99.8% | 100.0% | 0.3% | 0.0% | 1.000 |
| concatenated | 99.3% | 98.6% | 0.0% | 0.0% | 1.000 |
| activity-only | 95.8% | 91.7% | 0.0% | 0.0% | 0.997 |
| position-only | 76.6% | 77.8% | 24.5% | 64.7% | 0.859 |
**Sprockets path traversal (CVE-2018-3760)**

| Detector | Bal. acc. | Attack recall | False alarms (normal) | False alarms (end control) | AUC |
|---|---:|---:|---:|---:|---:|
| host-only | 94.0% | 88.4% | 0.5% | 0.4% | 0.998 |
| network-only | 70.9% | 42.1% | 0.3% | 1.6% | 0.967 |
| hybrid | 96.9% | 97.5% | 3.8% | 23.0% | 0.997 |
| concatenated | 92.1% | 84.3% | 0.1% | 2.2% | 0.998 |
| activity-only | 58.0% | 18.2% | 2.2% | 10.6% | 0.586 |
| position-only | 89.3% | 79.3% | 0.7% | 18.3% | 0.996 |
**Rails file disclosure (CVE-2019-5418)**

| Detector | Bal. acc. | Attack recall | False alarms (normal) | False alarms (end control) | AUC |
|---|---:|---:|---:|---:|---:|
| host-only | 84.9% | 70.0% | 0.2% | 0.5% | 0.965 |
| network-only | 74.3% | 49.1% | 0.6% | 0.8% | 0.958 |
| hybrid | 90.8% | 86.4% | 4.8% | 10.4% | 0.974 |
| concatenated | 82.3% | 64.5% | 0.0% | 0.0% | 0.979 |
| activity-only | 54.8% | 10.9% | 1.3% | 0.8% | 0.666 |
| position-only | 90.1% | 83.6% | 3.4% | 5.0% | 0.985 |
**Apache Unomi RCE (CVE-2020-13942)**

| Detector | Bal. acc. | Attack recall | False alarms (normal) | False alarms (end control) | AUC |
|---|---:|---:|---:|---:|---:|
| host-only | 52.5% | 5.0% | 0.0% | 0.0% | 0.906 |
| network-only | 84.0% | 68.0% | 0.1% | 0.0% | 0.991 |
| hybrid | 95.5% | 94.0% | 3.0% | 0.5% | 0.994 |
| concatenated | 82.5% | 65.0% | 0.0% | 0.0% | 0.994 |
| activity-only | 51.8% | 4.0% | 0.5% | 3.9% | 0.534 |
| position-only | 94.5% | 89.0% | 0.0% | 5.8% | 1.000 |
**CVE-2020-23839**

| Detector | Bal. acc. | Attack recall | False alarms (normal) | False alarms (end control) | AUC |
|---|---:|---:|---:|---:|---:|
| host-only | 97.9% | 95.8% | 0.0% | 0.1% | 1.000 |
| network-only | 97.1% | 94.2% | 0.0% | 0.0% | 1.000 |
| hybrid | 99.9% | 100.0% | 0.3% | 0.5% | 1.000 |
| concatenated | 97.9% | 95.8% | 0.0% | 0.0% | 1.000 |
| activity-only | 69.2% | 40.0% | 1.6% | 1.6% | 0.932 |
| position-only | 61.8% | 26.7% | 3.1% | 6.9% | 0.734 |
**Tomcat session deserialization (CVE-2020-9484)**

| Detector | Bal. acc. | Attack recall | False alarms (normal) | False alarms (end control) | AUC |
|---|---:|---:|---:|---:|---:|
| host-only | 99.2% | 98.3% | 0.0% | 0.0% | 1.000 |
| network-only | 97.9% | 95.8% | 0.0% | 0.3% | 1.000 |
| hybrid | 99.8% | 100.0% | 0.5% | 1.2% | 1.000 |
| concatenated | 100.0% | 100.0% | 0.0% | 0.0% | 1.000 |
| activity-only | 57.3% | 18.5% | 3.8% | 1.8% | 0.553 |
| position-only | 82.3% | 66.4% | 1.8% | 13.2% | 0.986 |
**SQL injection (CWE-89)**

| Detector | Bal. acc. | Attack recall | False alarms (normal) | False alarms (end control) | AUC |
|---|---:|---:|---:|---:|---:|
| host-only | 100.0% | 100.0% | 0.0% | 0.0% | 1.000 |
| network-only | 100.0% | 100.0% | 0.0% | 0.0% | 1.000 |
| hybrid | 99.7% | 100.0% | 0.7% | 0.0% | 1.000 |
| concatenated | 100.0% | 100.0% | 0.0% | 0.0% | 1.000 |
| activity-only | 96.8% | 94.2% | 0.5% | 0.7% | 0.999 |
| position-only | 63.9% | 28.3% | 0.5% | 0.9% | 0.973 |
**EPS file upload (CWE-434)**

| Detector | Bal. acc. | Attack recall | False alarms (normal) | False alarms (end control) | AUC |
|---|---:|---:|---:|---:|---:|
| host-only | 95.0% | 90.0% | 0.1% | 9.0% | 0.999 |
| network-only | 97.1% | 94.2% | 0.0% | 0.5% | 1.000 |
| hybrid | 99.7% | 100.0% | 0.6% | 31.0% | 1.000 |
| concatenated | 97.9% | 95.8% | 0.0% | 0.4% | 1.000 |
| activity-only | 61.1% | 23.3% | 1.1% | 4.2% | 0.760 |
| position-only | 94.0% | 88.3% | 0.3% | 15.7% | 0.999 |
**OWASP Juice Shop**

| Detector | Bal. acc. | Attack recall | False alarms (normal) | False alarms (end control) | AUC |
|---|---:|---:|---:|---:|---:|
| host-only | 55.6% | 11.7% | 0.4% | 0.6% | 0.691 |
| network-only | 67.9% | 35.8% | 0.1% | 0.8% | 0.904 |
| hybrid | 78.4% | 63.3% | 6.5% | 9.6% | 0.893 |
| concatenated | 65.4% | 30.8% | 0.0% | 0.0% | 0.909 |
| activity-only | 55.8% | 13.3% | 1.7% | 2.3% | 0.600 |
| position-only | 85.2% | 72.5% | 2.0% | 10.4% | 0.982 |
**PHP upload to web shell (CWE-434)**

| Detector | Bal. acc. | Attack recall | False alarms (normal) | False alarms (end control) | AUC |
|---|---:|---:|---:|---:|---:|
| host-only | 72.2% | 44.3% | 0.0% | 0.0% | 0.978 |
| network-only | 58.7% | 17.4% | 0.0% | 0.0% | 0.909 |
| hybrid | 90.8% | 85.2% | 3.7% | 0.4% | 0.979 |
| concatenated | 71.3% | 42.6% | 0.0% | 0.0% | 0.990 |
| activity-only | 57.8% | 17.4% | 1.7% | 0.3% | 0.647 |
| position-only | 88.4% | 77.4% | 0.6% | 2.2% | 0.997 |
**ZipSlip archive path traversal**

| Detector | Bal. acc. | Attack recall | False alarms (normal) | False alarms (end control) | AUC |
|---|---:|---:|---:|---:|---:|
| host-only | 58.7% | 17.4% | 0.0% | 2.0% | 0.790 |
| network-only | 81.1% | 62.6% | 0.4% | 1.0% | 0.970 |
| hybrid | 91.8% | 87.8% | 4.3% | 10.2% | 0.957 |
| concatenated | 81.1% | 62.6% | 0.5% | 0.8% | 0.966 |
| activity-only | 62.4% | 27.0% | 2.2% | 1.2% | 0.750 |
| position-only | 87.0% | 76.5% | 2.4% | 50.4% | 0.980 |

## Checks

- Extraction: batch 1 (5 scenarios) as before; batch 2 (10 scenarios, 82.5 GB bundle, SHA-256 in
  `../deleted_raw_files.json`) with the streaming version of `prepare_lidds.py`, which gives the same
  spans, events and rows as the whole-file version on 51 real recordings of all 10 scenarios (including a
  700 MB trace) and on 4,000 synthetic traces cut into 1-23-byte chunks.
- Network: packet and byte totals of 20 batch-2 windows (one attack and one normal per scenario)
  recomputed with tshark from the original cooked captures (IPv4 TCP/UDP frames of non-loopback devices,
  Ethernet framing): all 20 equal to the extracted rows (batch 1: 10 of 10).
- Host: the summed call count of every window equals the number of call-entry events in it, in all
  21,412 batch-2 rows (and all batch-1 rows).
- No extraction errors. 164 of 17,190 recordings are shorter than the 10-s window and were skipped
  (12 of 5,774 in batch 1, 152 of 11,416 in batch 2); 115 of them are nginx (CVE-2017-7529), including 47 of its 119 attack
  recordings, so its attack windows are the 72 recordings with at least 10 s of capture.
- Rows: 1,721 attack, 15,305 normal, 15,305 end-control windows.

## Reading

**Attack types seen in training (E2).** Combining the sensors gives the best detector. At the same
false-alarm rate on normal windows, attack recall (pooled out-of-fold scores; computed after scoring,
not part of the protocol):

| False alarms | Host-only | Network-only | Hybrid (stacked) | Concatenated |
|---:|---:|---:|---:|---:|
| 0.1% | 72.1% | 76.8% | 81.9% | 85.8% |
| 1% | 81.3% | 86.3% | 91.6% | 92.2% |
| 2% | 84.4% | 89.5% | 94.3% | 94.5% |
| 5% | 89.5% | 93.8% | 96.8% | 98.0% |

At the same false-alarm rate, both sensors together catch 3 to 9 points more attacks than the better single
sensor (the network sensor at every rate): the stacked hybrid 3.0 to 5.2 points, the concatenated forest 4.1
to 8.9 points. (Corrected 2026-11-06: this sentence first said "5-10 points", which overstated the hybrid's
gain; the table above is unchanged. Ten fold assignments: `../repeat-e2-*/`.) The stacked hybrid ranks like the concatenated forest (AUC 0.995 vs 0.996); its higher balanced
accuracy at threshold 0.5 (96.1% vs 91.2%) comes from its operating point (recall 94.2% at 2.0% false
alarms, against 82.5% at 0.0%), not from a better ranking. Per scenario the hybrid is at least as good as
the better sensor in 14 of 15 (SQL injection: 99.7% vs 100%), and gains most where one sensor is weak:
PHP web shell (host 72.2%, network 58.7%, hybrid 90.8%), Apache Unomi (52.5%, 84.0%, 95.5%), ZipSlip
(58.7%, 81.1%, 91.8%), Juice Shop (55.6%, 67.9%, 78.4%).

**Unseen service and exploit (E1).** Nothing transfers to a new service at the learned threshold. The
host detector flags almost nothing (mean recall 5.7%, balanced accuracy 51.9%); the network detector
catches only attacks with a strong traffic signature (CouchDB 100%, password brute force 93.4%, MySQL
login bypass 82.6%; most others near 50%); the hybrid's higher mean (64.8%) comes with 27.7% false alarms
on normal windows. Ranking transfers better than thresholds (mean AUC 0.73-0.78; e.g. SQL injection:
network AUC 0.998 at balanced accuracy 50.4%): each service has its own normal level. With a threshold set
on each held-out service's own normal windows to 2% false alarms (an optimistic diagnostic: it uses that
service's normal data), about a third of its attacks are caught by every detector (host 36.9%, network
34.4%, hybrid 32.2%, concatenated 37.4%), so fusion adds nothing on unseen services. Detecting attacks on a
new service needs that service's own normal behavior, which is how LID-DS is meant to be used (anomaly
detection trained on each scenario's normal recordings).

**Position control.** A forest on window position alone scores 80.9% (E1) and 84.0% (E2), because attack
windows sit near the end of short recordings. The content models flag few end-control windows (E2:
0.2-0.9% for the single sensors and the concatenated forest; hybrid 5.9% against 2.0% on normal
windows), so they detect attack content rather than position, with a small end-of-recording effect in the
hybrid. Compared with the five-scenario batch 1, the E2 numbers are similar (hybrid 97.8% there) and the
E1 means are lower (network 73.8% there): with 14 training services the network detector no longer flags
SQL injection (85.8% in batch 1, 50.4% here), so what transfers depends on the training mix.

## Limits

- 10-s windows (the paper uses 20 s) because attack recordings are short; sysdig traces instead of the
  paper's eBPF collector; one victim container per recording; cooked captures rewritten to Ethernet
  framing. The paper's models were not applied; every model here was trained on LID-DS.
- One exploit per scenario; attack windows within a scenario come from the same exploit and service, so
  they are not independent attacks (about 72-137 attack windows per scenario).
- Skipped recordings are not random (nginx: 47 of 119 attack recordings).
- The matched-false-alarm tables were computed after scoring from the saved out-of-fold scores.
- Batch-1 rows were extracted with the whole-file version of the extractor before its raw data was
  deleted; the streaming version was shown equal on batch-2 data, not re-run on batch 1.
