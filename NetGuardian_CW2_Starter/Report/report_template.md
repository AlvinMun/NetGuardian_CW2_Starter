# NetGuardian: Enterprise SDN Management
## CSI201 Introduction to Networking — Coursework II

> DRAFT TEMPLATE ONLY. Replace every bracketed placeholder. Do not invent test
> results, references, implementation details, member names, or contributions.
> Format the final six-page report (excluding cover) using the IEEE conference
> double-column template and export as `Report_Coursework_II.pdf`.

### Cover page
- Team: [Team name / group number]
- Student 1: [Passport name] — [Student ID]
- Student 2: [Passport name] — [Student ID]
- Student 3: [Passport name] — [Student ID]
- Student 4: [Passport name] — [Student ID]
- Student 5: [Passport name] — [Student ID]
- [Adjust for actual team size]

### Abstract
[Summarise the enterprise SDN problem, the implemented NetGuardian functions,
the test environment, and the actual measured findings. Keep concise.]

### 1. Introduction
[Explain SDN, the enterprise management problem, objectives, and the platform's
implemented capabilities in your own words.]

### 2. Related Work
[Discuss genuine, relevant sources on SDN, OpenFlow forwarding, SDN monitoring,
access control, and intrusion detection/mitigation. Cite in IEEE style. Explain
the relationship between each source and your implementation.]

### 3. System Design
[Insert topology diagram matching the specification's Fig. 1.]
[Explain Ryu, OpenFlow switches, hosts, module interactions, MAC learning,
Layer-3 policy, flow five-tuple, new-flow-rate detection, mitigation and recovery.]
[Add an architecture diagram and IDS/mitigation flowchart.]

### 4. Implementation
[State actual Ubuntu VM and installed software versions. Describe topology.py,
controller.py, traffic_generator.py, monitoring.py and experiment.py. Explain
important implementation choices, CSV collection, graphs, and problems solved.]

### 5. Testing and Results
[Present actual evidence for Tasks 1–4 and the integrated Task 5 demonstration.]

#### Five independent performance runs
| Run | Average RTT (ms) | Active flows | Detection time (s) | Mitigation response (s) |
|---:|---:|---:|---:|---:|
| 1 | [measured] | [measured] | [measured] | [measured] |
| 2 | [measured] | [measured] | [measured] | [measured] |
| 3 | [measured] | [measured] | [measured] | [measured] |
| 4 | [measured] | [measured] | [measured] | [measured] |
| 5 | [measured] | [measured] | [measured] | [measured] |
| Mean | [calculated] | [calculated] | [calculated] | [calculated] |

[Discuss actual variation, normal vs high-rate traffic, threshold effectiveness,
legitimate host connectivity during mitigation, and recovery.]

### 6. Conclusion
[Summarise what was implemented and measured. State limitations and realistic
future improvements.]

### Acknowledgment
[Student full name] ([Student ID]): [XX]%; repeat for each team member.
Contribution percentages should total 100%.

### References
[Use genuine sources and IEEE reference formatting. Verify author, title, venue,
year, pages and DOI/URL before submission.]
