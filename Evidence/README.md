# VM evidence checklist

Keep original, readable evidence from the module Ubuntu VM in
`Codes/Evidence/` (this root checklist is not a submission artifact). Do not make
screenshots or CSV rows that imply a test was run when it was not. The coursework
ZIP must have exactly three top-level folders (`Codes`, `Report`, `Video`);
incorporate the required evidence into the report and video or keep supporting
files inside one of those folders before packaging.

- `Task1`: `nodes`, `net`, `dump`, full `pingall` under `learning_switch.py`,
  switch/controller connection, OpenFlow 1.3, and installed flow rules.
- `Task2`: authorized host to h7, h6 to h7 denied, h6 to a non-protected host,
  MAC learning, forwarding and policy rules, five-second idle timeout, and the
  table-miss rule after dynamic entries expire.
- `Task3`: ICMP, normal TCP, high-rate h8 TCP, flow/port CSVs, active-flow
  graph, and traffic-volume graph.
- `Task4`: low-rate no-alert, high-rate alert with measured rate and threshold,
  timed priority-500 rule, legitimate traffic during mitigation, h8 recovery,
  and `security_events.csv`.
- `Task5`: integrated run transcript and five independently measured rows with
  means for RTT, active flows, detection time, and mitigation response.

The currently bundled `PLACE_REAL_EVIDENCE_HERE.txt` files are reminders only.
