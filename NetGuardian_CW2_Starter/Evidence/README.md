# Evidence checklist — use real screenshots/logs from the module Ubuntu VM

## Task 1
- [ ] `nodes`, `net`, `dump` showing c0, s1-s3, h1-h8 and links
- [ ] `pingall` result
- [ ] s1-s3 connected to Ryu
- [ ] OpenFlow 1.3 confirmed on all switches
- [ ] `ovs-ofctl dump-flows` showing installed rules

## Task 2
- [ ] At least one authorized host reaches h7
- [ ] h6 -> h7 blocked
- [ ] h6 reaches a non-protected host
- [ ] Controller log shows MAC learning
- [ ] Forwarding and h6 -> h7 DROP rules visible
- [ ] Dynamic forwarding entries show idle_timeout=5
- [ ] Table-miss remains after dynamic entries expire

## Task 3
- [ ] ICMP generation
- [ ] Normal TCP generation
- [ ] Controlled high-rate TCP from h8 to h7
- [ ] Flow statistics and port statistics
- [ ] flow_stats.csv and port_stats.csv
- [ ] active_flows.png and traffic_volume.png
- [ ] Short normal/high-rate traffic comparison

## Task 4
- [ ] Low-rate h8 traffic does not trigger alert
- [ ] High-rate h8 traffic triggers alert
- [ ] Measured new-flow rate and threshold shown
- [ ] Security alert includes timestamp, source, rate and threshold
- [ ] High-priority DROP rule visible
- [ ] h8 -> h7 blocked during mitigation
- [ ] Legitimate host -> h7 still works
- [ ] h8 -> h7 restored after timeout
- [ ] security_events.csv

## Task 5
- [ ] One integrated demonstration of Tasks 1-4
- [ ] Five independent performance runs
- [ ] Four metrics recorded for every run
- [ ] Mean of each metric
- [ ] Discussion of variation

Use screenshots with readable terminal output and timestamps. Keep originals.
