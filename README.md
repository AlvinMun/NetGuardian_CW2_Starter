# NetGuardian — CSI201 Coursework II

This folder contains the coursework implementation and its VM test workflow.
The brief requires Ubuntu, Mininet, Ryu, and Open vSwitch from the module VM.
No extra Python packages are needed by the submitted code. The VM tests and
performance measurements must be run there before the report is finalised.

The topology follows Fig. 1 and Table 1 of the brief: controller `c0` at
`127.0.0.1:6633`, switches `s1`–`s3`, and hosts `h1`–`h8`. Task 1 uses a
policy-free learning switch; the NetGuardian controller enforces the Task 2
guest restriction and therefore intentionally blocks `h6 -> h7`.

## Task 1: topology and full connectivity

Open two Ubuntu terminals. In terminal 1, from `Codes`:

```bash
ryu-manager learning_switch.py
```

In terminal 2:

```bash
cd ~/NetGuardian_CW2_Starter/Codes
sudo python3 topology.py
```

At the Mininet prompt, capture the required evidence:

```text
nodes
net
dump
pingall
sh ovs-vsctl get Bridge s1 protocols
sh ovs-vsctl get Bridge s2 protocols
sh ovs-vsctl get Bridge s3 protocols
sh ovs-ofctl -O OpenFlow13 dump-flows s1
sh ovs-ofctl -O OpenFlow13 dump-flows s2
sh ovs-ofctl -O OpenFlow13 dump-flows s3
```

`pingall` should have no loss in this Task 1 run. Save genuine screenshots in
`Codes/Evidence/Task1`. Exit Mininet with `exit` and stop the learning controller with
Ctrl+C before starting Task 2.

## Tasks 2–4: NetGuardian controller

In terminal 1, from `Codes`:

```bash
NG_FLOW_WINDOW=5 NG_FLOW_THRESHOLD=4 NG_MITIGATION_TIMEOUT=15 ryu-manager controller.py
```

In terminal 2, start `sudo python3 topology.py`. Test at the Mininet prompt:

```text
h1 ping -c 3 10.0.3.40
h6 ping -c 3 10.0.3.40
h6 ping -c 3 10.0.1.11
sh ovs-ofctl -O OpenFlow13 dump-flows s3
sh sleep 6
sh ovs-ofctl -O OpenFlow13 dump-flows s3
```

Expected: h1 reaches h7, h6 cannot reach h7, h6 can reach h1, and dynamic
forwarding entries expire after five idle seconds while the table-miss and
guest policy entries remain. The guest policy is installed on s3 at controller
connection time; the IDS rule has priority 500 and a finite hard timeout.

## Task 3: traffic and monitoring

With Mininet running, start the service from its prompt:

```text
h7 python3 -m http.server 5001 &
```

In another Ubuntu terminal, from `Codes`, start monitoring:

```bash
sudo python3 monitoring.py --interval 1 --duration 60 --out data
```

At the Mininet prompt, generate the required traffic:

```text
h1 python3 traffic_generator.py --mode icmp --destination 10.0.3.40 --rate 1 --duration 10
h1 python3 traffic_generator.py --mode tcp --destination 10.0.3.40 --port 5001 --rate 2 --duration 10
h8 python3 traffic_generator.py --mode tcp --destination 10.0.3.40 --port 5001 --rate 1 --duration 10
```

Collect `flow_stats.csv`, `port_stats.csv`, `active_flows.svg` (and PNG when
Matplotlib is already present), and `traffic_volume.svg` (and PNG when
available), and retain the generator output. Compare the normal and
low-rate trials with the high-rate trial below.

## Task 4: detection, block, and recovery

The controller polls s3 flow statistics once per second and confirms each new
packet-in five-tuple against the switch table before counting it. The default
detector uses a five-second rolling window and flags more than four distinct
h8-to-h7 TCP five-tuples per second. Thus 20 flows in the window is not an
alert; the 21st distinct flow exceeds the threshold. Every newly
observed h8-to-h7 tuple is appended to `data/security_events.csv`, including
non-alert observations. After the low-rate run above, leave a five-second quiet
gap so its tuples age out, then run:

```text
h8 python3 traffic_generator.py --mode tcp --destination 10.0.3.40 --port 5001 --rate 8 --duration 10
```

During the mitigation timeout, verify `h8 -> h7` is blocked while `h1 -> h7`
still works. After 15 seconds, verify h8 can reach h7 again. Inspect
`security_events.csv`, the Ryu `SECURITY_ALERT` log, and `s3` flow table. Save
real evidence in `Codes/Evidence/Task4`.

## Task 5: integrated VM run and five measurements

The live runner starts Ryu and the Mininet topology, exercises the policies,
normal and low-rate traffic, then performs five separate high-rate detection,
mitigation, and recovery trials. It records the measured RTT, active flows,
detection time, and mitigation response time; it also starts monitoring and
saves the controller log. Run from `Codes` in the module Ubuntu VM:

```bash
sudo python3 experiment.py --live
```

Each invocation writes uniquely named outputs under `data` and a transcript
under `Codes/Evidence/Task5`; it does not reuse example measurements. Keep the five
result rows and their calculated means for the report.

The detector unit tests use Python's standard library and can run in the VM:

```bash
cd ~/NetGuardian_CW2_Starter/Codes
python3 -m unittest -v test_flow_detection.py test_monitoring_graph.py test_experiment.py
```

## Report, video, and final ZIP

The report still needs actual VM versions, all five measured rows, team member
names/IDs, and contribution percentages. Do not submit estimated or sample
measurements. The video plan is in `Video/VIDEO_PLAN.md`; every actual team
member must appear and explain their own part. Generated CSVs, graphs, and
Task 5 logs are saved under `Codes/data` and `Codes/Evidence`, so they can be
included with the source. Put final screenshots and the real recording inside
the three required folders before packaging. The final ZIP must contain exactly
`Codes`, `Report`, and `Video` at its top level and use the team-name filename
from the brief.
