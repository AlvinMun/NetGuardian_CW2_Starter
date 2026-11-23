# CSI201 Coursework II — NetGuardian starter implementation

**Status: implementation starter, not yet verified in the module Ubuntu VM.**
Do not submit this package as a completed coursework until the team has executed it,
fixed environment-specific issues, captured real evidence, completed five runs,
and replaced all report placeholders with actual findings.

## Environment and controller

Use the module-provided Ubuntu VM and installed Mininet, Ryu and Open vSwitch.
The specification's Fig. 1 lists the controller at `127.0.0.1:6633`; this starter
uses that port. Confirm the supplied Ryu/OVS configuration with your teaching team.

Terminal 1:
```bash
cd Codes
ryu-manager controller.py
```

Terminal 2:
```bash
cd Codes
sudo python3 topology.py
```

At the Mininet prompt, collect the required Task 1 evidence:
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

## Task 2 policy checks

From the Mininet prompt:
```text
h1 ping -c 3 10.0.3.40
h6 ping -c 3 10.0.3.40
h6 ping -c 3 10.0.1.11
```
The expected policy is h1/h2/h3/h4/h5 -> h7 allowed and h6 -> h7 denied.
The controller logs should show MAC_LEARN entries. Inspect flow tables with
`ovs-ofctl -O OpenFlow13 dump-flows s3`.

## Task 3 traffic and monitoring

In another Ubuntu terminal while Mininet is running:
```bash
cd Codes
python3 monitoring.py --interval 1 --duration 60 --out ../data
```
At the Mininet prompt, run:
```text
h7 python3 -m http.server 5001 &
h1 python3 traffic_generator.py --mode icmp --destination 10.0.3.40 --rate 1 --duration 10
h1 python3 traffic_generator.py --mode tcp --destination 10.0.3.40 --port 5001 --rate 2 --duration 10
h8 python3 traffic_generator.py --mode tcp --destination 10.0.3.40 --port 5001 --rate 8 --duration 10
```
Run the generator from the Codes directory or copy the script to a location visible
inside Mininet host namespaces. Ensure the h7 TCP service is running before TCP tests.

## Task 4 detection tuning

The starter defaults are a 5-second observation window, 4 distinct new flows/second,
and 15-second mitigation timeout. These are initial experimental parameters, not
guaranteed optimal values. Tune using low-rate and high-rate trials, justify the
chosen values in the report, and verify the mitigation rule's priority and expiry.
Set parameters before starting Ryu, for example:
```bash
NG_FLOW_WINDOW=5 NG_FLOW_THRESHOLD=4 NG_MITIGATION_TIMEOUT=15 ryu-manager controller.py
```

Important: the policy and mitigation rules are controller-side OpenFlow rules.
Verify their actual match, priority and timeout using `ovs-ofctl dump-flows`.
If the controller receives no Packet_In events for distinct TCP connections, inspect
the installed flow matches and revise the implementation before claiming detection.

## Task 5 performance evaluation

The integrated functional demonstration is required once. Then perform five
independent runs. Measure RTT, active non-table-miss flows, detection time, and
mitigation response time from timestamps and flow tables. Record each measured run:
```bash
python3 experiment.py --add-run 3.2 7 1.4 0.08
```
The numbers above are an example of command syntax only; **do not use them as results**.
Use your actual measured values. The script calculates means after five runs.

## Required report and evidence

See `Report/report_template.md` and `Evidence/README.md`.
The final report must be six pages excluding cover, IEEE double-column PDF named
`Report_Coursework_II.pdf`. The video folder must contain the team's real
10-minute demonstration. The final ZIP must contain exactly `Codes`, `Report`,
and `Video` as its three main folders.
