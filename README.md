# CSI201 CW2 - NetGuardian team run guide

Extract the source package in the course Ubuntu virtual machine. Keep the
entire `Codes` folder together. Open two terminals and change to the `Codes`
directory in both. Follow the lab startup sequence and then run the CW2 checks
below.

## Task 1 - Verify the topology

Start the lab's basic learning-switch controller in terminal 1.

```bash
ryu-manager --ofp-tcp-listen-port 6633 ryu.app.simple_switch_13
```

Once Ryu has started, launch the topology in terminal 2.

```bash
sudo python3 topology.py
```

At the `mininet>` prompt, enter these commands one at a time.

```text
nodes
net
dump
pingall
```

Expect eight hosts, three switches, and 0% packet loss. In terminal 3, check
the flow table, controller connection status, and bridge protocol.

```bash
sudo ovs-ofctl -O OpenFlow13 dump-flows s1
sudo ovs-vsctl --columns=target,is_connected list Controller
sudo ovs-vsctl get Bridge s1 protocols
```

Replace `s1` with `s2` or `s3` to inspect the other switches. Before moving to the
next task, enter `exit` at the `mininet>` prompt, then press `Ctrl+C` in terminal 1
to stop Ryu. Use the basic learning switch for the Task 1 connectivity check.

## Task 2 - Test access policies

Start the project controller in terminal 1.

```bash
ryu-manager --ofp-tcp-listen-port 6633 controller.py
```

Launch the topology in terminal 2.

```bash
sudo python3 topology.py
```

Test the three paths at the `mininet>` prompt.

```text
h1 ping -c 3 h7
h6 ping -c 1 -W 1 h7
h6 ping -c 3 h5
```

The first and third pings should succeed. The second should be blocked.
Look for MAC learning messages in terminal 1. Have the following command ready
in terminal 3 and run it as soon as the last ping finishes.

```bash
sudo ovs-ofctl -O OpenFlow13 dump-flows s3
```

Run the command again after about six seconds. Verify that the learned ICMP
forwarding entries have expired after their five-second idle timeout and that
the table-miss entry and the permanent guest DROP rule are still present.
The CW2 specification names the policy controller `controller.py`.

## Task 3 - Generate traffic and inspect the monitoring results

In terminal 1, start Ryu with automatic mitigation disabled so the full
controlled workload can run while the controller collects statistics.

```bash
NG_MITIGATE=0 ryu-manager --ofp-tcp-listen-port 6633 controller.py
```

Once Ryu has started, run `sudo python3 topology.py` in terminal 2 as before.

At the `mininet>` prompt, start the TCP service on `h7` and run the three traffic
experiments in order.

```text
h7 python3 traffic_generator.py serve >/tmp/netguardian-h7.log 2>&1 &
h7 cat /tmp/netguardian-h7.log
h1 python3 traffic_generator.py generate icmp --source=h1 --destination=h7 --rate=1 --duration=3
h1 python3 traffic_generator.py generate tcp --source=h1 --destination=h7 --rate=1 --duration=3
h8 python3 traffic_generator.py generate tcp --source=h8 --destination=h7 --rate=5 --duration=4.5
h7 kill $!
exit
```

The controller prints its `Results directory` in terminal 1 at startup. After
stopping Ryu, run the following command from `Codes`. Replace `run-XXXXXX` with
the actual directory name to generate the two SVG monitoring plots.

```bash
python3 monitoring.py controller-output/run-XXXXXX
```

## Task 4 - Observe the alert, temporary DROP rule, and recovery

Start the project controller in terminal 1. Detection and automatic mitigation
are enabled by default.

```bash
ryu-manager --ofp-tcp-listen-port 6633 controller.py
```

Once Ryu has started, launch the topology in terminal 2.

```bash
sudo python3 topology.py
```

Run the low-rate test first at the `mininet>` prompt.

```text
h7 python3 traffic_generator.py serve >/tmp/netguardian-h7.log 2>&1 &
h8 python3 traffic_generator.py generate tcp --source=h8 --destination=h7 --rate=1 --duration=3
```

The low-rate traffic should pass. In terminal 3, start refreshing the `s3` flow
table so you can see the temporary DROP rule with priority 200 when it appears.

```bash
sudo watch -n 0.5 ovs-ofctl -O OpenFlow13 dump-flows s3
```

At the `mininet>` prompt, start continuous pings from both hosts, then run the
controlled TCP health-check workload.

```text
h1 ping -D -i 0.5 -c 31 h7 >/tmp/netguardian-h1-ping.log 2>&1 &
h8 ping -D -i 0.5 -c 31 h7 >/tmp/netguardian-h8-ping.log 2>&1 &
h8 python3 traffic_generator.py generate tcp --source=h8 --destination=h7 --rate=5 --duration=4.5
```

Terminal 1 shows `ALERT`, `DROP confirmed`, and `DROP removed`. The controller saves
these events in `security_events.csv` in the `Results directory`. Check `h8`
connectivity again after the rule expires.

```text
h8 ping -c 3 h7
h7 kill $!
exit
```

## Task 5 - Run the integrated demo and five performance trials

Stop any manually started Mininet and Ryu processes. Run the integrated
evaluation from the `Codes` directory.

```bash
sudo python3 Experiment.py --mode evaluation --output ~/CW2/results/Task5
```

The demo subdirectory contains the integrated demonstration results.
The `performance.csv` file lists the metrics for all five trials and their
averages.

## Optional - Record a terminal session or automate individual checks

Each time you start `controller.py` directly, it saves CSV files in
`Codes/controller-output/run-*` and prints the actual path. To record the
Mininet session for Task 1, replace the terminal 2 launch command with the
command below. Enter the same lab commands at the `mininet>` prompt.

```bash
script -q -f -c 'sudo python3 topology.py' ~/Task1-mininet.log
```

Use the separate-terminal steps above for a live demonstration. Use these
commands to run individual checks automatically. Choose a new output
directory for each run, and run one check at a time in the same virtual machine.

```bash
sudo python3 Experiment.py --mode topology   --output ~/CW2/results/Task1
sudo python3 Experiment.py --mode policy     --output ~/CW2/results/Task2
sudo python3 Experiment.py --mode monitoring --output ~/CW2/results/Task3
sudo python3 Experiment.py --mode security   --output ~/CW2/results/Task4
```

If Python 3 reports `No module named 'mininet'`, check that Mininet is configured
for Python 3 in the course Ubuntu virtual machine. Share the source package
within your registered team. For the final submission, package `Codes` with
your team's `Report` and `Video` folders and follow the coursework naming
requirements.
