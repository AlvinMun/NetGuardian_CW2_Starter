# NetGuardian 10-minute video script and recording checklist

This is a recording script, not a video. Record the real Ubuntu VM and actual
team members after the VM run succeeds. Do not use sample values or narrate an
expected outcome as if it were observed. Replace every bracketed prompt with
the team's names, real output, and measured results. Keep the final recording
to 10 minutes and export it into this `Video` folder.

## Before recording

1. Run the Task 1 check with `learning_switch.py`; have `nodes`, `net`, `dump`,
   `pingall`, the bridge protocol checks, and flow tables ready.
2. Stop that network/controller, then run the NetGuardian integration with
   `sudo python3 experiment.py --live` from `Codes`.
3. Confirm the generated performance CSV has five rows, the security CSV has
   both low-rate observations and a high-rate alert, and the monitoring output
   includes flow/port CSVs and both graphs.
4. Decide who speaks in each section. Every team member must appear and explain
   a meaningful part of the implementation. If the team has fewer or more than
   five people, adjust the speaker assignments while keeping everyone's part.
5. Close unrelated windows and notifications. Use readable terminal font size,
   record audio clearly, and keep the original recording until submission.

## Timed script

### 0:00–0:45 — Introduction — [Member 1]

Show the title slide or the team beside the Ubuntu VM.

> “We are [team name] presenting NetGuardian for CSI201 Coursework II. Our
> platform uses Mininet, Open vSwitch, OpenFlow 1.3, and a Ryu controller to
> deploy an enterprise topology, enforce a guest policy, monitor traffic, and
> detect and mitigate high-rate connection attempts. We will show the actual
> implementation and measurements from our module VM.”

### 0:45–1:45 — Architecture — [Member 1 or 2]

Show the topology diagram and point out c0, s1–s3, the administrator/staff/
engineering hosts, guest h6, server h7, and test host h8.

> “The switches form an s1–s2–s3 chain. h7 is the protected server, h6 is the
> guest that policy blocks from h7, and h8 is reserved for controlled security
> tests. The topology program assigns the specified IP and MAC addresses and
> connects every switch to the controller at 127.0.0.1:6633.”

### 1:45–3:00 — Task 1 deployment — [Member 2]

Show the first terminal running `ryu-manager learning_switch.py` and the second
running `sudo python3 topology.py`. At the Mininet prompt, show `nodes`, `net`,
`dump`, `pingall`, OpenFlow 1.3 on s1–s3, and `dump-flows` for each switch.

> “For Task 1 we use a policy-free learning switch so that the required full
> connectivity test is not affected by the later guest restriction. The output
> shows [describe the actual pingall loss and topology]. The bridge protocol
> output confirms [read the actual OpenFlow version].”

### 3:00–4:15 — Controller and policy — [Member 3]

Show the relevant `controller.py` sections, then the real h1-to-h7, h6-to-h7,
and h6-to-h1 test outputs. Show the s3 flow table.

> “The controller learns source MAC addresses per switch and installs dynamic
> forwarding entries with a five-second idle timeout. A persistent rule on s3
> denies h6 to h7, while other traffic follows the learning-switch behavior.
> Our tests show [state the observed reachability results]. The flow table
> shows [point out actual priorities, matches, and timeouts].”

### 4:15–5:30 — Traffic and monitoring — [Member 4]

Show `traffic_generator.py`, `monitoring.py`, the ICMP and normal TCP output,
the generated CSV headers/rows, and the active-flow and traffic-volume graphs.

> “The generator controls protocol, destination, port, attempt rate, and
> duration. The monitor polls flow and port counters on all three switches. It
> records timestamps, packet and byte counters, flow duration, active flows,
> and port packet counts. In our run, [describe the visible difference between
> normal and high-rate traffic using actual CSV/graph values].”

### 5:30–7:30 — Detection and mitigation — [Member 5 or another member]

Show the low-rate h8 trial, the quiet gap, then the high-rate h8 trial. Show
`security_events.csv`, the Ryu alert, and the priority-500 s3 drop entry. While
the entry is present, run h1-to-h7 and h8-to-h7 checks, then show h8 recovery
after the timeout.

> “The detector counts new h8-to-h7 TCP five-tuples over a five-second rolling
> window. The configured threshold is four new flows per second, so the alert
> requires more than 20 distinct tuples in the window. At the low rate, the log
> shows [actual count/rate] and [whether an alert occurred]. At the high rate,
> the alert reports [actual rate and threshold]. The temporary rule blocks h8
> to h7 while [actual legitimate-host result]. After [actual timeout] seconds,
> h8 [actual recovery result].”

### 7:30–8:45 — Integrated evaluation — [Member 1 or 2]

Show the `experiment.py --live` transcript and the five-row performance CSV.
Read the metric units and the computed averages from the actual file.

> “The runner performed one integrated functional check and five independent
> trials. For each trial we recorded average RTT, active flows, detection time,
> and mitigation response time. The five measured rows are [briefly show the
> table], with means [read the computed means]. The variation we observed was
> [briefly discuss actual values].”

### 8:45–10:00 — Limitations, contributions, conclusion — all members

Each member gives one short contribution statement. Finish with real limitations
and one possible extension.

> “This evaluation uses Mininet on one Ubuntu VM, so timing can vary with host
> load and does not represent physical-switch capacity. Our detector uses a
> fixed threshold and one test source/destination pair. We contributed as
> follows: [names and actual work]. We demonstrated topology deployment,
> forwarding, access policy, monitoring, detection, mitigation, recovery, and
> five measured runs. Thank you.”

## Submission check

- [ ] Video is approximately 10 minutes and plays from start to finish.
- [ ] Every actual team member appears and explains their part.
- [ ] All shown values and claims match the Ubuntu VM outputs and report.
- [ ] Screens and terminal output are readable; audio is understandable.
- [ ] Final video file is in this folder and included in the ZIP.
