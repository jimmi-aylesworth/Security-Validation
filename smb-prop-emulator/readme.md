# About

A safe, controller-driven Rust pair that emulates propagation in a lab without autonomous discovery, without remote execution, and without writing to SMB shares.

---

# What each component does

## Controller

- Loads an explicit allowlist/graph of approved nodes in 192.168.0.0/24
- Starts from a seed node
- Tells each agent which approved neighbors to test
- Receives findings and logs everything to a JSONL audit log
- Enforces hop limit, max hosts, and CIDR validation

## Agent

- Runs on each lab host (pre-installed / pre-launched by you)
- Polls the controller for tasks
- For each approved target, performs a TCP connect test to port 445 only
- Reports results back to the controller
- Does not scan subnets, does not self-install, does not execute remotely

This gives you a controlled propagation emulation that is auditable and safe for lab validation.

---

# Safety properties

This design intentionally does not:

- discover random hosts
- spread itself
- copy binaries
- drop files to shares
- authenticate to SMB
- enumerate shares
- execute commands remotely

Instead, it emulates spread using:

- pre-installed agents
- controller-approved next hops
- explicit topology
- TCP/445 reachability only

---

# Project Structure

```text

smb-prop-emulator/
├── Cargo.toml
├── config.example.json
└── src
    └── bin
        ├── controller.rs
        └── agent.rs
```

---

# How it works

1. Pre-deploy the agent

	Install the agent binary on each approved lab host and run it with that host’s ID.

	Example on host 192.168.0.10:

	```shell
	agent --node_id 192.168.0.10 --controller http://192.168.0.5:8080``Show more lines
	```

	Example on host 192.168.0.11:

	```shell
	agent --node_id 192.168.0.11 --controller http://192.168.0.5:8080Show more lines
	```

2. Start the controller

	```shell
	controller --config config.example.jsonShow more lines
	```

	The controller immediately:

	- validates the config
	- seeds the initial node (seed_node)
	- queues the first set of neighbor probes


3.  Propagation emulation logic

	If the seed node’s agent reports that an approved neighbor has TCP/445 reachable:

	- the controller activates that neighbor
	- the controller queues that neighbor’s approved neighbor probes
	- the process continues until:
		- hop_limit is reached, or
		- max_hosts is reached

This emulates “spread” without any self-copy or remote execution.

---

# Audit logging

The controller appends a JSON line per event to audit.jsonl.

Examples:

```json
{"event":"seeded","seed_node":"192.168.0.10","task":{"task_id":"...","kind":"probe_neighbors","hop":0,"probes":[...]}}{"event":"register","node_id":"192.168.0.10","version":"0.1.0"}{"event":"task_fetch","node_id":"192.168.0.10","task_count":1}{"event":"report","node_id":"192.168.0.10","task_id":"...","hop":0,"findings":[...]}{"event":"activated","node_id":"192.168.0.11","hop":1,"task":{"task_id":"...","kind":"probe_neighbors","hop":1,"probes":[...]}}
```

This gives you:

- who ran
- what was assigned
- what was observed
- what was activated next
- the hop count and scope

# Example status check

The controller exposes:

```HTTP
GET /status
```

Example:

```shell
curl http://192.168.0.5:8080/status
```
This shows:

- registered nodes
- activated nodes
- queued nodes
- hop counts
- completed task count

---

# Build Instructions

```shell
cargo build --release
```

Binaries will be:

```text
target/release/controller
target/release/agent
```

---

# Recommended lab setup

To keep it controlled and auditable:

## Use these guardrails

- isolated VLAN / vSwitch
- no route to corporate network
- pre-approved static host list only
- snapshots before each run
- lab-only credentials
- host firewall rules allowing only expected paths
- short polling interval for visibility, not speed
- low hop_limit first (e.g. 2)
- low max_hosts first (e.g. 5)


# Suggested first test
## Config

- 5 nodes in config.example.json
- seed_node = 192.168.0.10
- hop_limit = 2
- max_hosts = 5

## Run order

- Start controller
- Start each agent manually
- Watch audit.jsonl
- Query /status
- Shut down and inspect the event trail

---

# Things to consider for future release

1. Signed task tokens
	So agents only accept controller-issued work.
2. Kill switch
	A file, env var, or controller endpoint that halts all task execution.
3. Persistent state
	Store controller runtime state in SQLite or a JSON snapshot so the run can resume.
4. CSV/HTML reporting
	Summarize:
	- hop graph
	- reachable nodes
	- timing
	- max spread depth
	- failed connections
5. Optional canary-path validation
	A strictly allowlisted, non-destructive check against known approved lab targets only (not arbitrary shares).

Additionally consider:

- A Windows service version of the agent so it can run cleanly on lab VMs as a service instead of a console app
- A Mermaid or Graphviz output generator for the propagation path from audit.jsonl

---

# Why this is a good fit for validation goals

The design tests:

- which hosts are reachable over SMB port 445
- what propagation graph would be possible
- how quickly “spread” occurs
- whether controls like segmentation and hop limits work
- whether monitoring captures the chain

Without code that:

- propagates itself
- copies payloads
- modifies remote systems
