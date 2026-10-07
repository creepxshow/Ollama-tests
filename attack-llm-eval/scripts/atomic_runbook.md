# Generating labeled ground truth

The whole study depends on clean labels. The reliable way to get them is to
run known techniques yourself in an isolated lab and record *when* each ran,
so you know exactly which events belong to which technique.

## Safety first

- Use a **throwaway VM** with no access to production or sensitive networks.
- Snapshot it before you start so you can roll back.
- Never run offensive atomics on a shared or production host.

## Setup

1. Install Sysmon for Linux and start collection:
   ```bash
   sudo ./collect_sysmon.sh install
   ```
2. Install Atomic Red Team (Invoke-Atomic, runs under PowerShell on Linux) per
   its official docs, or run individual atomics by hand from the technique's
   markdown.

## Recording labels

For each technique you exercise, capture the UTC start and end so the window
maps events to the label. A simple wrapper:

```bash
run_atomic () {
  local technique="$1"; shift
  local start; start=$(date -u +%Y-%m-%dT%H:%M:%S)
  "$@"                      # the atomic command(s)
  local end; end=$(date -u +%Y-%m-%dT%H:%M:%S)
  echo "${technique},${start},${end},$(hostname),," >> labels.csv
}
```

Example manual atomics for the Linux starter set (run inside the lab VM):

```bash
# T1003.008 - read /etc/shadow
run_atomic T1003.008 sudo cat /etc/shadow

# T1070.003 - clear shell history
run_atomic T1070.003 bash -c 'rm -f ~/.bash_history; history -c'

# T1098.004 - add an SSH authorized key
run_atomic T1098.004 bash -c 'echo "ssh-ed25519 AAAA... test" >> ~/.ssh/authorized_keys'

# T1136.001 - create a local account
run_atomic T1136.001 sudo useradd -M evaluser

# T1053.003 - add a cron job
run_atomic T1053.003 bash -c 'echo "* * * * * root /tmp/x" | sudo tee /etc/cron.d/eval'

# T1105 - ingress tool transfer
run_atomic T1105 bash -c 'curl -s http://127.0.0.1/nothing -o /tmp/payload || true'
```

Prepend the CSV header once:

```bash
echo "technique_id,start,end,host,image_contains,note" > labels.csv
```

## Benign captures

Record a separate session of ordinary admin activity (ls, cd, apt, editing
files, git, etc.) with **no** label rows. These become your benign set for the
false-positive-rate metric. Keep them in their own log file so you can point
`--logs` at both attack and benign captures together.

## Then dump and evaluate

```bash
sudo ./collect_sysmon.sh dump capture.log
python -m attack_llm_eval.run \
  --logs capture.log benign.log \
  --labels labels.csv \
  --stix data/enterprise-attack.json \
  --model llama3.1:8b --granularity process_tree --mode zero_shot --repeats 3 \
  --out results/
```
