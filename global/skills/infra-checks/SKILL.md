---
name: infra-checks
description: Fastest commands to validate or debug Terraform, Bicep, CloudFormation/CDK, shell, YAML, Kubernetes (AKS/EKS), Helm, Ansible, Docker, Python and CI pipelines. Use when checking an infra change or diagnosing a failing plan, what-if, change set, lint, pipeline, deploy or pod.
---

# Infra checks

Pick the cheapest check that can show the problem. Each rung is slower and produces more output than the one before it, so start at rung 1 and move up only when it passes and the problem is still there. Run checks on the changed files rather than the whole repo.

| Stack | 1. Syntax / format (seconds) | 2. Static / lint | 3. Preview (read-only, slower, needs credentials) |
|---|---|---|---|
| Terraform | `terraform fmt -check -diff` | `terraform validate -no-color`, `tflint` | `terraform plan -no-color -lock=false 2>&1 \| grep -E '^(Plan:\|Error\|  # )'` |
| Bicep | `az bicep build --file main.bicep --stdout >/dev/null` | `az bicep lint --file main.bicep` | `az deployment group what-if -g <rg> -f main.bicep --result-format ResourceIdOnly` |
| CloudFormation | `cfn-lint t.yaml` | `aws cloudformation validate-template --template-body file://t.yaml` | `aws cloudformation create-change-set … && describe-change-set` (then delete the change set or let the user execute it) |
| CDK | `cdk synth -q` | `cdk diff` | — (`cdk deploy` is for the user) |
| Shell | `bash -n f.sh` | `shellcheck -f gcc f.sh` | — |
| YAML | `yamllint -f parsable f.yaml` | — | — |
| Kubernetes | `kubeconform -strict -summary` | `kubectl apply --dry-run=client -f` | `kubectl diff -f` / `--dry-run=server` |
| Helm | `helm lint chart/` | `helm template chart/ \| kubeconform -summary` | `helm diff upgrade` (plugin) |
| Ansible | `ansible-playbook --syntax-check` | `ansible-lint -p` | `--check --diff --limit <one host>` |
| Docker | `hadolint Dockerfile` | — | `docker build --target <stage>` |
| Python | `python -m py_compile` | `ruff check` | the one failing test: `pytest path::test -x -q` |
| GitHub Actions | `actionlint` | — | — |
| Azure Pipelines | `yamllint` | — | read the failed step's log (below) |

Rung 3 talks to real environments. Run it only against the context or subscription the user named, and ask which one when it isn't clear. If a tool isn't installed, mention it in one line and use the next option instead of installing it.

## Diagnosing a failure

The first error is usually the cause; later errors tend to be fallout from it. Get it cheaply:

- GitHub Actions: `gh run view <id> --log-failed | grep -n -m5 -B2 -A8 -iE 'error|fatal|failed'`
- Azure Pipelines: `az pipelines runs show --id <id> --query "{result:result,status:status}" -o tsv`, then open only the failed step's log
- Terraform: `terraform plan -no-color 2>&1 | grep -n -A12 '^Error'`
- Bicep / ARM deployment: `az deployment group show -g <rg> -n <name> --query properties.error -o json`, and `az deployment operation group list -g <rg> -n <name> --query "[?properties.provisioningState=='Failed'].properties.statusMessage" -o json`
- Pod: `kubectl describe pod <p> | sed -n '/^Events:/,$p'`, then `kubectl logs <p> --previous --tail=80`
- Cluster events: `kubectl get events -A --sort-by=.lastTimestamp --field-selector type=Warning | tail -20`
- AKS: `az aks show -g <rg> -n <aks> --query "{state:provisioningState, power:powerState.code, k8s:kubernetesVersion}" -o tsv`
- EKS: `aws eks describe-cluster --name <c> --query 'cluster.{status:status,health:health.issues}'`, nodegroups: `aws eks describe-nodegroup --cluster-name <c> --nodegroup-name <ng> --query 'nodegroup.health.issues'`
- CloudFormation: `aws cloudformation describe-stack-events --stack-name <s> --query "StackEvents[?ResourceStatus=='CREATE_FAILED'||ResourceStatus=='UPDATE_FAILED'].[LogicalResourceId,ResourceStatusReason]" -o table`
- Ansible: `ansible-playbook … 2>&1 | grep -n -B3 -A10 -E 'fatal:|FAILED!'`

Reproduce locally with the smallest command from the table that shows the same error, fix the cause, and re-run that same command.
