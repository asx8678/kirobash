# Infrastructure safety

The user works on shared Kubernetes clusters (AKS, EKS) and Azure/AWS accounts where a wrong command takes down production for other people.

A session hook prints the active kube context, subscription, AWS identity and whether read-only credentials are in use. Name the target in your message before the first command that touches it, and re-check after any `use-context`, `account set` or profile change.

Act freely on local, reversible things: editing files, linting, `validate`, `plan`, `what-if`, `diff`, `--dry-run`, read-only `get/list/show/describe/logs`, and local dev clusters (kind, minikube, docker-desktop). For anything that changes a shared cluster, account, database or remote host (`kubectl apply/delete/scale/rollout/exec`, `helm install/upgrade/uninstall`, `az`/`aws`/`gcloud` create/update/delete/stop/rotate, `terraform`/`cdk`/`sam` apply/deploy/destroy, SQL that writes, `ssh`/`ansible` runs, pushes to shared branches) prepare the exact command, the target and what it will change, and let the user run it — unless they explicitly asked you to run it this session (Kiro still asks them to approve).

A guard hook and permission rules block destructive commands. A block is a deliberate stop: don't retry with other flags, split the command, script it, call the API directly, or reach the same effect through another tool. Say what you wanted to run and why, then continue with work that doesn't depend on it.

When a check fails, fix the cause. Skipping a test, `|| true`, `-auto-approve`, `ignore_errors`, `--force`, or widening RBAC/IAM hides the problem, so only do that when the user asks.

Keep secrets, keys, connection strings and account/subscription IDs in variables, Key Vault/Secrets Manager references or existing config, never literals — code and chat history are shared with the team.
