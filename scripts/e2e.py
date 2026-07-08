#!/usr/bin/env python3
"""Manual end-to-end walkthrough of the SDE-agent ↔ homelab-agent scenario.

Run against a live broker (with Discord configured) and follow the prompts:

    AGENT_AUTH_URL=http://localhost:8400 \
    AGENT_AUTH_ADMIN_TOKEN=... \
    uv run python scripts/e2e.py

Steps exercised:
  1. Register sde-agent and homelab-agent (idempotent-ish: fails if they exist).
  2. sde-agent requests a2a→homelab-agent  → approve it on Discord.
  3. homelab-agent verifies the inbound grant, receives a relayed message.
  4. homelab-agent requests homelab/group/svc-gitea (policy decides: rule/llm/surface).
  5. sde-agent requests github/repo with contents+secrets write (LLM path if configured),
     then fetches an installation token.
  6. homelab-agent requests homelab/group/svc-k8s-gitops → decide on Discord.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from agent_auth.client import BrokerClient, BrokerError  # noqa: E402

REPO = os.environ.get("E2E_GITHUB_REPO", "jrt/cactus")


def banner(text: str) -> None:
    print(f"\n{'=' * 70}\n{text}\n{'=' * 70}")


def wait_decided(client: BrokerClient, req: dict, label: str) -> dict:
    while req["status"] in ("pending", "llm_evaluating", "awaiting_human", "approved", "provisioning"):
        if req["status"] == "awaiting_human":
            print(f"  [{label}] waiting for YOUR decision on Discord ...")
        else:
            print(f"  [{label}] status={req['status']} ...")
        req = client.wait(req["id"], timeout=60)
    print(f"  [{label}] → {req['status']}"
          + (f" ({req.get('decision_reason')})" if req.get("decision_reason") else ""))
    return req


def main() -> None:
    admin = BrokerClient()
    if not admin.admin_token:
        sys.exit("set AGENT_AUTH_ADMIN_TOKEN")

    banner("1. Registering agents (sde-agent, homelab-agent)")
    agents = {}
    for name, extra in (
        ("sde-agent", {"description": "software development agent"}),
        ("homelab-agent", {"description": "homelab operations agent",
                           "lldap_username": os.environ.get("E2E_LLDAP_USER", "svc-homelab-agent")}),
    ):
        try:
            created = admin.admin_create_agent(name, **extra)
            agents[name] = created["api_key"]
            print(f"  created {name} (key {created['api_key'][:12]}…)")
        except BrokerError as exc:
            if exc.status_code == 409:
                sys.exit(f"{name} already exists — delete it or export its key and adapt this script")
            raise

    sde = BrokerClient(api_key=agents["sde-agent"])
    homelab = BrokerClient(api_key=agents["homelab-agent"])

    banner("2. sde-agent requests permission to talk to homelab-agent (a2a)")
    req = sde.request_access(
        "a2a", "talk", "homelab-agent",
        justification="I need the homelab agent's help deploying a web app: it should "
                      "receive my deployment request and handle gitops on its side.",
        duration="4h", scope={"topic": "deploy/*"},
    )
    req = wait_decided(sde, req, "a2a")
    assert req["status"] == "granted", "a2a request was not granted; aborting"

    banner("3. homelab-agent verifies inbound grant + receives a relayed message")
    check = homelab.a2a_check("sde-agent", direction="in", topic="deploy/webapp")
    print(f"  inbound check: {check}")
    sent = sde.a2a_send("homelab-agent", {"task": "please help me deploy 'cactus'"}, topic="deploy/webapp")
    print(f"  message relayed via {sent['delivered_via']}")
    inbox = homelab.a2a_inbox()
    print(f"  homelab inbox: {inbox[-1]['payload'] if inbox else '(webhook-delivered)'}")
    if inbox:
        homelab.a2a_ack(inbox[-1]["message_id"])

    banner("4. homelab-agent requests LLDAP group svc-gitea")
    req = homelab.request_access(
        "homelab", "group", "svc-gitea",
        justification="sde-agent asked me to host its app; I need Gitea access to create "
                      "a repo + registry token for CI. I will mint my own scoped Gitea token.",
        duration="8h",
    )
    req = wait_decided(homelab, req, "svc-gitea")
    if req["status"] == "llm_denied":
        print("  retrying with a more specific justification ...")
        req = homelab.retry(req["id"],
                            "Deploying app 'cactus' for sde-agent (a2a grant on file): need "
                            "svc-gitea group for 8h to create repo jrt/cactus-deploy and one "
                            "registry write token for CI pushes only.")
        req = wait_decided(homelab, req, "svc-gitea-retry")

    banner("5. sde-agent requests GitHub repo access (contents+secrets write)")
    req = sde.request_access(
        "github", "repo", REPO,
        justification=f"Pushing deployment workflow to {REPO} and uploading the registry "
                      "token (from homelab-agent) as an Actions secret.",
        duration="4h",
        scope={"permissions": {"contents": "write", "secrets": "write"}},
    )
    req = wait_decided(sde, req, "github")
    if req["status"] == "granted":
        cred = sde.credential(req["grant_id"])
        print(f"  installation token: {cred['value'][:12]}… (expires {cred['expires_at']})")
        print("  (agent would now push code + upload the Actions secret with this token)")

    banner("6. homelab-agent requests kubernetes edit on the app namespace (surfaces)")
    req = homelab.request_access(
        "kubernetes", "edit", os.environ.get("E2E_K8S_NAMESPACE", "personal-site"),
        justification="Final deploy step for 'cactus': apply manifests and restart "
                      "the deployment in this namespace.",
        duration="2h",
    )
    req = wait_decided(homelab, req, "k8s")
    if req["status"] == "granted":
        cred = homelab.credential(req["grant_id"])
        print(f"  k8s token: {cred['value'][:16]}… (expires {cred['expires_at']})")
        print(f"  note: {cred['note']}")

    banner("Done — check active grants")
    print(f"  sde-agent grants:     {[g['resource'] for g in sde.grants()]}")
    print(f"  homelab-agent grants: {[g['resource'] for g in homelab.grants()]}")


if __name__ == "__main__":
    main()
