# The broker from nixosModules.broker on a NixOS VM with its local
# PostgreSQL: it starts under the unit's sandbox, answers /healthz, and an
# agent made with the admin CLI gets a pool lease approved by policy and
# its credential (a file secret passed with LoadCredential). Also checks
# that a second broker on the same database refuses to start, and that the
# broker comes back after a restart with its data.
{ pkgs, self }:
let
  system = pkgs.stdenv.hostPlatform.system;
  packages = self.packages.${system};
  adminToken = "vm-test-admin-token-0123456789abcdef";
  policy = pkgs.writeText "policy.yaml" ''
    defaults: {action: surface, max_duration: 24h}
    platforms:
      pools:
        accounts:
          description: test accounts
          agents: ["bot-*"]
          items:
            alt-1:
              properties: {username: AltOne}
              secret_file: /run/credentials/agent-auth.service/pool-alt-1
    rules:
      - match: {platform: pool, capability: lease, resource: accounts}
        action: approve
        constraints: {max_duration: 8h}
  '';
in
pkgs.testers.runNixOSTest {
  name = "agent-auth-broker";
  nodes.machine =
    { pkgs, ... }:
    {
      imports = [ self.nixosModules.broker ];
      virtualisation.memorySize = 1024;
      environment.systemPackages = [
        packages.client
        pkgs.curl
        pkgs.jq
      ];
      # Test-only secrets (a real host uses sops-nix: never the store).
      environment.etc."agent-auth/test.env".text = ''
        ADMIN_TOKEN=${adminToken}
        ENCRYPTION_KEY=0rFMOyE3xb4MtSUsqVSzLLvWZ8AyZt6Z0jYv9RlmIFU=
      '';
      environment.etc."agent-auth/pool-alt-1".text = "hunter2\n";
      services.agent-auth = {
        enable = true;
        policyFile = policy;
        environmentFiles = [ "/etc/agent-auth/test.env" ];
        loadCredentials = [ "pool-alt-1:/etc/agent-auth/pool-alt-1" ];
        settings.LOG_LEVEL = "info";
      };
    };

  testScript = ''
    import json

    machine.wait_for_unit("agent-auth.service")
    machine.wait_for_open_port(8400)
    health = json.loads(machine.succeed("curl -sf http://127.0.0.1:8400/healthz"))
    assert health == {"ok": True}, health

    # Unknown routes answer {"detail": ...}; the admin API wants the token.
    machine.succeed("curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8400/admin/agents | grep -qx 401")

    env = "AGENT_AUTH_URL=http://127.0.0.1:8400"
    admin = f"{env} AGENT_AUTH_ADMIN_TOKEN=${adminToken}"
    agent = json.loads(machine.succeed(f"{admin} agent-auth admin agent-create bot-a --description vm-test"))
    key = agent["api_key"]
    who = json.loads(machine.succeed(f"{env} AGENT_AUTH_API_KEY={key} agent-auth me"))
    assert who["name"] == "bot-a", who

    req = json.loads(machine.succeed(
        f"{env} AGENT_AUTH_API_KEY={key} agent-auth request pool lease accounts --why 'vm test of the packaging' --wait"
    ))
    print(req)
    assert req["status"] == "granted", req
    cred = json.loads(machine.succeed(f"{env} AGENT_AUTH_API_KEY={key} agent-auth cred {req['grant_id']}"))
    print(cred)
    assert cred["value"].strip() == "hunter2", cred

    # One broker per database: a second one exits.
    out = machine.fail(
        "systemd-run --wait --pipe -p DynamicUser=yes -p User=agent-auth "
        "-E DATABASE_URL='postgres://agent-auth@localhost/agent-auth?host=/run/postgresql' "
        "-E POLICY_FILE=${policy} -E LISTEN_PORT=8401 "
        "${packages.broker}/bin/agent-auth-server 2>&1"
    )
    print(out)
    assert "another agent-auth broker is running on this database" in out, out

    # A restart keeps the data (Postgres) and drains within the stop timeout.
    machine.succeed("systemctl restart agent-auth.service")
    machine.wait_for_open_port(8400)
    grants = machine.succeed(f"{env} AGENT_AUTH_API_KEY={key} agent-auth grants")
    print(grants)
    assert req["grant_id"] in grants, grants

    # The unit's sandbox, as systemd scores it.
    print(machine.succeed("systemd-analyze security agent-auth.service | tail -n 3"))
  '';
}
