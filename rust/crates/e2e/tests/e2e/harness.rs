//! Running the real binaries: a broker per test on its own database, the
//! CLI, the stdio MCP server.

use std::fs::File;
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Stdio};
use std::time::Duration;

use serde_json::{Value, json};
use sqlx::postgres::PgConnectOptions;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};

pub const ADMIN_TOKEN: &str = "e2e-admin-token-0123456789abcdef";

/// A binary of the workspace, from the target directory this test was
/// built into (`target/<profile>/deps/<test>` → `target/<profile>/<name>`).
pub fn bin(name: &str) -> PathBuf {
    let exe = std::env::current_exe().unwrap();
    let dir = exe.parent().unwrap().parent().unwrap();
    let path = dir.join(name);
    assert!(
        path.is_file(),
        "{} is missing: run `cargo build --workspace --bins` first \
         (`scripts/check.sh e2e` does)",
        path.display()
    );
    path
}

/// A directory removed on drop.
#[derive(Debug)]
pub struct TempDir(PathBuf);

impl TempDir {
    pub fn new() -> TempDir {
        let path =
            std::env::temp_dir().join(format!("agent-auth-e2e-{}", uuid::Uuid::new_v4().simple()));
        std::fs::create_dir_all(&path).unwrap();
        TempDir(path)
    }

    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The URL of the database `#[sqlx::test]` made for this test: the
/// server's `DATABASE_URL` with the database name replaced.
pub fn database_url(opts: &PgConnectOptions) -> String {
    let base = std::env::var("DATABASE_URL").expect("DATABASE_URL (scripts/pg.sh start)");
    let mut url = url::Url::parse(&base).unwrap();
    url.set_path(opts.get_database().expect("a test database"));
    url.to_string()
}

/// A loopback port nobody listens on (bound, then released).
pub fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// What a broker is started with.
#[derive(Debug, Clone)]
pub struct Setup {
    pub database_url: String,
    pub policy: String,
    /// Extra environment (GitHub, OpenRouter...).
    pub env: Vec<(String, String)>,
    /// Lines of the broker's `./.env`.
    pub dotenv: Vec<(String, String)>,
}

impl Setup {
    pub fn new(database_url: String, policy: &str) -> Setup {
        Setup {
            database_url,
            policy: policy.to_owned(),
            env: Vec::new(),
            dotenv: Vec::new(),
        }
    }

    /// A `KEY=value` line in the broker's `./.env`.
    pub fn dotenv(mut self, key: &str, value: &str) -> Setup {
        self.dotenv.push((key.to_owned(), value.to_owned()));
        self
    }

    pub fn env(mut self, key: &str, value: &str) -> Setup {
        self.env.push((key.to_owned(), value.to_owned()));
        self
    }
}

/// A running `agent-auth-server`. Killed on drop; its log is printed when
/// the test is failing.
#[derive(Debug)]
pub struct Broker {
    child: Option<Child>,
    pub url: String,
    pub setup: Setup,
    pub encryption_key: String,
    log: PathBuf,
    /// The broker's working directory (its `./.env`), and the CLI's home.
    pub dir: TempDir,
    http: reqwest::Client,
}

pub fn http_client() -> reqwest::Client {
    let tls = agent_auth_tls::default_client_config().unwrap();
    agent_auth_tls::reqwest_builder(tls, Duration::from_secs(120))
        .build()
        .unwrap()
}

/// `agent-auth admin gen-key`, through the real CLI.
pub async fn gen_key() -> String {
    let out = Command::new(bin("agent-auth"))
        .args(["admin", "gen-key"])
        .env_clear()
        .output()
        .await
        .unwrap();
    assert!(out.status.success(), "gen-key failed: {out:?}");
    String::from_utf8(out.stdout).unwrap().trim().to_owned()
}

impl Broker {
    /// Start a broker and wait until it answers `/healthz`.
    pub async fn start(setup: Setup) -> Broker {
        let key = gen_key().await;
        Broker::start_with_key(setup, key).await
    }

    pub async fn start_with_key(setup: Setup, encryption_key: String) -> Broker {
        let dir = TempDir::new();
        let mut broker = Broker::spawn(setup, encryption_key, dir, free_port());
        broker.ready().await;
        broker
    }

    /// Spawn without waiting.
    pub fn spawn(setup: Setup, encryption_key: String, dir: TempDir, port: u16) -> Broker {
        let policy = dir.path().join("policy.yaml");
        std::fs::write(&policy, &setup.policy).unwrap();
        let dotenv: String = setup
            .dotenv
            .iter()
            .map(|(k, v)| format!("{k}={v}\n"))
            .collect();
        std::fs::write(dir.path().join(".env"), dotenv).unwrap();
        let log = dir
            .path()
            .join(format!("broker-{}.log", uuid::Uuid::new_v4().simple()));
        let out = File::create(&log).unwrap();
        let err = out.try_clone().unwrap();
        let mut cmd = Command::new(bin("agent-auth-server"));
        cmd.env_clear()
            .current_dir(dir.path())
            .env("DATABASE_URL", &setup.database_url)
            .env("POLICY_FILE", &policy)
            .env("ADMIN_TOKEN", ADMIN_TOKEN)
            .env("ENCRYPTION_KEY", &encryption_key)
            .env("LISTEN_HOST", "127.0.0.1")
            .env("LISTEN_PORT", port.to_string())
            .env("LOG_LEVEL", "info")
            .env("NO_COLOR", "1");
        for (k, v) in &setup.env {
            cmd.env(k, v);
        }
        let child = cmd
            .stdin(Stdio::null())
            .stdout(Stdio::from(out))
            .stderr(Stdio::from(err))
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        Broker {
            child: Some(child),
            url: format!("http://127.0.0.1:{port}"),
            setup,
            encryption_key,
            log,
            dir,
            http: http_client(),
        }
    }

    async fn ready(&mut self) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        loop {
            if let Some(status) = self.child.as_mut().unwrap().try_wait().unwrap() {
                panic!(
                    "the broker exited ({status}) before it was up:\n{}",
                    self.log()
                );
            }
            if let Ok(r) = self.http.get(format!("{}/healthz", self.url)).send().await
                && r.status().is_success()
            {
                return;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "the broker was not up within 30 s:\n{}",
                self.log()
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    /// Everything the broker logged so far.
    pub fn log(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }

    pub fn pid(&self) -> u32 {
        self.child.as_ref().unwrap().id().expect("running")
    }

    /// SIGTERM, through kill(1).
    pub fn sigterm(&self) {
        let status = std::process::Command::new("kill")
            .args(["-TERM", &self.pid().to_string()])
            .status()
            .unwrap();
        assert!(status.success(), "kill -TERM failed");
    }

    /// Wait for the process to end (at most `timeout`).
    pub async fn exited(&mut self, timeout: Duration) -> Option<ExitStatus> {
        let child = self.child.as_mut().unwrap();
        tokio::time::timeout(timeout, child.wait())
            .await
            .ok()
            .map(Result::unwrap)
    }

    /// Stop with SIGTERM and start again on the same database and key
    /// (the boot tick runs at once).
    pub async fn restart(&mut self) {
        self.sigterm();
        let status = self.exited(Duration::from_secs(30)).await;
        assert!(
            status.is_some_and(|s| s.success()),
            "the broker did not stop cleanly ({status:?}):\n{}",
            self.log()
        );
        let new = Broker::spawn(
            self.setup.clone(),
            self.encryption_key.clone(),
            TempDir::new(),
            free_port(),
        );
        drop(std::mem::replace(self, new));
        self.ready().await;
    }

    /// Run the CLI as `who`.
    pub async fn cli(&self, who: Who<'_>, args: &[&str]) -> Out {
        let mut cmd = Command::new(bin("agent-auth"));
        cmd.env_clear()
            .env("AGENT_AUTH_URL", &self.url)
            .env("HOME", self.dir.path())
            .args(args)
            .stdin(Stdio::null())
            .kill_on_drop(true);
        match who {
            Who::Admin => {
                cmd.env("AGENT_AUTH_ADMIN_TOKEN", ADMIN_TOKEN);
            }
            Who::Agent(key) => {
                cmd.env("AGENT_AUTH_API_KEY", key);
            }
            Who::Nobody => {}
        }
        let out = tokio::time::timeout(Duration::from_secs(120), cmd.output())
            .await
            .unwrap_or_else(|_| panic!("agent-auth {args:?} did not finish in 120 s"))
            .unwrap();
        Out {
            args: args.iter().map(|a| (*a).to_owned()).collect(),
            code: out.status.code().unwrap_or(-1),
            stdout: String::from_utf8(out.stdout).unwrap(),
            stderr: String::from_utf8(out.stderr).unwrap(),
        }
    }

    /// `agent-auth admin agent-create <name>`.
    pub async fn create_agent(&self, name: &str, extra: &[&str]) -> Agent {
        let mut args = vec!["admin", "agent-create", name, "--description", "e2e"];
        args.extend_from_slice(extra);
        let v = self.cli(Who::Admin, &args).await.ok();
        Agent {
            id: v["id"].as_str().unwrap().to_owned(),
            key: v["api_key"].as_str().unwrap().to_owned(),
        }
    }

    /// A raw admin call (what the CLI has no option for).
    pub async fn admin(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<Value>,
    ) -> (u16, Value) {
        let mut rb = self
            .http
            .request(method, format!("{}{path}", self.url))
            .bearer_auth(ADMIN_TOKEN);
        if let Some(b) = body {
            rb = rb.json(&b);
        }
        let r = rb.send().await.unwrap();
        let status = r.status().as_u16();
        let text = r.text().await.unwrap();
        (
            status,
            serde_json::from_str(&text).unwrap_or(Value::String(text)),
        )
    }
}

impl Drop for Broker {
    fn drop(&mut self) {
        if std::thread::panicking() {
            eprintln!("---- broker log ({}) ----\n{}", self.url, self.log());
        }
        if let Some(child) = self.child.as_mut() {
            let _ = child.start_kill();
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum Who<'a> {
    Admin,
    Agent(&'a str),
    Nobody,
}

#[derive(Debug, Clone)]
pub struct Agent {
    pub id: String,
    pub key: String,
}

impl Agent {
    pub fn who(&self) -> Who<'_> {
        Who::Agent(&self.key)
    }
}

/// A finished CLI run.
#[derive(Debug, Clone)]
pub struct Out {
    pub args: Vec<String>,
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

impl Out {
    /// Exit 0; stdout as JSON.
    #[track_caller]
    pub fn ok(&self) -> Value {
        assert_eq!(
            self.code, 0,
            "agent-auth {:?} failed: {}",
            self.args, self.stderr
        );
        serde_json::from_str(&self.stdout).unwrap_or_else(|e| {
            panic!(
                "agent-auth {:?}: not JSON ({e}): {}",
                self.args, self.stdout
            )
        })
    }

    /// Exit 1 with a broker refusal; the stderr line.
    #[track_caller]
    pub fn refused(&self) -> String {
        assert_eq!(
            self.code, 1,
            "agent-auth {:?} should have been refused: {}",
            self.args, self.stdout
        );
        self.stderr.trim().to_owned()
    }
}

/// `agent-auth-mcp` over its stdin and stdout.
#[derive(Debug)]
pub struct Mcp {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    next: i64,
    pub instructions: String,
}

impl Mcp {
    /// Start it as an agent and complete the handshake. `runtime_dir`
    /// becomes `XDG_RUNTIME_DIR` (where `to_file` writes).
    pub async fn start(broker: &Broker, key: &str, runtime_dir: &Path) -> Mcp {
        let mut child = Command::new(bin("agent-auth-mcp"))
            .env_clear()
            .env("AGENT_AUTH_URL", &broker.url)
            .env("AGENT_AUTH_API_KEY", key)
            .env("XDG_RUNTIME_DIR", runtime_dir)
            .env("HOME", runtime_dir)
            .current_dir(runtime_dir)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let stdin = child.stdin.take().unwrap();
        let stdout = BufReader::new(child.stdout.take().unwrap());
        let mut mcp = Mcp {
            child,
            stdin,
            stdout,
            next: 1,
            instructions: String::new(),
        };
        let init = mcp
            .request(
                "initialize",
                json!({"protocolVersion": "2025-06-18", "capabilities": {},
                       "clientInfo": {"name": "e2e", "version": "0"}}),
            )
            .await;
        assert_eq!(init["result"]["serverInfo"]["name"], "agent-auth", "{init}");
        mcp.instructions = init["result"]["instructions"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        mcp.send(json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))
            .await;
        mcp
    }

    async fn send(&mut self, message: Value) {
        let mut line = message.to_string();
        line.push('\n');
        self.stdin.write_all(line.as_bytes()).await.unwrap();
        self.stdin.flush().await.unwrap();
    }

    /// A JSON-RPC request; the whole answer.
    pub async fn request(&mut self, method: &str, params: Value) -> Value {
        let id = self.next;
        self.next += 1;
        self.send(json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}))
            .await;
        loop {
            let mut line = String::new();
            let n =
                tokio::time::timeout(Duration::from_secs(120), self.stdout.read_line(&mut line))
                    .await
                    .unwrap_or_else(|_| panic!("no answer to {method} within 120 s"))
                    .unwrap();
            assert!(n > 0, "agent-auth-mcp closed its stdout");
            let m: Value = serde_json::from_str(&line).unwrap();
            if m["id"] == json!(id) {
                return m;
            }
        }
    }

    /// `tools/call`: the tool's text, and whether it is an error.
    pub async fn call(&mut self, name: &str, arguments: Value) -> (bool, String) {
        let m = self
            .request("tools/call", json!({"name": name, "arguments": arguments}))
            .await;
        let result = &m["result"];
        assert!(result.is_object(), "{name}: {m}");
        let text = result["content"][0]["text"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        (result["isError"] == json!(true), text)
    }

    /// A tool that must succeed, its text parsed as JSON.
    pub async fn call_ok(&mut self, name: &str, arguments: Value) -> Value {
        let (error, text) = self.call(name, arguments).await;
        assert!(!error, "{name} failed: {text}");
        serde_json::from_str(&text).unwrap_or_else(|e| panic!("{name}: not JSON ({e}): {text}"))
    }

    /// Close stdin; the server exits.
    pub async fn close(mut self) -> ExitStatus {
        drop(self.stdin);
        tokio::time::timeout(Duration::from_secs(10), self.child.wait())
            .await
            .expect("agent-auth-mcp exits when its stdin closes")
            .unwrap()
    }
}

/// Poll `check` until it is true (at most `timeout`).
pub async fn eventually<F, Fut>(timeout: Duration, what: &str, mut check: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let deadline = tokio::time::Instant::now() + timeout;
    while !check().await {
        assert!(tokio::time::Instant::now() < deadline, "timed out: {what}");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}
