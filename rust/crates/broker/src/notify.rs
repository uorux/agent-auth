//! Where humans hear about things: the Discord bot, or nothing (a headless
//! broker). Static dispatch over an enum, like the provisioners.
//!
//! Every method swallows its own errors (logs them): a notification that
//! fails must never fail the operation that triggered it. The one method
//! whose answer matters is [`Notify::shell_command`]: a shell command that
//! could not be shown to a human does not run.
//! (rust/spec/human-and-agent-surfaces.md, the Notifier interface.)

use agent_auth_store::agents::AgentRow;
use agent_auth_store::grants::GrantRow;
use agent_auth_store::hostexec::JobRow;
use agent_auth_store::requests::RequestRow;
use agent_auth_store::rules::RuleRow;
use serde_json::Value;

pub trait Notify {
    /// A request awaits a human: post the approval card.
    fn surface(&self, request: &RequestRow, agent: &AgentRow) -> impl Future<Output = ()> + Send;
    /// A decision landed (approved/denied/failed): update the card.
    fn update_outcome(
        &self,
        request: &RequestRow,
        grant: Option<&GrantRow>,
    ) -> impl Future<Output = ()> + Send;
    /// A grant expired or was revoked: update the card.
    fn update_grant_ended(
        &self,
        request: &RequestRow,
        grant: &GrantRow,
    ) -> impl Future<Output = ()> + Send;
    /// Something was decided without a human (a saved rule, the policy file,
    /// the LLM): an audit line in the activity channel.
    fn rule_applied(
        &self,
        request: &RequestRow,
        agent: &AgentRow,
        rule: Option<&RuleRow>,
        grant: Option<&GrantRow>,
    ) -> impl Future<Output = ()> + Send;
    /// A host command's result is in.
    fn job_finished(&self, request: &RequestRow, job: &JobRow) -> impl Future<Output = ()> + Send;
    /// A shell command is about to go to its host. False: it could not be
    /// shown to a human, and then it must not run.
    fn shell_command(
        &self,
        request: &RequestRow,
        job: &JobRow,
    ) -> impl Future<Output = bool> + Send;
    /// The watcher found a running command alarming (advisory).
    fn watch_alert(
        &self,
        request: &RequestRow,
        job: &JobRow,
        text: &str,
    ) -> impl Future<Output = ()> + Send;
    /// An agent wants the operator's attention; `desks` already showed it.
    fn attention(
        &self,
        agent: &AgentRow,
        text: &str,
        urgency: &str,
        desks: &[String],
    ) -> impl Future<Output = ()> + Send;
    /// Agents were contained or locked down: always a ping.
    fn contained(&self, event: &Value) -> impl Future<Output = ()> + Send;
    /// The mail gateway held a message (inbound, or one an agent wants to
    /// send): the card with Release / Discard.
    fn mail_held(&self, item: &agent_auth_wire::mail::MailItem) -> impl Future<Output = ()> + Send;
}

#[derive(Debug, Default)]
pub enum Notifier {
    /// No human surface: requests await a decision through the admin API.
    #[default]
    Null,
    /// Records every call, for tests.
    Recording(Recorder),
    /// The Discord bot (spec A.4).
    Discord(crate::discord::DiscordNotifier),
    /// Another notifier with desk prompts alongside (`crate::desktop`).
    Fanout(crate::desktop::Fanout),
}

macro_rules! dispatch {
    ($self:ident, $n:ident => $e:expr, null => $null:expr) => {
        match $self {
            Notifier::Null => $null,
            Notifier::Recording($n) => $e,
            Notifier::Discord($n) => $e,
            Notifier::Fanout($n) => $e,
        }
    };
}

impl Notify for Notifier {
    async fn surface(&self, request: &RequestRow, agent: &AgentRow) {
        dispatch!(self, n => n.surface(request, agent).await,
            null => tracing::warn!(request = %request.id, "no notifier configured; request awaits a human via the admin API only"))
    }
    async fn update_outcome(&self, request: &RequestRow, grant: Option<&GrantRow>) {
        dispatch!(self, n => n.update_outcome(request, grant).await, null => ())
    }
    async fn update_grant_ended(&self, request: &RequestRow, grant: &GrantRow) {
        dispatch!(self, n => n.update_grant_ended(request, grant).await, null => ())
    }
    async fn rule_applied(
        &self,
        request: &RequestRow,
        agent: &AgentRow,
        rule: Option<&RuleRow>,
        grant: Option<&GrantRow>,
    ) {
        dispatch!(self, n => n.rule_applied(request, agent, rule, grant).await, null => ())
    }
    async fn job_finished(&self, request: &RequestRow, job: &JobRow) {
        dispatch!(self, n => n.job_finished(request, job).await, null => ())
    }
    async fn shell_command(&self, request: &RequestRow, job: &JobRow) -> bool {
        // Headless: the host's journal is the record (as the Python).
        dispatch!(self, n => n.shell_command(request, job).await, null => true)
    }
    async fn watch_alert(&self, request: &RequestRow, job: &JobRow, text: &str) {
        dispatch!(self, n => n.watch_alert(request, job, text).await,
            null => tracing::warn!(job = %job.id, host = %job.host, "{text}"))
    }
    async fn attention(&self, agent: &AgentRow, text: &str, urgency: &str, desks: &[String]) {
        dispatch!(self, n => n.attention(agent, text, urgency, desks).await,
            null => tracing::info!(agent = %agent.name, urgency, "attention: {text}"))
    }
    async fn contained(&self, event: &Value) {
        dispatch!(self, n => n.contained(event).await,
            null => tracing::warn!(?event, "contained (no notifier)"))
    }
    async fn mail_held(&self, item: &agent_auth_wire::mail::MailItem) {
        dispatch!(self, n => n.mail_held(item).await,
            null => tracing::warn!(item = %item.id, "mail held for the operator (no notifier): agent-auth admin mail-held"))
    }
}

/// Test notifier: records `"<method> <id>"` lines.
#[derive(Debug, Default)]
pub struct Recorder {
    pub calls: std::sync::Mutex<Vec<String>>,
    /// What `shell_command` answers.
    pub refuse_shell: bool,
}

impl Recorder {
    fn record(&self, line: String) {
        self.calls
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(line);
    }
    #[must_use]
    pub fn lines(&self) -> Vec<String> {
        self.calls
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

impl Notify for Recorder {
    async fn surface(&self, request: &RequestRow, _agent: &AgentRow) {
        self.record(format!("surface {}", request.id));
    }
    async fn update_outcome(&self, request: &RequestRow, _grant: Option<&GrantRow>) {
        self.record(format!("update_outcome {}", request.id));
    }
    async fn update_grant_ended(&self, request: &RequestRow, _grant: &GrantRow) {
        self.record(format!("update_grant_ended {}", request.id));
    }
    async fn rule_applied(
        &self,
        request: &RequestRow,
        _agent: &AgentRow,
        _rule: Option<&RuleRow>,
        _grant: Option<&GrantRow>,
    ) {
        self.record(format!("rule_applied {}", request.id));
    }
    async fn job_finished(&self, _request: &RequestRow, job: &JobRow) {
        self.record(format!("job_finished {}", job.id));
    }
    async fn shell_command(&self, _request: &RequestRow, job: &JobRow) -> bool {
        self.record(format!("shell_command {}", job.id));
        !self.refuse_shell
    }
    async fn watch_alert(&self, _request: &RequestRow, job: &JobRow, _text: &str) {
        self.record(format!("watch_alert {}", job.id));
    }
    async fn attention(&self, agent: &AgentRow, _text: &str, urgency: &str, _desks: &[String]) {
        self.record(format!("attention {} {urgency}", agent.name));
    }
    async fn contained(&self, _event: &Value) {
        self.record("contained".to_owned());
    }
    async fn mail_held(&self, item: &agent_auth_wire::mail::MailItem) {
        self.record(format!(
            "mail_held {} {} {}",
            item.id,
            item.direction,
            item.text
                .as_deref()
                .or(item.excerpt.as_deref())
                .unwrap_or("")
        ));
    }
}
