//! Terminal session lifecycle boundary.
//!
//! Sessions bind a principal, authority bitmap, trace context, and bounded
//! history of security-relevant events. The state machine fails closed for
//! closed, locked, or not-yet-open sessions.

use crate::{
    commands::CommandContext, validate_redaction, validate_terminal_label, DataClass,
    RedactionState, TerminalError, TerminalResult, TerminalRights, TraceContext,
    MAX_COMMAND_NAME_LEN,
};

/// Session descriptor schema version.
pub const SESSION_SCHEMA_VERSION: &str = "alani-terminal.session.v1";
/// Maximum session label length.
pub const MAX_SESSION_LABEL_LEN: usize = 64;
/// Maximum principal label length.
pub const MAX_PRINCIPAL_LABEL_LEN: usize = 128;
/// Default bounded history capacity for host-mode sessions.
pub const MAX_HISTORY: usize = 64;

/// Session operating mode.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionMode {
    /// Human operator with command execution authority.
    Operator,
    /// Read-only inspection session.
    ReadOnly,
    /// Debug session for trusted development.
    Debug,
    /// Automation or scripted session.
    Automation,
    /// Guest session with minimal authority.
    Guest,
}

/// Session lifecycle state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionState {
    /// Session exists but is not accepting commands.
    New,
    /// Session accepts commands.
    Active,
    /// Session is locked until reauthorization.
    Locked,
    /// Session has been closed.
    Closed,
}

/// Principal family for terminal sessions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrincipalKind {
    /// Human operator.
    Human,
    /// System service.
    Service,
    /// Agent or cognition process.
    Agent,
    /// Host-mode test principal.
    Test,
    /// Anonymous guest principal.
    Anonymous,
}

/// Principal identity metadata visible to the terminal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TerminalPrincipal<'a> {
    /// Principal family.
    pub kind: PrincipalKind,
    /// Stable principal label.
    pub label: &'a str,
}

impl<'a> TerminalPrincipal<'a> {
    /// Creates principal metadata.
    pub const fn new(kind: PrincipalKind, label: &'a str) -> Self {
        Self { kind, label }
    }

    /// Validates principal metadata.
    pub fn validate(self) -> TerminalResult<()> {
        validate_terminal_label(self.label, MAX_PRINCIPAL_LABEL_LEN)
            .map_err(|_| TerminalError::InvalidSession)
    }
}

/// Session descriptor used when opening a terminal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionDescriptor<'a> {
    /// Stable session label.
    pub name: &'a str,
    /// Session schema version.
    pub schema: &'static str,
    /// Session mode.
    pub mode: SessionMode,
    /// Principal bound to the session.
    pub principal: TerminalPrincipal<'a>,
    /// Rights available to the session.
    pub rights: TerminalRights,
    /// Session metadata data class.
    pub data_class: DataClass,
    /// Session metadata redaction state.
    pub redaction: RedactionState,
    /// Whether session lifecycle changes must be audited.
    pub audit_required: bool,
    /// Trace context for the session.
    pub trace: TraceContext,
}

impl<'a> SessionDescriptor<'a> {
    /// Creates a session descriptor.
    pub const fn new(
        name: &'a str,
        mode: SessionMode,
        principal: TerminalPrincipal<'a>,
        rights: TerminalRights,
    ) -> Self {
        Self {
            name,
            schema: SESSION_SCHEMA_VERSION,
            mode,
            principal,
            rights,
            data_class: DataClass::Operational,
            redaction: RedactionState::Operational,
            audit_required: false,
            trace: TraceContext::EMPTY,
        }
    }

    /// Marks session lifecycle changes as audit-required.
    pub const fn with_audit_required(mut self) -> Self {
        self.audit_required = true;
        self
    }

    /// Overrides classification and redaction metadata.
    pub const fn with_data(mut self, data_class: DataClass, redaction: RedactionState) -> Self {
        self.data_class = data_class;
        self.redaction = redaction;
        self
    }

    /// Attaches trace metadata.
    pub const fn with_trace(mut self, trace: TraceContext) -> Self {
        self.trace = trace;
        self
    }

    /// Validates session descriptor metadata.
    pub fn validate(self) -> TerminalResult<()> {
        validate_terminal_label(self.name, MAX_SESSION_LABEL_LEN)
            .map_err(|_| TerminalError::InvalidSession)?;
        if self.schema.is_empty() {
            return Err(TerminalError::InvalidSession);
        }
        self.principal.validate()?;
        self.rights.validate()?;
        if self.audit_required && !self.rights.contains(TerminalRights::AUDIT) {
            return Err(TerminalError::AuditRequired);
        }
        validate_redaction(self.data_class, self.redaction)?;
        self.trace.validate()
    }
}

/// Session event kind recorded in bounded history.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionEventKind {
    /// Session opened.
    Opened,
    /// Command accepted by the session.
    CommandAccepted,
    /// Command denied by the session.
    CommandDenied,
    /// Command completed after dispatch.
    CommandCompleted,
    /// Session locked.
    Locked,
    /// Session unlocked.
    Unlocked,
    /// Session closed.
    Closed,
}

/// Session lifecycle event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionEvent<'a> {
    /// Event kind.
    pub kind: SessionEventKind,
    /// Command name or lifecycle label.
    pub command: &'a str,
    /// Monotonic event counter within the session.
    pub counter: u64,
    /// Whether this event must be represented in audit evidence.
    pub requires_audit: bool,
    /// Trace context for the event.
    pub trace: TraceContext,
}

impl<'a> SessionEvent<'a> {
    /// Creates a session event.
    pub const fn new(
        kind: SessionEventKind,
        command: &'a str,
        counter: u64,
        requires_audit: bool,
        trace: TraceContext,
    ) -> Self {
        Self {
            kind,
            command,
            counter,
            requires_audit,
            trace,
        }
    }

    /// Validates session event metadata.
    pub fn validate(self) -> TerminalResult<()> {
        validate_terminal_label(self.command, MAX_COMMAND_NAME_LEN)?;
        if self.counter == 0 {
            return Err(TerminalError::InvalidSession);
        }
        self.trace.validate()
    }
}

/// Fixed-capacity terminal session state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TerminalSession<'a, const N: usize> {
    /// Session identifier.
    pub session_id: u64,
    /// Session descriptor.
    pub descriptor: SessionDescriptor<'a>,
    /// Current lifecycle state.
    pub state: SessionState,
    events: [Option<SessionEvent<'a>>; N],
    len: usize,
}

impl<'a, const N: usize> TerminalSession<'a, N> {
    /// Creates a new unopened terminal session.
    pub fn new(session_id: u64, descriptor: SessionDescriptor<'a>) -> TerminalResult<Self> {
        if session_id == 0 {
            return Err(TerminalError::InvalidSession);
        }
        descriptor.validate()?;
        Ok(Self {
            session_id,
            descriptor,
            state: SessionState::New,
            events: [None; N],
            len: 0,
        })
    }

    /// Returns the number of recorded session events.
    pub const fn event_count(&self) -> usize {
        self.len
    }

    /// Returns `true` when the session accepts commands.
    pub const fn is_active(&self) -> bool {
        matches!(self.state, SessionState::Active)
    }

    /// Returns a session event by index.
    pub fn event(&self, index: usize) -> Option<SessionEvent<'a>> {
        if index >= self.len {
            None
        } else {
            self.events[index]
        }
    }

    /// Opens the session and records an open event.
    pub fn open(&mut self, trace: TraceContext) -> TerminalResult<()> {
        if self.state != SessionState::New {
            return Err(TerminalError::InvalidState);
        }
        trace.validate()?;
        self.push_event(SessionEvent::new(
            SessionEventKind::Opened,
            "session",
            self.next_counter(),
            self.descriptor.audit_required,
            trace,
        ))?;
        self.state = SessionState::Active;
        Ok(())
    }

    /// Records a command acceptance or denial event.
    pub fn record_command(
        &mut self,
        command: &'a str,
        accepted: bool,
        requires_audit: bool,
        trace: TraceContext,
    ) -> TerminalResult<()> {
        self.require_active()?;
        if requires_audit && !self.descriptor.rights.contains(TerminalRights::AUDIT) {
            return Err(TerminalError::AuditRequired);
        }
        let kind = if accepted {
            SessionEventKind::CommandAccepted
        } else {
            SessionEventKind::CommandDenied
        };
        self.push_event(SessionEvent::new(
            kind,
            command,
            self.next_counter(),
            requires_audit,
            trace,
        ))
    }

    /// Records command completion.
    pub fn complete_command(
        &mut self,
        command: &'a str,
        trace: TraceContext,
    ) -> TerminalResult<()> {
        self.require_active()?;
        self.push_event(SessionEvent::new(
            SessionEventKind::CommandCompleted,
            command,
            self.next_counter(),
            false,
            trace,
        ))
    }

    /// Locks an active session.
    pub fn lock(&mut self, trace: TraceContext) -> TerminalResult<()> {
        self.require_active()?;
        self.push_event(SessionEvent::new(
            SessionEventKind::Locked,
            "session",
            self.next_counter(),
            self.descriptor.audit_required,
            trace,
        ))?;
        self.state = SessionState::Locked;
        Ok(())
    }

    /// Unlocks a locked session after reauthorization.
    pub fn unlock(&mut self, rights: TerminalRights, trace: TraceContext) -> TerminalResult<()> {
        if self.state == SessionState::Closed {
            return Err(TerminalError::SessionClosed);
        }
        if self.state != SessionState::Locked {
            return Err(TerminalError::InvalidState);
        }
        rights.require(TerminalRights::EXECUTE)?;
        if self.descriptor.audit_required && !rights.contains(TerminalRights::AUDIT) {
            return Err(TerminalError::AuditRequired);
        }
        self.push_event(SessionEvent::new(
            SessionEventKind::Unlocked,
            "session",
            self.next_counter(),
            self.descriptor.audit_required,
            trace,
        ))?;
        self.state = SessionState::Active;
        Ok(())
    }

    /// Closes an active or locked session.
    pub fn close(&mut self, trace: TraceContext) -> TerminalResult<()> {
        if self.state == SessionState::Closed {
            return Err(TerminalError::SessionClosed);
        }
        if self.state == SessionState::New {
            return Err(TerminalError::InvalidState);
        }
        self.push_event(SessionEvent::new(
            SessionEventKind::Closed,
            "session",
            self.next_counter(),
            self.descriptor.audit_required,
            trace,
        ))?;
        self.state = SessionState::Closed;
        Ok(())
    }

    fn require_active(&self) -> TerminalResult<()> {
        match self.state {
            SessionState::Active => Ok(()),
            SessionState::Closed => Err(TerminalError::SessionClosed),
            SessionState::New | SessionState::Locked => Err(TerminalError::InvalidState),
        }
    }

    /// Creates a command context using the session descriptor rights.
    pub fn command_context(&self, trace: TraceContext) -> TerminalResult<CommandContext> {
        self.require_active()?;
        trace.validate()?;
        let context = CommandContext::new(self.session_id, self.descriptor.rights, trace);
        if self.descriptor.audit_required {
            Ok(context.with_audit_ready())
        } else {
            Ok(context)
        }
    }

    fn next_counter(&self) -> u64 {
        self.len as u64 + 1
    }

    fn push_event(&mut self, event: SessionEvent<'a>) -> TerminalResult<()> {
        if self.len >= N {
            return Err(TerminalError::CapacityExceeded);
        }
        event.validate()?;
        if event.requires_audit && !self.descriptor.rights.contains(TerminalRights::AUDIT) {
            return Err(TerminalError::AuditRequired);
        }
        self.events[self.len] = Some(event);
        self.len += 1;
        Ok(())
    }
}
