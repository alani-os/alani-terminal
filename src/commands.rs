//! Command registration and execution boundary.
//!
//! The terminal command layer is intentionally small: descriptors declare the
//! authority, audit, trace, and output classification requirements for a
//! command, while registries provide fixed-capacity host-mode lookup and
//! authorization checks.

use crate::{
    validate_redaction, validate_terminal_label, DataClass, RedactionState, TerminalError,
    TerminalResult, TerminalRights, TraceContext,
};

/// Command descriptor schema version.
pub const COMMANDS_SCHEMA_VERSION: &str = "alani-terminal.commands.v1";
/// Maximum command name length.
pub const MAX_COMMAND_NAME_LEN: usize = 64;
/// Maximum command argument value length.
pub const MAX_COMMAND_ARGUMENT_LEN: usize = 256;
/// Maximum command output length accepted by skeleton formatters.
pub const MAX_COMMAND_OUTPUT_LEN: usize = 4096;
/// Maximum arguments accepted by host-mode command requests.
pub const MAX_COMMAND_ARGS: usize = 16;
/// Default command registry capacity used by tests and examples.
pub const MAX_COMMANDS: usize = 64;

/// High-level command family used for policy and UI grouping.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommandKind {
    /// Inspect runtime, kernel, or component state.
    Inspect,
    /// Control service lifecycle.
    ServiceControl,
    /// Run cognition experiments or demos.
    Cognition,
    /// Run debug-only commands.
    Debug,
    /// Display trace or diagnostic events.
    Trace,
    /// Display terminal help.
    Help,
    /// Exit or close the current session.
    Exit,
    /// Echo public text for smoke tests and demos.
    Echo,
}

impl CommandKind {
    /// Stable command-kind label.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Inspect => "inspect",
            Self::ServiceControl => "service_control",
            Self::Cognition => "cognition",
            Self::Debug => "debug",
            Self::Trace => "trace",
            Self::Help => "help",
            Self::Exit => "exit",
            Self::Echo => "echo",
        }
    }
}

/// Built-in command descriptors exposed by the terminal skeleton.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BuiltinCommand {
    /// `help` command.
    Help,
    /// `inspect` command for runtime or component state.
    Inspect,
    /// `trace.show` command for diagnostic trace inspection.
    TraceShow,
    /// `service.restart` command for service lifecycle control.
    ServiceRestart,
    /// `cognition.run` command for cognition experiments.
    CognitionRun,
    /// `debug.dump` command for trusted debug sessions.
    DebugDump,
    /// `exit` command.
    Exit,
    /// `echo` command for host-mode smoke tests.
    Echo,
}

impl BuiltinCommand {
    /// Returns the stable descriptor for a built-in command.
    pub const fn descriptor(self) -> CommandDescriptor<'static> {
        match self {
            Self::Help => CommandDescriptor::new("help", CommandKind::Help, TerminalRights::READ)
                .with_output(DataClass::Public, RedactionState::Public),
            Self::Inspect => {
                CommandDescriptor::new("inspect", CommandKind::Inspect, TerminalRights::READ)
            }
            Self::TraceShow => {
                CommandDescriptor::new("trace.show", CommandKind::Trace, TerminalRights::TRACE_READ)
                    .with_output(DataClass::Operational, RedactionState::Operational)
            }
            Self::ServiceRestart => CommandDescriptor::new(
                "service.restart",
                CommandKind::ServiceControl,
                TerminalRights::SERVICE_CONTROL,
            )
            .with_audit(),
            Self::CognitionRun => CommandDescriptor::new(
                "cognition.run",
                CommandKind::Cognition,
                TerminalRights::COGNITION,
            )
            .with_audit(),
            Self::DebugDump => {
                CommandDescriptor::new("debug.dump", CommandKind::Debug, TerminalRights::DEBUG)
                    .with_audit()
                    .with_output(DataClass::Sensitive, RedactionState::SensitiveRedacted)
            }
            Self::Exit => {
                CommandDescriptor::new("exit", CommandKind::Exit, TerminalRights::EXECUTE)
                    .with_output(DataClass::Public, RedactionState::Public)
            }
            Self::Echo => {
                CommandDescriptor::new("echo", CommandKind::Echo, TerminalRights::EXECUTE)
                    .with_output(DataClass::Public, RedactionState::Public)
            }
        }
    }
}

/// Command argument metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommandArgument<'a> {
    /// Optional argument name. Positional arguments use an empty name.
    pub name: &'a str,
    /// Argument value.
    pub value: &'a str,
    /// Data class for the value.
    pub data_class: DataClass,
    /// Redaction state for the value.
    pub redaction: RedactionState,
}

impl<'a> CommandArgument<'a> {
    /// Creates a named command argument.
    pub const fn named(
        name: &'a str,
        value: &'a str,
        data_class: DataClass,
        redaction: RedactionState,
    ) -> Self {
        Self {
            name,
            value,
            data_class,
            redaction,
        }
    }

    /// Creates a positional public command argument.
    pub const fn positional(value: &'a str) -> Self {
        Self {
            name: "",
            value,
            data_class: DataClass::Public,
            redaction: RedactionState::Public,
        }
    }

    /// Validates argument bounds, labels, and redaction metadata.
    pub fn validate(self) -> TerminalResult<()> {
        if !self.name.is_empty() {
            validate_terminal_label(self.name, MAX_COMMAND_NAME_LEN)?;
        }
        if self.value.is_empty() {
            return Err(TerminalError::InvalidArgument);
        }
        if self.value.len() > MAX_COMMAND_ARGUMENT_LEN {
            return Err(TerminalError::FieldTooLong);
        }
        validate_redaction(self.data_class, self.redaction)
            .map_err(|_| TerminalError::InvalidArgument)
    }
}

/// Stable command descriptor consumed by command registries and shell help.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommandDescriptor<'a> {
    /// Stable command name.
    pub name: &'a str,
    /// Descriptor schema version.
    pub schema: &'static str,
    /// Command family.
    pub kind: CommandKind,
    /// Rights required before execution.
    pub required_rights: TerminalRights,
    /// Whether execution must preserve audit evidence.
    pub requires_audit: bool,
    /// Data class for command output.
    pub output_class: DataClass,
    /// Redaction state for command output.
    pub output_redaction: RedactionState,
    /// Trace context attached to the descriptor when it was created.
    pub trace: TraceContext,
}

impl<'a> CommandDescriptor<'a> {
    /// Creates a command descriptor.
    pub const fn new(name: &'a str, kind: CommandKind, required_rights: TerminalRights) -> Self {
        Self {
            name,
            schema: COMMANDS_SCHEMA_VERSION,
            kind,
            required_rights,
            requires_audit: false,
            output_class: DataClass::Operational,
            output_redaction: RedactionState::Operational,
            trace: TraceContext::EMPTY,
        }
    }

    /// Marks the command as requiring audit evidence.
    pub const fn with_audit(mut self) -> Self {
        self.requires_audit = true;
        self
    }

    /// Overrides output classification and redaction metadata.
    pub const fn with_output(
        mut self,
        output_class: DataClass,
        output_redaction: RedactionState,
    ) -> Self {
        self.output_class = output_class;
        self.output_redaction = output_redaction;
        self
    }

    /// Attaches trace metadata.
    pub const fn with_trace(mut self, trace: TraceContext) -> Self {
        self.trace = trace;
        self
    }

    /// Validates descriptor metadata.
    pub fn validate(self) -> TerminalResult<()> {
        validate_terminal_label(self.name, MAX_COMMAND_NAME_LEN)
            .map_err(|_| TerminalError::InvalidCommand)?;
        if self.schema.is_empty() {
            return Err(TerminalError::InvalidCommand);
        }
        self.required_rights.validate()?;
        self.trace.validate()?;
        validate_redaction(self.output_class, self.output_redaction)
    }
}

/// Caller and session context supplied to command execution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommandContext {
    /// Terminal session identifier.
    pub session_id: u64,
    /// Rights held by the caller.
    pub rights: TerminalRights,
    /// Trace context for the execution.
    pub trace: TraceContext,
    /// Whether the caller has an available audit sink.
    pub audit_ready: bool,
}

impl CommandContext {
    /// Creates a command context.
    pub const fn new(session_id: u64, rights: TerminalRights, trace: TraceContext) -> Self {
        Self {
            session_id,
            rights,
            trace,
            audit_ready: false,
        }
    }

    /// Marks the context as having an audit sink.
    pub const fn with_audit_ready(mut self) -> Self {
        self.audit_ready = true;
        self
    }

    /// Validates context metadata.
    pub fn validate(self) -> TerminalResult<()> {
        if self.session_id == 0 {
            return Err(TerminalError::InvalidSession);
        }
        self.rights.validate()?;
        self.trace.validate()
    }
}

/// Parsed command request ready for authorization and dispatch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommandRequest<'a> {
    /// Command descriptor selected by the parser or registry.
    pub descriptor: CommandDescriptor<'a>,
    /// Command arguments.
    pub arguments: &'a [CommandArgument<'a>],
    /// Raw command line.
    pub raw: &'a str,
    /// Terminal session identifier.
    pub session_id: u64,
    /// Trace context for this request.
    pub trace: TraceContext,
}

impl<'a> CommandRequest<'a> {
    /// Creates a command request.
    pub const fn new(
        descriptor: CommandDescriptor<'a>,
        arguments: &'a [CommandArgument<'a>],
        raw: &'a str,
        session_id: u64,
        trace: TraceContext,
    ) -> Self {
        Self {
            descriptor,
            arguments,
            raw,
            session_id,
            trace,
        }
    }

    /// Validates request metadata and argument bounds.
    pub fn validate(self) -> TerminalResult<()> {
        self.descriptor.validate()?;
        if self.arguments.len() > MAX_COMMAND_ARGS {
            return Err(TerminalError::CapacityExceeded);
        }
        if self.raw.is_empty() {
            return Err(TerminalError::MissingField);
        }
        if self.raw.len() > MAX_COMMAND_OUTPUT_LEN {
            return Err(TerminalError::FieldTooLong);
        }
        if self.session_id == 0 {
            return Err(TerminalError::InvalidSession);
        }
        self.trace.validate()?;
        for argument in self.arguments {
            argument.validate()?;
        }
        Ok(())
    }

    /// Returns `true` when this request must preserve audit evidence.
    pub const fn requires_audit(self) -> bool {
        self.descriptor.requires_audit || self.trace.has_flags(crate::TRACE_FLAG_AUDIT_REQUIRED)
    }
}

/// Execution status for a command result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommandStatus {
    /// Command was accepted but has not produced a terminal result.
    Accepted,
    /// Command completed successfully.
    Completed,
    /// Command was denied by policy.
    Denied,
    /// Command failed after dispatch.
    Failed,
    /// Command could not proceed until audit evidence is available.
    NeedsAudit,
    /// Command requested session exit.
    Exited,
}

impl CommandStatus {
    /// Stable status label.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Completed => "completed",
            Self::Denied => "denied",
            Self::Failed => "failed",
            Self::NeedsAudit => "needs_audit",
            Self::Exited => "exited",
        }
    }

    /// Returns `true` when this status represents successful completion.
    pub const fn is_success(self) -> bool {
        matches!(self, Self::Completed | Self::Exited)
    }
}

/// Output record returned by host-mode command dispatch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommandResultRecord<'a> {
    /// Command name.
    pub command: &'a str,
    /// Command status.
    pub status: CommandStatus,
    /// Output body. Empty output is valid for command skeletons.
    pub output: &'a str,
    /// Data class for output.
    pub data_class: DataClass,
    /// Redaction state for output.
    pub redaction: RedactionState,
    /// Trace context propagated to output.
    pub trace: TraceContext,
}

impl<'a> CommandResultRecord<'a> {
    /// Creates a command result record.
    pub const fn new(
        command: &'a str,
        status: CommandStatus,
        output: &'a str,
        data_class: DataClass,
        redaction: RedactionState,
        trace: TraceContext,
    ) -> Self {
        Self {
            command,
            status,
            output,
            data_class,
            redaction,
            trace,
        }
    }

    /// Validates result metadata before formatting or export.
    pub fn validate(self) -> TerminalResult<()> {
        validate_terminal_label(self.command, MAX_COMMAND_NAME_LEN)?;
        if self.output.len() > MAX_COMMAND_OUTPUT_LEN {
            return Err(TerminalError::FieldTooLong);
        }
        self.trace.validate()?;
        validate_redaction(self.data_class, self.redaction)
    }

    /// Returns `true` when this result is displayable as a successful command.
    pub const fn is_success(self) -> bool {
        self.status.is_success()
    }
}

/// Trait implemented by concrete command handlers.
pub trait Command<'a> {
    /// Returns the stable command descriptor.
    fn descriptor(&self) -> CommandDescriptor<'a>;

    /// Executes the command with already parsed and validated input.
    fn execute(
        &self,
        context: CommandContext,
        request: CommandRequest<'a>,
    ) -> TerminalResult<CommandResultRecord<'a>>;
}

/// Fixed-capacity command registry for host-mode demos and tests.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandRegistry<'a, const N: usize> {
    entries: [Option<CommandDescriptor<'a>>; N],
    len: usize,
    sealed: bool,
}

impl<'a, const N: usize> CommandRegistry<'a, N> {
    /// Creates an empty command registry.
    pub const fn new() -> Self {
        Self {
            entries: [None; N],
            len: 0,
            sealed: false,
        }
    }

    /// Returns the number of registered commands.
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Returns `true` when no commands are registered.
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Returns `true` when the registry no longer accepts additions.
    pub const fn is_sealed(&self) -> bool {
        self.sealed
    }

    /// Prevents further command registrations.
    pub fn seal(&mut self) {
        self.sealed = true;
    }

    /// Registers a command descriptor.
    pub fn register(&mut self, descriptor: CommandDescriptor<'a>) -> TerminalResult<()> {
        if self.sealed {
            return Err(TerminalError::Sealed);
        }
        descriptor.validate()?;
        if self.find(descriptor.name).is_ok() {
            return Err(TerminalError::Duplicate);
        }
        if self.len >= N {
            return Err(TerminalError::CapacityExceeded);
        }
        self.entries[self.len] = Some(descriptor);
        self.len += 1;
        Ok(())
    }

    /// Registers one built-in command descriptor.
    pub fn register_builtin(&mut self, command: BuiltinCommand) -> TerminalResult<()> {
        self.register(command.descriptor())
    }

    /// Finds a registered command descriptor by name.
    pub fn find(&self, name: &str) -> TerminalResult<CommandDescriptor<'a>> {
        validate_terminal_label(name, MAX_COMMAND_NAME_LEN)?;
        for descriptor in self.entries.iter().take(self.len).flatten() {
            if descriptor.name == name {
                return Ok(*descriptor);
            }
        }
        Err(TerminalError::UnknownCommand)
    }

    /// Authorizes a command descriptor for the supplied context.
    pub fn authorize(
        &self,
        descriptor: CommandDescriptor<'a>,
        context: CommandContext,
    ) -> TerminalResult<()> {
        descriptor.validate()?;
        context.validate()?;
        context.rights.require(descriptor.required_rights)?;
        if descriptor.requires_audit
            && (!context.audit_ready || !context.rights.contains(TerminalRights::AUDIT))
        {
            return Err(TerminalError::AuditRequired);
        }
        Ok(())
    }

    /// Performs registry lookup and fail-closed authorization for a request.
    ///
    /// This skeleton does not run command side effects. It returns an empty
    /// result record that downstream formatters can validate.
    pub fn execute_declared(
        &self,
        context: CommandContext,
        request: CommandRequest<'a>,
    ) -> TerminalResult<CommandResultRecord<'a>> {
        request.validate()?;
        let descriptor = self.find(request.descriptor.name)?;
        self.authorize(descriptor, context)?;
        let status = if descriptor.kind == CommandKind::Exit {
            CommandStatus::Exited
        } else {
            CommandStatus::Completed
        };
        Ok(CommandResultRecord::new(
            descriptor.name,
            status,
            "",
            descriptor.output_class,
            descriptor.output_redaction,
            request.trace,
        ))
    }
}

impl<'a, const N: usize> Default for CommandRegistry<'a, N> {
    fn default() -> Self {
        Self::new()
    }
}
