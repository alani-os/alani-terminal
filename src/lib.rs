#![cfg_attr(not(feature = "std"), no_std)]

//! Interactive shell and CLI contracts for Alani diagnostics and demos.
//!
//! `alani-terminal` owns command registration, command-line parsing, terminal
//! sessions, and output formatting. The API is dependency-free, `no_std`
//! compatible, and explicit about authority checks, trace propagation, data
//! classification, redaction, and audit requirements.

pub mod commands;
pub mod format;
pub mod parser;
pub mod session;

pub use commands::{
    BuiltinCommand, Command, CommandArgument, CommandContext, CommandDescriptor, CommandKind,
    CommandRegistry, CommandRequest, CommandResultRecord, CommandStatus, COMMANDS_SCHEMA_VERSION,
    MAX_COMMANDS, MAX_COMMAND_ARGS, MAX_COMMAND_ARGUMENT_LEN, MAX_COMMAND_NAME_LEN,
    MAX_COMMAND_OUTPUT_LEN,
};
pub use format::{
    format_command_result, format_record, DiagnosticRecord, FormatDescriptor, FormatStyle,
    FormattedOutput, OutputFormat, Severity, FORMAT_SCHEMA_VERSION, MAX_DIAGNOSTIC_MESSAGE_LEN,
    MAX_FORMAT_LABEL_LEN, MAX_FORMAT_WIDTH,
};
pub use parser::{
    contains_sensitive_literal, parse_command, ParsePolicy, ParsedCommand, ParserDescriptor, Token,
    TokenKind, MAX_INPUT_LEN, MAX_SCRIPT_LINES, MAX_TOKENS, MAX_TOKEN_LEN, PARSER_SCHEMA_VERSION,
};
pub use parser::{parse_script, ScriptPlan};
pub use session::{
    PrincipalKind, SessionDescriptor, SessionEvent, SessionEventKind, SessionMode, SessionState,
    TerminalPrincipal, TerminalSession, MAX_HISTORY, MAX_PRINCIPAL_LABEL_LEN,
    MAX_SESSION_LABEL_LEN, SESSION_SCHEMA_VERSION,
};

/// Repository name.
pub const REPOSITORY: &str = "alani-terminal";

/// Crate version.
pub const VERSION: &str = "0.1.0";

/// Public module names exposed by this crate.
pub const MODULES: &[&str] = &["commands", "parser", "session", "format"];

/// Feature bit for command descriptors and registries.
pub const TERMINAL_FEATURE_COMMANDS: u64 = 1 << 0;
/// Feature bit for shell input parsing.
pub const TERMINAL_FEATURE_PARSER: u64 = 1 << 1;
/// Feature bit for session lifecycle tracking.
pub const TERMINAL_FEATURE_SESSION: u64 = 1 << 2;
/// Feature bit for diagnostic output formatting.
pub const TERMINAL_FEATURE_FORMAT: u64 = 1 << 3;
/// Feature bit for scripting-oriented command arguments.
pub const TERMINAL_FEATURE_SCRIPTING: u64 = 1 << 4;
/// Feature bit for trace-view commands.
pub const TERMINAL_FEATURE_TRACE_VIEW: u64 = 1 << 5;
/// Feature bit for cognition experiment command surfaces.
pub const TERMINAL_FEATURE_COGNITION_RUN: u64 = 1 << 6;
/// Feature bit for service-control command surfaces.
pub const TERMINAL_FEATURE_SERVICE_CONTROL: u64 = 1 << 7;
/// Feature bit for data classification and redaction validation.
pub const TERMINAL_FEATURE_REDACTION: u64 = 1 << 8;

/// All terminal feature bits known by this crate version.
pub const TERMINAL_KNOWN_FEATURES: u64 = TERMINAL_FEATURE_COMMANDS
    | TERMINAL_FEATURE_PARSER
    | TERMINAL_FEATURE_SESSION
    | TERMINAL_FEATURE_FORMAT
    | TERMINAL_FEATURE_SCRIPTING
    | TERMINAL_FEATURE_TRACE_VIEW
    | TERMINAL_FEATURE_COGNITION_RUN
    | TERMINAL_FEATURE_SERVICE_CONTROL
    | TERMINAL_FEATURE_REDACTION;

/// Caller may inspect terminal and runtime state.
pub const TERMINAL_RIGHT_READ: u64 = 1 << 0;
/// Caller may execute ordinary terminal commands.
pub const TERMINAL_RIGHT_EXECUTE: u64 = 1 << 1;
/// Caller may control services.
pub const TERMINAL_RIGHT_SERVICE_CONTROL: u64 = 1 << 2;
/// Caller may run debug commands.
pub const TERMINAL_RIGHT_DEBUG: u64 = 1 << 3;
/// Caller may run cognition experiments.
pub const TERMINAL_RIGHT_COGNITION: u64 = 1 << 4;
/// Caller may render or export formatted output.
pub const TERMINAL_RIGHT_FORMAT: u64 = 1 << 5;
/// Caller may inspect trace events.
pub const TERMINAL_RIGHT_TRACE_READ: u64 = 1 << 6;
/// Caller may emit or preserve audit evidence.
pub const TERMINAL_RIGHT_AUDIT: u64 = 1 << 7;
/// Caller has administrative terminal authority.
pub const TERMINAL_RIGHT_ADMIN: u64 = 1 << 8;

/// All terminal rights known by this crate version.
pub const TERMINAL_KNOWN_RIGHTS: u64 = TERMINAL_RIGHT_READ
    | TERMINAL_RIGHT_EXECUTE
    | TERMINAL_RIGHT_SERVICE_CONTROL
    | TERMINAL_RIGHT_DEBUG
    | TERMINAL_RIGHT_COGNITION
    | TERMINAL_RIGHT_FORMAT
    | TERMINAL_RIGHT_TRACE_READ
    | TERMINAL_RIGHT_AUDIT
    | TERMINAL_RIGHT_ADMIN;

/// Trace flag indicating the terminal event was sampled.
pub const TRACE_FLAG_SAMPLED: u32 = 1 << 0;
/// Trace flag indicating debug metadata may be attached by a trusted sink.
pub const TRACE_FLAG_DEBUG: u32 = 1 << 1;
/// Trace flag indicating an interactive trust boundary was crossed.
pub const TRACE_FLAG_INTERACTIVE_BOUNDARY: u32 = 1 << 2;
/// Trace flag indicating audit evidence must be preserved.
pub const TRACE_FLAG_AUDIT_REQUIRED: u32 = 1 << 3;

/// Trace flags known by this crate version.
pub const TRACE_KNOWN_FLAGS: u32 = TRACE_FLAG_SAMPLED
    | TRACE_FLAG_DEBUG
    | TRACE_FLAG_INTERACTIVE_BOUNDARY
    | TRACE_FLAG_AUDIT_REQUIRED;

/// Result alias for terminal validation and host-mode operations.
pub type TerminalResult<T> = Result<T, TerminalError>;

/// Error taxonomy for command, parser, session, and formatting contracts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TerminalError {
    /// A required field was empty or omitted.
    MissingField,
    /// A bounded field exceeded its documented maximum length.
    FieldTooLong,
    /// A stable label contained a disallowed character.
    InvalidLabel,
    /// Unknown feature, flag, right, or option bits were supplied.
    ReservedBits,
    /// Command descriptor metadata failed validation.
    InvalidCommand,
    /// Requested command was not registered.
    UnknownCommand,
    /// Command argument metadata failed validation.
    InvalidArgument,
    /// Command input could not be parsed safely.
    ParseError,
    /// Parser descriptor or policy failed validation.
    InvalidParser,
    /// Session descriptor or identifier failed validation.
    InvalidSession,
    /// Operation attempted to use a closed session.
    SessionClosed,
    /// Formatter descriptor or output metadata failed validation.
    InvalidFormat,
    /// Caller lacks required terminal authority.
    AccessDenied,
    /// Audit evidence is required but not authorized or available.
    AuditRequired,
    /// Operation attempted to mutate a sealed registry.
    Sealed,
    /// Fixed-capacity collection is full.
    CapacityExceeded,
    /// Duplicate entry was supplied.
    Duplicate,
    /// State machine transition is not allowed.
    InvalidState,
    /// Trace context was malformed.
    InvalidTrace,
    /// Redaction state is incompatible with data classification.
    InvalidRedaction,
    /// Sensitive input literal was rejected by policy.
    SensitiveInput,
    /// Sensitive output would be exposed without redaction.
    SensitiveOutput,
    /// Internal invariant failed.
    Internal,
}

impl TerminalError {
    /// Stable reason label for diagnostics and tests.
    pub const fn reason(self) -> &'static str {
        match self {
            Self::MissingField => "missing_field",
            Self::FieldTooLong => "field_too_long",
            Self::InvalidLabel => "invalid_label",
            Self::ReservedBits => "reserved_bits",
            Self::InvalidCommand => "invalid_command",
            Self::UnknownCommand => "unknown_command",
            Self::InvalidArgument => "invalid_argument",
            Self::ParseError => "parse_error",
            Self::InvalidParser => "invalid_parser",
            Self::InvalidSession => "invalid_session",
            Self::SessionClosed => "session_closed",
            Self::InvalidFormat => "invalid_format",
            Self::AccessDenied => "access_denied",
            Self::AuditRequired => "audit_required",
            Self::Sealed => "sealed",
            Self::CapacityExceeded => "capacity_exceeded",
            Self::Duplicate => "duplicate",
            Self::InvalidState => "invalid_state",
            Self::InvalidTrace => "invalid_trace",
            Self::InvalidRedaction => "invalid_redaction",
            Self::SensitiveInput => "sensitive_input",
            Self::SensitiveOutput => "sensitive_output",
            Self::Internal => "internal",
        }
    }

    /// Returns `true` when this error represents a fail-closed trust boundary.
    pub const fn is_security_relevant(self) -> bool {
        matches!(
            self,
            Self::ReservedBits
                | Self::InvalidCommand
                | Self::InvalidArgument
                | Self::ParseError
                | Self::AccessDenied
                | Self::AuditRequired
                | Self::Sealed
                | Self::InvalidTrace
                | Self::InvalidRedaction
                | Self::SensitiveInput
                | Self::SensitiveOutput
        )
    }
}

/// Data sensitivity classification for terminal inputs, outputs, and metadata.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum DataClass {
    /// Public metadata or output.
    Public = 0,
    /// Operational metadata suitable for trusted operators.
    Operational = 1,
    /// Sensitive data requiring redaction before broad export.
    Sensitive = 2,
    /// Secret data that must not be exported raw.
    Secret = 3,
}

impl DataClass {
    /// Returns `true` when data with this class must be redacted before export.
    pub const fn requires_redaction(self) -> bool {
        matches!(self, Self::Sensitive | Self::Secret)
    }

    /// Stable data class label.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Operational => "operational",
            Self::Sensitive => "sensitive",
            Self::Secret => "secret",
        }
    }
}

/// Redaction state applied to terminal inputs, outputs, and diagnostics.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RedactionState {
    /// Public fields only.
    Public = 0,
    /// Operational metadata only.
    Operational = 1,
    /// Sensitive fields were redacted.
    SensitiveRedacted = 2,
    /// Secret fields were redacted.
    SecretRedacted = 3,
    /// Sensitive fields are present and must not be exported broadly.
    UnredactedSensitive = 4,
}

impl RedactionState {
    /// Stable redaction label.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Operational => "operational",
            Self::SensitiveRedacted => "sensitive_redacted",
            Self::SecretRedacted => "secret_redacted",
            Self::UnredactedSensitive => "unredacted_sensitive",
        }
    }
}

/// Stable trace context copied from observability layers when present.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TraceContext {
    /// Trace identifier shared across component boundaries.
    pub trace_id: u64,
    /// Current span identifier.
    pub span_id: u64,
    /// Parent span identifier.
    pub parent_span_id: u64,
    /// Trace flags.
    pub flags: u32,
}

impl TraceContext {
    /// Empty trace context used when no trace is available.
    pub const EMPTY: Self = Self {
        trace_id: 0,
        span_id: 0,
        parent_span_id: 0,
        flags: 0,
    };

    /// Creates a root trace context for a terminal interaction.
    pub const fn root(trace_id: u64, span_id: u64) -> Self {
        Self {
            trace_id,
            span_id,
            parent_span_id: 0,
            flags: TRACE_FLAG_SAMPLED | TRACE_FLAG_INTERACTIVE_BOUNDARY,
        }
    }

    /// Creates a child trace context preserving the trace identifier.
    pub const fn child(self, span_id: u64) -> Self {
        Self {
            trace_id: self.trace_id,
            span_id,
            parent_span_id: self.span_id,
            flags: self.flags,
        }
    }

    /// Sets trace flags.
    pub const fn with_flags(mut self, flags: u32) -> Self {
        self.flags = flags;
        self
    }

    /// Returns `true` when both trace and span identifiers are present.
    pub const fn is_present(self) -> bool {
        self.trace_id != 0 && self.span_id != 0
    }

    /// Returns `true` when all requested trace flags are present.
    pub const fn has_flags(self, flags: u32) -> bool {
        self.flags & flags == flags
    }

    /// Validates trace metadata.
    pub const fn validate(self) -> TerminalResult<()> {
        if self.flags & !TRACE_KNOWN_FLAGS != 0 {
            return Err(TerminalError::ReservedBits);
        }
        if self.trace_id == 0 && self.span_id == 0 && self.parent_span_id == 0 {
            return Ok(());
        }
        if self.trace_id == 0 || self.span_id == 0 {
            return Err(TerminalError::InvalidTrace);
        }
        if self.parent_span_id != 0 && self.parent_span_id == self.span_id {
            return Err(TerminalError::InvalidTrace);
        }
        Ok(())
    }
}

/// Terminal authority bitmap used for fail-closed command gates.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TerminalRights(pub u64);

impl TerminalRights {
    /// No authority.
    pub const NONE: Self = Self(0);
    /// Inspect terminal and runtime metadata.
    pub const READ: Self = Self(TERMINAL_RIGHT_READ);
    /// Execute ordinary commands.
    pub const EXECUTE: Self = Self(TERMINAL_RIGHT_EXECUTE);
    /// Control services.
    pub const SERVICE_CONTROL: Self = Self(TERMINAL_RIGHT_SERVICE_CONTROL);
    /// Run debug commands.
    pub const DEBUG: Self = Self(TERMINAL_RIGHT_DEBUG);
    /// Run cognition experiments.
    pub const COGNITION: Self = Self(TERMINAL_RIGHT_COGNITION);
    /// Render or export formatted output.
    pub const FORMAT: Self = Self(TERMINAL_RIGHT_FORMAT);
    /// Inspect trace events.
    pub const TRACE_READ: Self = Self(TERMINAL_RIGHT_TRACE_READ);
    /// Emit or preserve audit evidence.
    pub const AUDIT: Self = Self(TERMINAL_RIGHT_AUDIT);
    /// Administrative terminal authority.
    pub const ADMIN: Self = Self(TERMINAL_RIGHT_ADMIN);
    /// Full authority for host-mode administrative tests.
    pub const ADMINISTRATOR: Self = Self(TERMINAL_KNOWN_RIGHTS);

    /// Creates rights from raw bits after rejecting unknown bits.
    pub const fn from_bits(bits: u64) -> TerminalResult<Self> {
        if bits & !TERMINAL_KNOWN_RIGHTS != 0 {
            Err(TerminalError::ReservedBits)
        } else {
            Ok(Self(bits))
        }
    }

    /// Returns raw rights bits.
    pub const fn bits(self) -> u64 {
        self.0
    }

    /// Returns `true` when all required rights are present.
    pub const fn contains(self, required: Self) -> bool {
        self.0 & required.0 == required.0
    }

    /// Combines two rights sets.
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Validates reserved bits.
    pub const fn validate(self) -> TerminalResult<()> {
        if self.0 & !TERMINAL_KNOWN_RIGHTS != 0 {
            Err(TerminalError::ReservedBits)
        } else {
            Ok(())
        }
    }

    /// Fails closed when required rights are absent.
    pub const fn require(self, required: Self) -> TerminalResult<()> {
        if self.0 & !TERMINAL_KNOWN_RIGHTS != 0 || required.0 & !TERMINAL_KNOWN_RIGHTS != 0 {
            return Err(TerminalError::ReservedBits);
        }
        if self.contains(required) {
            Ok(())
        } else {
            Err(TerminalError::AccessDenied)
        }
    }
}

/// Implementation maturity marker for generated repository metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ComponentStatus {
    /// API is present as a draft skeleton.
    Draft,
    /// API is implemented enough for host-mode experimentation.
    Experimental,
    /// API is compatible and stable.
    Stable,
}

/// Stable component identity record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ComponentInfo {
    /// Repository name.
    pub repository: &'static str,
    /// Crate version.
    pub version: &'static str,
    /// Current implementation status.
    pub status: ComponentStatus,
}

/// Returns stable component identity metadata.
pub const fn component_info() -> ComponentInfo {
    ComponentInfo {
        repository: REPOSITORY,
        version: VERSION,
        status: ComponentStatus::Experimental,
    }
}

/// Returns the repository name.
pub const fn repository_name() -> &'static str {
    REPOSITORY
}

/// Returns public module names.
pub fn module_names() -> &'static [&'static str] {
    MODULES
}

/// Compact root view of the terminal crate contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TerminalCatalog {
    /// Repository name.
    pub repository: &'static str,
    /// Crate version.
    pub version: &'static str,
    /// Feature bitmap.
    pub features: u64,
    /// Rights bitmap recognized by this crate version.
    pub rights: u64,
    /// Command schema version.
    pub commands_schema: &'static str,
    /// Parser schema version.
    pub parser_schema: &'static str,
    /// Session schema version.
    pub session_schema: &'static str,
    /// Format schema version.
    pub format_schema: &'static str,
}

impl TerminalCatalog {
    /// Current terminal catalog.
    pub const CURRENT: Self = Self {
        repository: REPOSITORY,
        version: VERSION,
        features: TERMINAL_KNOWN_FEATURES,
        rights: TERMINAL_KNOWN_RIGHTS,
        commands_schema: COMMANDS_SCHEMA_VERSION,
        parser_schema: PARSER_SCHEMA_VERSION,
        session_schema: SESSION_SCHEMA_VERSION,
        format_schema: FORMAT_SCHEMA_VERSION,
    };

    /// Validates catalog metadata.
    pub const fn validate(self) -> TerminalResult<()> {
        if self.repository.is_empty()
            || self.version.is_empty()
            || self.commands_schema.is_empty()
            || self.parser_schema.is_empty()
            || self.session_schema.is_empty()
            || self.format_schema.is_empty()
        {
            return Err(TerminalError::MissingField);
        }
        if self.features & !TERMINAL_KNOWN_FEATURES != 0
            || self.rights & !TERMINAL_KNOWN_RIGHTS != 0
        {
            return Err(TerminalError::ReservedBits);
        }
        Ok(())
    }
}

/// Current terminal catalog.
pub const TERMINAL_CATALOG: TerminalCatalog = TerminalCatalog::CURRENT;

/// Returns the current terminal catalog.
pub const fn terminal_catalog() -> TerminalCatalog {
    TerminalCatalog::CURRENT
}

/// Validates redaction state for a data class.
pub const fn validate_redaction(
    data_class: DataClass,
    redaction: RedactionState,
) -> TerminalResult<()> {
    match data_class {
        DataClass::Public => {
            if matches!(redaction, RedactionState::Public) {
                Ok(())
            } else {
                Err(TerminalError::InvalidRedaction)
            }
        }
        DataClass::Operational => {
            if matches!(redaction, RedactionState::Operational) {
                Ok(())
            } else {
                Err(TerminalError::InvalidRedaction)
            }
        }
        DataClass::Sensitive => {
            if matches!(
                redaction,
                RedactionState::SensitiveRedacted | RedactionState::SecretRedacted
            ) {
                Ok(())
            } else {
                Err(TerminalError::InvalidRedaction)
            }
        }
        DataClass::Secret => {
            if matches!(redaction, RedactionState::SecretRedacted) {
                Ok(())
            } else {
                Err(TerminalError::InvalidRedaction)
            }
        }
    }
}

/// Validates a stable terminal label.
pub fn validate_terminal_label(label: &str, max_len: usize) -> TerminalResult<()> {
    if label.is_empty() {
        return Err(TerminalError::MissingField);
    }
    if label.len() > max_len {
        return Err(TerminalError::FieldTooLong);
    }
    if !label.bytes().all(|byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b':' | b'_' | b'-' | b'.' | b'/' | b'@')
    }) {
        return Err(TerminalError::InvalidLabel);
    }
    Ok(())
}
