//! Output formatting and diagnostic record boundary.
//!
//! Formatters validate output metadata and carry classification, redaction, and
//! trace context forward. The skeleton deliberately avoids allocation; it
//! returns borrowed bodies that concrete terminal frontends can render.

use crate::{
    commands::CommandResultRecord, validate_redaction, validate_terminal_label, DataClass,
    RedactionState, TerminalError, TerminalResult, TraceContext,
};

/// Formatter descriptor schema version.
pub const FORMAT_SCHEMA_VERSION: &str = "alani-terminal.format.v1";
/// Maximum formatter label length.
pub const MAX_FORMAT_LABEL_LEN: usize = 64;
/// Maximum diagnostic message length.
pub const MAX_DIAGNOSTIC_MESSAGE_LEN: usize = 4096;
/// Maximum formatter width accepted by the skeleton.
pub const MAX_FORMAT_WIDTH: u16 = 240;

/// Supported terminal output formats.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutputFormat {
    /// Plain text.
    Plain,
    /// JSON Lines envelope expected by tooling.
    JsonLines,
    /// Fixed-width table view.
    Table,
    /// Markdown-oriented host output.
    Markdown,
    /// Diagnostic record view.
    Diagnostic,
}

impl OutputFormat {
    /// Stable format label.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Plain => "plain",
            Self::JsonLines => "jsonl",
            Self::Table => "table",
            Self::Markdown => "markdown",
            Self::Diagnostic => "diagnostic",
        }
    }
}

/// Diagnostic severity.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum Severity {
    /// Trace-level details.
    Trace,
    /// Debug-only details.
    Debug,
    /// Informational output.
    Info,
    /// Warning output.
    Warn,
    /// Error output.
    Error,
}

impl Severity {
    /// Stable severity label.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Trace => "trace",
            Self::Debug => "debug",
            Self::Info => "info",
            Self::Warn => "warn",
            Self::Error => "error",
        }
    }
}

/// Formatter style preferences.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FormatStyle {
    /// Whether ANSI color may be emitted by a concrete frontend.
    pub color: bool,
    /// Preferred output width. Zero means unbounded.
    pub width: u16,
    /// Whether sensitive output must be redacted.
    pub redact_sensitive: bool,
}

impl FormatStyle {
    /// Conservative default style.
    pub const DEFAULT: Self = Self {
        color: false,
        width: 80,
        redact_sensitive: true,
    };

    /// Creates a formatter style.
    pub const fn new(color: bool, width: u16, redact_sensitive: bool) -> Self {
        Self {
            color,
            width,
            redact_sensitive,
        }
    }

    /// Validates formatter style bounds.
    pub const fn validate(self) -> TerminalResult<()> {
        if self.width > MAX_FORMAT_WIDTH {
            return Err(TerminalError::InvalidFormat);
        }
        if self.width != 0 && self.width < 20 {
            return Err(TerminalError::InvalidFormat);
        }
        Ok(())
    }
}

/// Formatter descriptor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FormatDescriptor<'a> {
    /// Stable formatter name.
    pub name: &'a str,
    /// Formatter schema version.
    pub schema: &'static str,
    /// Default output format.
    pub output_format: OutputFormat,
    /// Style preferences.
    pub style: FormatStyle,
    /// Trace context for formatter creation or invocation.
    pub trace: TraceContext,
}

impl<'a> FormatDescriptor<'a> {
    /// Creates a formatter descriptor.
    pub const fn new(name: &'a str, output_format: OutputFormat) -> Self {
        Self {
            name,
            schema: FORMAT_SCHEMA_VERSION,
            output_format,
            style: FormatStyle::DEFAULT,
            trace: TraceContext::EMPTY,
        }
    }

    /// Overrides style preferences.
    pub const fn with_style(mut self, style: FormatStyle) -> Self {
        self.style = style;
        self
    }

    /// Attaches trace metadata.
    pub const fn with_trace(mut self, trace: TraceContext) -> Self {
        self.trace = trace;
        self
    }

    /// Validates formatter descriptor metadata.
    pub fn validate(self) -> TerminalResult<()> {
        validate_terminal_label(self.name, MAX_FORMAT_LABEL_LEN)
            .map_err(|_| TerminalError::InvalidFormat)?;
        if self.schema.is_empty() {
            return Err(TerminalError::InvalidFormat);
        }
        self.style.validate()?;
        self.trace.validate()
    }
}

/// Diagnostic record accepted by terminal formatters.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DiagnosticRecord<'a> {
    /// Component or command that produced the diagnostic.
    pub component: &'a str,
    /// Diagnostic message body.
    pub message: &'a str,
    /// Diagnostic severity.
    pub severity: Severity,
    /// Data class for the message.
    pub data_class: DataClass,
    /// Redaction state for the message.
    pub redaction: RedactionState,
    /// Trace context for the diagnostic.
    pub trace: TraceContext,
}

impl<'a> DiagnosticRecord<'a> {
    /// Creates an operational diagnostic record.
    pub const fn new(component: &'a str, message: &'a str, severity: Severity) -> Self {
        Self {
            component,
            message,
            severity,
            data_class: DataClass::Operational,
            redaction: RedactionState::Operational,
            trace: TraceContext::EMPTY,
        }
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

    /// Validates diagnostic metadata before display or export.
    pub fn validate(self) -> TerminalResult<()> {
        validate_terminal_label(self.component, MAX_FORMAT_LABEL_LEN)?;
        if self.message.is_empty() {
            return Err(TerminalError::MissingField);
        }
        if self.message.len() > MAX_DIAGNOSTIC_MESSAGE_LEN {
            return Err(TerminalError::FieldTooLong);
        }
        if self.data_class.requires_redaction()
            && matches!(self.redaction, RedactionState::UnredactedSensitive)
        {
            return Err(TerminalError::SensitiveOutput);
        }
        validate_redaction(self.data_class, self.redaction)?;
        self.trace.validate()
    }
}

/// Formatted output envelope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FormattedOutput<'a> {
    /// Output format.
    pub output_format: OutputFormat,
    /// Borrowed output body.
    pub body: &'a str,
    /// Data class for the output.
    pub data_class: DataClass,
    /// Redaction state for the output.
    pub redaction: RedactionState,
    /// Trace context for the output.
    pub trace: TraceContext,
}

impl<'a> FormattedOutput<'a> {
    /// Creates formatted output.
    pub const fn new(
        output_format: OutputFormat,
        body: &'a str,
        data_class: DataClass,
        redaction: RedactionState,
        trace: TraceContext,
    ) -> Self {
        Self {
            output_format,
            body,
            data_class,
            redaction,
            trace,
        }
    }

    /// Validates formatted output metadata.
    pub fn validate(self) -> TerminalResult<()> {
        if self.body.len() > MAX_DIAGNOSTIC_MESSAGE_LEN {
            return Err(TerminalError::FieldTooLong);
        }
        if self.data_class.requires_redaction()
            && matches!(self.redaction, RedactionState::UnredactedSensitive)
        {
            return Err(TerminalError::SensitiveOutput);
        }
        validate_redaction(self.data_class, self.redaction)?;
        self.trace.validate()
    }
}

/// Validates a diagnostic record and returns a borrowed formatted output view.
pub fn format_record<'a>(
    descriptor: FormatDescriptor<'a>,
    record: DiagnosticRecord<'a>,
) -> TerminalResult<FormattedOutput<'a>> {
    descriptor.validate()?;
    record.validate()?;
    if descriptor.style.redact_sensitive && record.data_class.requires_redaction() {
        validate_redaction(record.data_class, record.redaction)?;
    }
    let output = FormattedOutput::new(
        descriptor.output_format,
        record.message,
        record.data_class,
        record.redaction,
        record.trace,
    );
    output.validate()?;
    Ok(output)
}

/// Validates a command result and returns a borrowed formatted output view.
pub fn format_command_result<'a>(
    descriptor: FormatDescriptor<'a>,
    result: CommandResultRecord<'a>,
) -> TerminalResult<FormattedOutput<'a>> {
    descriptor.validate()?;
    result.validate()?;
    if descriptor.style.redact_sensitive && result.data_class.requires_redaction() {
        validate_redaction(result.data_class, result.redaction)?;
    }
    let output = FormattedOutput::new(
        descriptor.output_format,
        result.output,
        result.data_class,
        result.redaction,
        result.trace,
    );
    output.validate()?;
    Ok(output)
}
