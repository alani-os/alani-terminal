//! Shell input parser boundary.
//!
//! The parser intentionally supports a conservative token model for MVK
//! host-mode tests. It rejects shell control operators and sensitive literals
//! unless the caller explicitly opts into handling them.

use crate::{
    validate_terminal_label, TerminalError, TerminalResult, TraceContext, MAX_COMMAND_NAME_LEN,
};

/// Parser descriptor schema version.
pub const PARSER_SCHEMA_VERSION: &str = "alani-terminal.parser.v1";
/// Maximum accepted raw input length.
pub const MAX_INPUT_LEN: usize = 4096;
/// Maximum accepted token length.
pub const MAX_TOKEN_LEN: usize = 256;
/// Default token capacity for parser examples and tests.
pub const MAX_TOKENS: usize = 64;
/// Default maximum script lines accepted by host-mode planning helpers.
pub const MAX_SCRIPT_LINES: usize = 64;

/// Parsed token kind.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TokenKind {
    /// First token naming the command.
    Command,
    /// Positional argument token.
    Argument,
    /// Flag token beginning with `--`.
    Flag,
    /// Assignment token containing `=`.
    Assignment,
    /// Single-token quoted literal.
    Quoted,
    /// Comment marker accepted by policy.
    Comment,
}

/// Borrowed parser token.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Token<'a> {
    /// Token text borrowed from the input line.
    pub text: &'a str,
    /// Token classification.
    pub kind: TokenKind,
    /// Zero-based token index.
    pub index: usize,
}

impl<'a> Token<'a> {
    /// Creates a parser token.
    pub const fn new(text: &'a str, kind: TokenKind, index: usize) -> Self {
        Self { text, kind, index }
    }

    /// Validates token bounds.
    pub fn validate(self) -> TerminalResult<()> {
        if self.text.is_empty() {
            return Err(TerminalError::MissingField);
        }
        if self.text.len() > MAX_TOKEN_LEN {
            return Err(TerminalError::FieldTooLong);
        }
        Ok(())
    }
}

/// Parser policy controlling optional shell features.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParsePolicy {
    /// Whether `#` comment markers are accepted.
    pub allow_comments: bool,
    /// Whether single-token quoted literals are accepted.
    pub allow_quoted: bool,
    /// Whether sensitive literals may remain in parsed tokens.
    pub allow_sensitive_literals: bool,
    /// Maximum token count.
    pub max_tokens: usize,
    /// Maximum raw input length.
    pub max_input_len: usize,
}

impl ParsePolicy {
    /// Conservative default parser policy.
    pub const DEFAULT: Self = Self {
        allow_comments: true,
        allow_quoted: true,
        allow_sensitive_literals: false,
        max_tokens: MAX_TOKENS,
        max_input_len: MAX_INPUT_LEN,
    };

    /// Creates a parser policy.
    pub const fn new(max_tokens: usize, max_input_len: usize) -> Self {
        Self {
            allow_comments: true,
            allow_quoted: true,
            allow_sensitive_literals: false,
            max_tokens,
            max_input_len,
        }
    }

    /// Allows sensitive literals to be parsed by an explicitly trusted caller.
    pub const fn with_sensitive_literals(mut self) -> Self {
        self.allow_sensitive_literals = true;
        self
    }

    /// Validates parser policy bounds.
    pub const fn validate(self) -> TerminalResult<()> {
        if self.max_tokens == 0 || self.max_input_len == 0 {
            return Err(TerminalError::InvalidParser);
        }
        if self.max_tokens > MAX_TOKENS || self.max_input_len > MAX_INPUT_LEN {
            return Err(TerminalError::FieldTooLong);
        }
        Ok(())
    }
}

/// Parser descriptor for host-mode parser instances.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParserDescriptor<'a> {
    /// Stable parser name.
    pub name: &'a str,
    /// Parser schema version.
    pub schema: &'static str,
    /// Parser policy.
    pub policy: ParsePolicy,
    /// Trace context for parser creation or invocation.
    pub trace: TraceContext,
}

impl<'a> ParserDescriptor<'a> {
    /// Creates a parser descriptor with the default policy.
    pub const fn new(name: &'a str) -> Self {
        Self {
            name,
            schema: PARSER_SCHEMA_VERSION,
            policy: ParsePolicy::DEFAULT,
            trace: TraceContext::EMPTY,
        }
    }

    /// Overrides parser policy.
    pub const fn with_policy(mut self, policy: ParsePolicy) -> Self {
        self.policy = policy;
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
            .map_err(|_| TerminalError::InvalidParser)?;
        if self.schema.is_empty() {
            return Err(TerminalError::InvalidParser);
        }
        self.policy.validate()?;
        self.trace.validate()
    }
}

/// Parsed command with fixed-capacity token storage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParsedCommand<'a, const N: usize> {
    /// Raw input line after outer whitespace trimming.
    pub raw: &'a str,
    /// Parsed command name.
    pub command: &'a str,
    tokens: [Option<Token<'a>>; N],
    len: usize,
    /// Whether the parser observed a sensitive literal.
    pub has_sensitive_literal: bool,
    /// Trace context attached to parsing.
    pub trace: TraceContext,
}

impl<'a, const N: usize> ParsedCommand<'a, N> {
    /// Creates an empty parsed command container.
    pub const fn empty(trace: TraceContext) -> Self {
        Self {
            raw: "",
            command: "",
            tokens: [None; N],
            len: 0,
            has_sensitive_literal: false,
            trace,
        }
    }

    /// Returns the number of parsed tokens.
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Returns `true` when no tokens were parsed.
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Returns a parsed token by index.
    pub fn token(&self, index: usize) -> Option<Token<'a>> {
        if index >= self.len {
            None
        } else {
            self.tokens[index]
        }
    }

    /// Returns the number of argument-like tokens excluding the command token.
    pub const fn argument_count(&self) -> usize {
        self.len.saturating_sub(1)
    }

    /// Returns `true` when the command token matches the supplied name.
    pub fn command_is(&self, name: &str) -> bool {
        self.command == name
    }

    fn push(&mut self, token: Token<'a>) -> TerminalResult<()> {
        if self.len >= N {
            return Err(TerminalError::CapacityExceeded);
        }
        self.tokens[self.len] = Some(token);
        self.len += 1;
        Ok(())
    }
}

/// Fixed-capacity parsed script plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScriptPlan<'a, const L: usize, const T: usize> {
    /// Parser descriptor used to build the plan.
    pub descriptor: ParserDescriptor<'a>,
    lines: [Option<ParsedCommand<'a, T>>; L],
    len: usize,
    /// Whether any parsed line contained a sensitive literal.
    pub has_sensitive_literal: bool,
    /// Trace context attached to the plan.
    pub trace: TraceContext,
}

impl<'a, const L: usize, const T: usize> ScriptPlan<'a, L, T> {
    /// Creates an empty script plan.
    pub const fn new(descriptor: ParserDescriptor<'a>) -> Self {
        Self {
            descriptor,
            lines: [None; L],
            len: 0,
            has_sensitive_literal: false,
            trace: descriptor.trace,
        }
    }

    /// Returns the number of parsed command lines.
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Returns `true` when no command lines were parsed.
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Returns a parsed command by script index.
    pub fn command_at(&self, index: usize) -> Option<ParsedCommand<'a, T>> {
        if index >= self.len {
            None
        } else {
            self.lines[index]
        }
    }

    fn push(&mut self, command: ParsedCommand<'a, T>) -> TerminalResult<()> {
        if self.len >= L {
            return Err(TerminalError::CapacityExceeded);
        }
        if command.has_sensitive_literal {
            self.has_sensitive_literal = true;
        }
        self.lines[self.len] = Some(command);
        self.len += 1;
        Ok(())
    }
}

/// Parses a terminal command line into fixed-capacity borrowed tokens.
pub fn parse_command<'a, const N: usize>(
    descriptor: ParserDescriptor<'a>,
    input: &'a str,
    policy: ParsePolicy,
) -> TerminalResult<ParsedCommand<'a, N>> {
    descriptor.validate()?;
    policy.validate()?;
    if input.len() > policy.max_input_len {
        return Err(TerminalError::FieldTooLong);
    }

    let line = input.trim();
    if line.is_empty() {
        return Err(TerminalError::MissingField);
    }

    let mut parsed = ParsedCommand::empty(descriptor.trace);
    parsed.raw = line;

    for word in line.split_whitespace() {
        if word.starts_with('#') {
            if policy.allow_comments {
                break;
            }
            return Err(TerminalError::ParseError);
        }
        if word.len() > MAX_TOKEN_LEN {
            return Err(TerminalError::FieldTooLong);
        }
        if parsed.len >= policy.max_tokens {
            return Err(TerminalError::CapacityExceeded);
        }
        if contains_shell_control(word) {
            return Err(TerminalError::ParseError);
        }

        let quoted = is_quoted_token(word)?;
        if quoted && !policy.allow_quoted {
            return Err(TerminalError::ParseError);
        }

        let sensitive = contains_sensitive_literal(word);
        if sensitive {
            parsed.has_sensitive_literal = true;
            if !policy.allow_sensitive_literals {
                return Err(TerminalError::SensitiveInput);
            }
        }

        let kind = classify_token(word, parsed.len, quoted);
        if kind == TokenKind::Command {
            validate_terminal_label(word, MAX_COMMAND_NAME_LEN)
                .map_err(|_| TerminalError::InvalidCommand)?;
            parsed.command = word;
        }
        parsed.push(Token::new(word, kind, parsed.len))?;
    }

    if parsed.command.is_empty() {
        return Err(TerminalError::MissingField);
    }
    Ok(parsed)
}

/// Parses a multi-line terminal script into a fixed-capacity plan.
pub fn parse_script<'a, const L: usize, const T: usize>(
    descriptor: ParserDescriptor<'a>,
    script: &'a str,
    policy: ParsePolicy,
) -> TerminalResult<ScriptPlan<'a, L, T>> {
    descriptor.validate()?;
    policy.validate()?;
    if script.len() > policy.max_input_len {
        return Err(TerminalError::FieldTooLong);
    }

    let mut plan = ScriptPlan::new(descriptor);
    for line in script.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.starts_with('#') {
            if policy.allow_comments {
                continue;
            }
            return Err(TerminalError::ParseError);
        }
        let parsed = parse_command::<T>(descriptor, trimmed, policy)?;
        plan.push(parsed)?;
    }
    if plan.is_empty() {
        return Err(TerminalError::MissingField);
    }
    Ok(plan)
}

/// Returns `true` when a token contains a sensitive literal marker.
pub fn contains_sensitive_literal(token: &str) -> bool {
    token.contains("password=")
        || token.contains("secret=")
        || token.contains("token=")
        || token.contains("credential=")
        || token.contains("key=")
        || token.contains("--password")
        || token.contains("--secret")
        || token.contains("--token")
}

fn classify_token(token: &str, index: usize, quoted: bool) -> TokenKind {
    if index == 0 {
        TokenKind::Command
    } else if quoted {
        TokenKind::Quoted
    } else if token.starts_with("--") {
        TokenKind::Flag
    } else if token.contains('=') {
        TokenKind::Assignment
    } else {
        TokenKind::Argument
    }
}

fn contains_shell_control(token: &str) -> bool {
    token
        .bytes()
        .any(|byte| matches!(byte, b';' | b'|' | b'&' | b'<' | b'>' | b'`'))
}

fn is_quoted_token(token: &str) -> TerminalResult<bool> {
    let starts_double = token.starts_with('"');
    let ends_double = token.ends_with('"');
    let starts_single = token.starts_with('\'');
    let ends_single = token.ends_with('\'');
    if starts_double || ends_double || starts_single || ends_single {
        if (starts_double && ends_double && !starts_single && !ends_single)
            || (starts_single && ends_single && !starts_double && !ends_double)
        {
            Ok(true)
        } else {
            Err(TerminalError::ParseError)
        }
    } else if token.contains('"') || token.contains('\'') {
        Err(TerminalError::ParseError)
    } else {
        Ok(false)
    }
}
