use alani_terminal::*;

#[test]
fn repository_catalog_is_stable() {
    let catalog = terminal_catalog();
    assert_eq!(repository_name(), "alani-terminal");
    assert_eq!(module_names(), ["commands", "parser", "session", "format"]);
    assert_eq!(catalog.commands_schema, COMMANDS_SCHEMA_VERSION);
    assert!(catalog.validate().is_ok());
    assert_eq!(component_info().status, ComponentStatus::Experimental);
}

#[test]
fn parser_accepts_safe_tokens_and_rejects_sensitive_literals() {
    let parser = ParserDescriptor::new("host-parser");
    let parsed = parse_command::<8>(
        parser,
        "inspect runtime --verbose level=info",
        ParsePolicy::DEFAULT,
    )
    .unwrap();

    assert_eq!(parsed.command, "inspect");
    assert_eq!(parsed.len(), 4);
    assert_eq!(parsed.token(2).unwrap().kind, TokenKind::Flag);
    assert_eq!(parsed.token(3).unwrap().kind, TokenKind::Assignment);
    assert!(!parsed.has_sensitive_literal);

    let err = parse_command::<8>(parser, "inspect token=secret", ParsePolicy::DEFAULT).unwrap_err();
    assert_eq!(err, TerminalError::SensitiveInput);

    let err = parse_command::<1>(parser, "inspect runtime", ParsePolicy::DEFAULT).unwrap_err();
    assert_eq!(err, TerminalError::CapacityExceeded);

    let script = parse_script::<4, 8>(
        parser,
        "# safe demo\ninspect runtime\ntrace.show --last=5\n",
        ParsePolicy::DEFAULT,
    )
    .unwrap();
    assert_eq!(script.len(), 2);
    assert!(script.command_at(0).unwrap().command_is("inspect"));
    assert_eq!(script.command_at(1).unwrap().argument_count(), 1);
}

#[test]
fn command_registry_authorizes_and_fails_closed() {
    let trace = TraceContext::root(1, 10);
    let inspect = CommandDescriptor::new("inspect", CommandKind::Inspect, TerminalRights::READ)
        .with_trace(trace);
    let restart = CommandDescriptor::new(
        "service.restart",
        CommandKind::ServiceControl,
        TerminalRights::SERVICE_CONTROL,
    )
    .with_audit()
    .with_trace(trace);

    let mut registry: CommandRegistry<4> = CommandRegistry::new();
    registry.register(inspect).unwrap();
    assert_eq!(
        registry.register(inspect).unwrap_err(),
        TerminalError::Duplicate
    );
    registry.register(restart).unwrap();
    registry.register_builtin(BuiltinCommand::Echo).unwrap();

    let args = [CommandArgument::positional("runtime")];
    let request = CommandRequest::new(inspect, &args, "inspect runtime", 7, trace);
    let context = CommandContext::new(7, TerminalRights::READ, trace);
    let result = registry.execute_declared(context, request).unwrap();
    assert_eq!(result.status, CommandStatus::Completed);
    assert_eq!(result.command, "inspect");

    let request = CommandRequest::new(restart, &[], "service.restart runtime", 7, trace);
    let context = CommandContext::new(7, TerminalRights::SERVICE_CONTROL, trace);
    assert_eq!(
        registry.execute_declared(context, request).unwrap_err(),
        TerminalError::AuditRequired
    );

    assert_eq!(
        registry.find("missing").unwrap_err(),
        TerminalError::UnknownCommand
    );

    let echo = registry.find("echo").unwrap();
    assert_eq!(echo.kind.label(), "echo");
    assert_eq!(CommandStatus::Completed.label(), "completed");
}

#[test]
fn sessions_record_lifecycle_and_reject_closed_commands() {
    let trace = TraceContext::root(2, 20);
    let principal = TerminalPrincipal::new(PrincipalKind::Test, "tester@host");
    let rights = TerminalRights::READ
        .union(TerminalRights::EXECUTE)
        .union(TerminalRights::AUDIT);
    let descriptor = SessionDescriptor::new("operator", SessionMode::Operator, principal, rights)
        .with_audit_required()
        .with_trace(trace);
    let mut session: TerminalSession<4> = TerminalSession::new(42, descriptor).unwrap();

    session.open(trace).unwrap();
    session
        .record_command("inspect", true, false, trace)
        .unwrap();
    session.close(trace).unwrap();

    assert_eq!(session.state, SessionState::Closed);
    assert_eq!(session.event_count(), 3);
    assert_eq!(
        session
            .record_command("inspect", true, false, trace)
            .unwrap_err(),
        TerminalError::SessionClosed
    );
}

#[test]
fn locked_sessions_require_authorized_unlock_before_command_context() {
    let trace = TraceContext::root(4, 40);
    let principal = TerminalPrincipal::new(PrincipalKind::Human, "operator:local");
    let rights = TerminalRights::EXECUTE.union(TerminalRights::AUDIT);
    let descriptor =
        SessionDescriptor::new("interactive", SessionMode::Operator, principal, rights)
            .with_audit_required();
    let mut session: TerminalSession<6> = TerminalSession::new(9, descriptor).unwrap();

    session.open(trace).unwrap();
    session.lock(trace.child(41)).unwrap();
    assert_eq!(
        session.command_context(trace.child(42)).unwrap_err(),
        TerminalError::InvalidState
    );
    assert_eq!(
        session
            .unlock(TerminalRights::EXECUTE, trace.child(43))
            .unwrap_err(),
        TerminalError::AuditRequired
    );
    session.unlock(rights, trace.child(44)).unwrap();
    let context = session.command_context(trace.child(45)).unwrap();
    assert!(context.audit_ready);
    assert_eq!(session.state, SessionState::Active);
}

#[test]
fn formatter_preserves_classification_and_blocks_unredacted_sensitive_output() {
    let trace = TraceContext::root(3, 30);
    let formatter = FormatDescriptor::new("diagnostic", OutputFormat::Diagnostic).with_trace(trace);
    let record = DiagnosticRecord::new("terminal", "ready", Severity::Info).with_trace(trace);
    let output = format_record(formatter, record).unwrap();

    assert_eq!(output.output_format, OutputFormat::Diagnostic);
    assert_eq!(output.body, "ready");
    assert_eq!(output.data_class, DataClass::Operational);

    let sensitive = DiagnosticRecord::new("terminal", "token=secret", Severity::Error)
        .with_data(DataClass::Sensitive, RedactionState::UnredactedSensitive)
        .with_trace(trace);
    assert_eq!(
        format_record(formatter, sensitive).unwrap_err(),
        TerminalError::SensitiveOutput
    );

    let redacted = sensitive.with_data(DataClass::Sensitive, RedactionState::SensitiveRedacted);
    assert!(format_record(formatter, redacted).is_ok());

    let result = CommandResultRecord::new(
        "echo",
        CommandStatus::Completed,
        "ready",
        DataClass::Public,
        RedactionState::Public,
        trace,
    );
    let formatted = format_command_result(formatter, result).unwrap();
    assert_eq!(formatted.body, "ready");
    assert!(result.is_success());
}

#[test]
fn reserved_bits_and_invalid_traces_are_rejected() {
    assert_eq!(
        TerminalRights::from_bits(1 << 63).unwrap_err(),
        TerminalError::ReservedBits
    );

    let invalid_trace = TraceContext {
        trace_id: 0,
        span_id: 99,
        parent_span_id: 0,
        flags: 0,
    };
    assert_eq!(
        invalid_trace.validate().unwrap_err(),
        TerminalError::InvalidTrace
    );
}
