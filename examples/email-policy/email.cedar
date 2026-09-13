@id("discover-mail")
@layer("baseline")
@description("Mail assistants can discover the email service.")
permit (
    principal in Group::"mail-assistants",
    action in [Action::"ListTools", Action::"SearchTools"],
    resource == Server::"example-messages"
);

@id("send-email")
@layer("baseline")
@description("The assistant may send email on your behalf.")
permit (
    principal in Group::"mail-assistants",
    action == Action::"CallTool",
    resource == Tool::"example-messages.send"
);

@id("require-explicit-recipients")
@layer("service-grants")
@description("Every recipient must be an explicit, unambiguous email address.")
@reason("Provide bare email addresses in To, Cc, and Bcc.")
forbid (
    principal,
    action == Action::"CallTool",
    resource == Tool::"example-messages.send"
) when { !context.discovery && !context.email_recipients.valid };

@id("approve-external-email")
@layer("service-grants")
@description("Email colleagues freely. Ask before sending outside the company.")
@reason("An external recipient requires approval for this exact message.")
forbid (
    principal,
    action == Action::"CallTool",
    resource == Tool::"example-messages.send"
) when {
    !context.discovery
    && !["example.com"].containsAll(context.email_recipients.domains)
    && !context.approval_present
};
