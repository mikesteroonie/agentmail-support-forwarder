# Support email forwarder

Receives signed AgentMail `message.received` and `message.received.unauthenticated` webhooks for `support@agentmail.to` and forwards the original message, including attachments, to `support@agentmail.cc` through AgentMail's forward API. Spam and blocked events are intentionally not subscribed.

## Environment

- `AGENTMAIL_API_KEY`: inbox-scoped key with `message_send` permission
- `AGENTMAIL_WEBHOOK_SECRET`: signing secret returned when the webhook is created
- `SOURCE_INBOX`: `support@agentmail.to`
- `FORWARD_TO`: `support@agentmail.cc`
- `AGENTMAIL_BASE_URL`: optional; defaults to `https://api.agentmail.to/v0`

The webhook URL is `POST /webhooks/agentmail`; the health check is `GET /healthz`.
