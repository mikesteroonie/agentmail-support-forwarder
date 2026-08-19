import { createHmac } from 'node:crypto'
import test from 'node:test'
import assert from 'node:assert/strict'

import { buildForwardRequest, isRetryableForwardFailure, loadConfig, verifyWebhook } from './server.mjs'

const encodedSecret = Buffer.from('test signing secret').toString('base64')
const secret = `whsec_${encodedSecret}`

const signedHeaders = (body, timestamp) => ({
    'svix-id': 'msg_test',
    'svix-timestamp': String(timestamp),
    'svix-signature': `v1,${createHmac('sha256', Buffer.from(encodedSecret, 'base64'))
        .update(`msg_test.${timestamp}.${body}`)
        .digest('base64')}`,
})

test('verifyWebhook accepts a current valid Svix signature', () => {
    const now = Date.now()
    const timestamp = Math.floor(now / 1000)
    const body = JSON.stringify({ event_type: 'message.received' })

    assert.equal(verifyWebhook({ body, headers: signedHeaders(body, timestamp), secret, now }), true)
})

test('verifyWebhook rejects a bad or stale signature', () => {
    const now = Date.now()
    const timestamp = Math.floor(now / 1000)
    const body = '{}'

    assert.equal(
        verifyWebhook({
            body,
            headers: { ...signedHeaders(body, timestamp), 'svix-signature': 'v1,bad' },
            secret,
            now,
        }),
        false
    )
    assert.equal(verifyWebhook({ body, headers: signedHeaders(body, timestamp - 301), secret, now }), false)
})

test('buildForwardRequest preserves the original Reply-To and adds a loop marker', () => {
    assert.deepEqual(
        buildForwardRequest(
            {
                from: 'Sender <sender@example.com>',
                reply_to: ['reply@example.com'],
                subject: 'Need help',
            },
            'support@agentmail.cc'
        ),
        {
            to: ['support@agentmail.cc'],
            reply_to: ['reply@example.com'],
            subject: 'Need help',
            headers: { 'X-AgentMail-Auto-Forwarded': 'support-gmail-forward-v1' },
        }
    )
})

test('loadConfig normalizes inboxes and removes a trailing base URL slash', () => {
    assert.deepEqual(
        loadConfig({
            AGENTMAIL_API_KEY: 'key',
            AGENTMAIL_BASE_URL: 'https://api.agentmail.to/v0/',
            AGENTMAIL_WEBHOOK_SECRET: secret,
            FORWARD_TO: 'Support@AgentMail.cc',
            SOURCE_INBOX: 'Support@AgentMail.to',
        }),
        {
            agentMailApiKey: 'key',
            agentMailBaseUrl: 'https://api.agentmail.to/v0',
            forwardTo: 'support@agentmail.cc',
            sourceInbox: 'support@agentmail.to',
            webhookSecret: secret,
        }
    )
})

test('sending-paused rejections remain retryable', () => {
    assert.equal(
        isRetryableForwardFailure(403, {
            code: 'message_rejected',
            message: 'Message rejected: Sending paused for this account.',
        }),
        true
    )
    assert.equal(isRetryableForwardFailure(403, { code: 'forbidden', message: 'Forbidden' }), false)
    assert.equal(isRetryableForwardFailure(429, undefined), true)
})
