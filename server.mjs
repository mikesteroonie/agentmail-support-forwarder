import { createHmac, createHash, timingSafeEqual } from 'node:crypto'
import { createServer } from 'node:http'
import { fileURLToPath } from 'node:url'

const MAX_BODY_BYTES = 1024 * 1024
const WEBHOOK_TOLERANCE_SECONDS = 5 * 60
const LOOP_HEADER = 'X-AgentMail-Auto-Forwarded'
const DEFAULT_AGENTMAIL_BASE_URL = 'https://api.agentmail.to/v0'
const FORWARDED_EVENT_TYPES = new Set(['message.received', 'message.received.unauthenticated'])

const requiredEnv = (name, env = process.env) => {
    const value = env[name]?.trim()
    if (!value) throw new Error(`Missing required environment variable: ${name}`)
    return value
}

export const loadConfig = (env = process.env) => ({
    agentMailApiKey: requiredEnv('AGENTMAIL_API_KEY', env),
    agentMailBaseUrl: (env.AGENTMAIL_BASE_URL || DEFAULT_AGENTMAIL_BASE_URL).replace(/\/$/, ''),
    forwardTo: requiredEnv('FORWARD_TO', env).toLowerCase(),
    sourceInbox: requiredEnv('SOURCE_INBOX', env).toLowerCase(),
    webhookSecret: requiredEnv('AGENTMAIL_WEBHOOK_SECRET', env),
})

const secretBytes = (secret) => {
    const encoded = secret.startsWith('whsec_') ? secret.slice('whsec_'.length) : secret
    const decoded = Buffer.from(encoded, 'base64')
    if (!decoded.length) throw new Error('Invalid webhook secret')
    return decoded
}

export const verifyWebhook = ({ body, headers, secret, now = Date.now() }) => {
    const id = headers['svix-id']
    const timestampHeader = headers['svix-timestamp']
    const signatureHeader = headers['svix-signature']
    if (!id || !timestampHeader || !signatureHeader) return false

    const timestamp = Number(timestampHeader)
    if (!Number.isInteger(timestamp) || Math.abs(Math.floor(now / 1000) - timestamp) > WEBHOOK_TOLERANCE_SECONDS)
        return false

    const expected = createHmac('sha256', secretBytes(secret)).update(`${id}.${timestamp}.${body}`).digest()

    return signatureHeader.split(' ').some((signature) => {
        const [version, encoded] = signature.split(',', 2)
        if (version !== 'v1' || !encoded) return false
        const actual = Buffer.from(encoded, 'base64')
        return actual.length === expected.length && timingSafeEqual(actual, expected)
    })
}

const hasLoopMarker = (headers = {}) =>
    Object.entries(headers).some(([name, value]) => name.toLowerCase() === LOOP_HEADER.toLowerCase() && Boolean(value))

const replyToFor = (message) => {
    if (Array.isArray(message.reply_to) && message.reply_to.length) return message.reply_to.filter(Boolean)
    return typeof message.from === 'string' && message.from.trim() ? [message.from] : undefined
}

export const buildForwardRequest = (message, forwardTo) => {
    const replyTo = replyToFor(message)
    return {
        to: [forwardTo],
        ...(replyTo ? { reply_to: replyTo } : {}),
        ...(typeof message.subject === 'string' ? { subject: message.subject } : {}),
        headers: {
            [LOOP_HEADER]: 'support-gmail-forward-v1',
        },
    }
}

const eventIdempotencyKey = (eventId) => `support-forward.${createHash('sha256').update(eventId).digest('hex')}`

const readBody = (request) =>
    new Promise((resolve, reject) => {
        const chunks = []
        let size = 0
        let tooLarge = false

        request.on('data', (chunk) => {
            size += chunk.length
            if (size > MAX_BODY_BYTES) {
                tooLarge = true
                return
            }
            if (!tooLarge) chunks.push(chunk)
        })
        request.on('end', () =>
            tooLarge
                ? reject(Object.assign(new Error('Request body is too large'), { statusCode: 413 }))
                : resolve(Buffer.concat(chunks).toString('utf8'))
        )
        request.on('error', reject)
    })

const respond = (response, statusCode, body = '') => {
    response.writeHead(statusCode, {
        'content-type': 'text/plain; charset=utf-8',
        'content-length': Buffer.byteLength(body),
    })
    response.end(body)
}

const isRetryableStatus = (status) => status === 408 || status === 409 || status === 429 || status >= 500

export const isRetryableForwardFailure = (status, error) =>
    isRetryableStatus(status) ||
    (status === 403 &&
        error?.code === 'message_rejected' &&
        typeof error?.message === 'string' &&
        error.message.toLowerCase().includes('sending paused'))

export const createRequestHandler =
    ({ config, fetchImpl = fetch }) =>
    async (request, response) => {
        if (request.method === 'GET' && request.url === '/healthz') {
            respond(response, 200, 'ok')
            return
        }
        if (request.method !== 'POST' || request.url !== '/webhooks/agentmail') {
            respond(response, 404, 'not found')
            return
        }

        try {
            const body = await readBody(request)
            if (!verifyWebhook({ body, headers: request.headers, secret: config.webhookSecret })) {
                respond(response, 401, 'invalid signature')
                return
            }

            let event
            try {
                event = JSON.parse(body)
            } catch {
                respond(response, 400, 'invalid json')
                return
            }

            const { event_id: eventId, event_type: eventType, message } = event
            if (!FORWARDED_EVENT_TYPES.has(eventType)) {
                console.info('Ignoring webhook event', { event_id: eventId, event_type: eventType })
                respond(response, 204)
                return
            }
            if (
                typeof eventId !== 'string' ||
                typeof message?.message_id !== 'string' ||
                typeof message?.inbox_id !== 'string'
            ) {
                respond(response, 400, 'invalid event')
                return
            }
            if (message.inbox_id.toLowerCase() !== config.sourceInbox || hasLoopMarker(message.headers)) {
                console.info('Ignoring out-of-scope message', { event_id: eventId, message_id: message.message_id })
                respond(response, 204)
                return
            }

            const url = `${config.agentMailBaseUrl}/inboxes/${encodeURIComponent(config.sourceInbox)}/messages/${encodeURIComponent(message.message_id)}/forward`
            const forwardResponse = await fetchImpl(url, {
                method: 'POST',
                headers: {
                    authorization: `Bearer ${config.agentMailApiKey}`,
                    'content-type': 'application/json',
                    'idempotency-key': eventIdempotencyKey(eventId),
                },
                body: JSON.stringify(buildForwardRequest(message, config.forwardTo)),
                signal: AbortSignal.timeout(25_000),
            })

            if (forwardResponse.ok) {
                console.info('Forwarded support email', { event_id: eventId, message_id: message.message_id })
                respond(response, 204)
                return
            }

            const forwardError = await forwardResponse.json().catch(() => undefined)
            const retryable = isRetryableForwardFailure(forwardResponse.status, forwardError)
            console.error('AgentMail forward failed', {
                event_id: eventId,
                message_id: message.message_id,
                status: forwardResponse.status,
                retryable,
            })
            respond(response, retryable ? 503 : 204)
        } catch (error) {
            const statusCode = error?.statusCode || 500
            console.error('Webhook processing failed', {
                name: error?.name,
                message: error?.message,
                status: statusCode,
            })
            if (!response.headersSent)
                respond(response, statusCode, statusCode === 500 ? 'temporary failure' : error.message)
        }
    }

export const startServer = (env = process.env) => {
    const config = loadConfig(env)
    const port = Number(env.PORT || 10000)
    const server = createServer(createRequestHandler({ config }))
    server.listen(port, '0.0.0.0', () => console.info('Support forwarder listening', { port }))
    return server
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) startServer()
