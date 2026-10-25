# tiny-credential-gateway

A tiny TypeScript credential gateway for sandboxed agents.

- The sandbox holds only a short-lived, signed session token.
- The gateway verifies the session, checks the agent's egress policy, strips any auth header the agent set, and injects the real credential from a vault outside the sandbox.
- The backend only trusts the real key. Every call is audited.

Small model of the "zero-secrets" idea in Google's [Agent Compute Engine](https://cloud.google.com/blog/topics/ai-infrastructure/agent-compute-engine-deep-dive), not its implementation. Fake services, fake keys. No API key. No network.

```bash
npm install
npx tsx gateway.ts
```

MIT, by Bobby Hall Jr.

Read the write-up on Dev.to: https://dev.to/bobbyhalljr/google-built-a-sandbox-with-nothing-to-steal-lets-build-a-tiny-credential-gateway-in-typescript-6ja
