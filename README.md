# toolgate

**A security auditor for MCP servers.** An MCP server is third-party code with
access to your data that injects text straight into a model's context — and
almost nobody reviews them. `toolgate` audits three things:

- **What the code can do** — a capability inventory from the package's AST,
  read straight from the npm tarball, without installing anything.
- **What the model will actually receive** — the tool names, descriptions and
  schemas the server declares, checked for hidden characters and injected
  instructions.
- **Whether any of it changed** — a pinned fingerprint, so a *rug pull* (a
  server that quietly rewrites its tool descriptions after you trusted it)
  becomes an alert instead of a silence.

## Status

**Early — under construction.**

## What it does not do

Two limits stated up front, because they change how much you should trust it:

- **It does not beat an adaptive adversary.** A server is code, and it can tell
  it is being audited rather than used. It can serve benign tools to `toolgate`
  and poisoned ones to your real client. `toolgate` catches careless attacks and
  it catches *changes*; it does not catch a server that is waiting for you.
- **It does not see tool *outputs*.** The most common injection today arrives in
  what a tool *returns* (a "fetch this page" tool relaying attacker text), not in
  its description. That only exists at runtime.

Both are the job of a proxy that sits in the live request path, which is a later
deliverable. What holds regardless of any of this is the **pinning** and the
**deterministic signals** — they do not depend on detecting intent.

## License

Dual-licensed under either of [MIT](LICENSE-MIT) or
[Apache-2.0](LICENSE-APACHE), at your option.
