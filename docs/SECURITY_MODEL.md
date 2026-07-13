# Security Model

Packsight treats every supplied repository, archive, manifest, ABI, IDL, and source file as hostile.

## Required Production Controls

- Run analyzers in disposable containers.
- Do not mount the host Docker socket into analyzer containers.
- Disable privileged mode.
- Use read-only root filesystems where possible.
- Enforce CPU, memory, process-count, output-size, and wall-clock limits.
- Block internal network ranges and restrict outbound network access.
- Reject archives with path traversal or symlink escapes.
- Limit decompressed archive size.
- Never execute install, build, postinstall, or arbitrary project scripts.
- Prefer lockfile parsing over dependency installation.
- Redact RPC keys and provider credentials from logs.
- Validate chain addresses before enqueueing work.
- Rate-limit public scan submission.

## Current MVP Posture

The MVP implements parser-based source and manifest analysis and does not execute scanned project code. The API can run local scans for development, but production deployments should route scans through isolated workers before accepting uploaded archives.
