# Production readiness

Status: **working-lab**. The native app can proxy a configurable origin, enforce Coraza/CRS rules, persist local events, produce explained incidents, apply lab-scoped temporary deception, and display real event data. Production use has not been reviewed or approved.

Before any external customer deployment, complete and verify:

- TLS termination, certificate and upstream validation, network firewall design, origin bypass prevention, and a supported service supervisor.
- User authentication, authorization roles, CSRF protection, session security, admin audit review, and secret rotation. The current management UI is a local single-operator tool.
- Durable telemetry buffering and recovery. The gateway currently uses a bounded in-memory queue; SQLite is a local single-file persistence layer.
- SQLite backup/restore procedures or an explicitly configured production database, retention/deletion controls, encryption at rest, and privacy review.
- Multi-site and tenant isolation, per-site quotas, event retention, and policy isolation under concurrent load.
- Load, soak, restart, and fault-injection exercises; alert delivery and operational SLOs.
- Site-specific CRS tuning, false-positive measurement on representative traffic, independent penetration testing, and security review.
- Repair execution in a strongly isolated runner before processing any untrusted repository; reviewed coding-model credentials; policy and deployment approvals; rollback drills.
- Jev and local-model reliability, privacy and evaluation review using representative site incidents. Model outputs remain advisory.
- Dependency, secret, and software-supply-chain scans, release signing, on-call procedures, and legal/privacy review.

Until these gates are completed by the responsible engineering and security teams, keep CounterFlow on a controlled lab or staging site and do not describe it as production-ready.
