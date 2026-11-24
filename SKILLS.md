# Ink Project Reference

Ink is an append-only database project implemented in Rust. The workspace uses Cargo and contains storage, query, protocol, client, server, and desktop application packages.

## Project Metadata

- Edition: Rust 2021
- License: MIT OR Apache-2.0
- Desktop framework: eframe and egui
- Query language: Ink Query Language (IQL)
- Wire protocol: Ink Wire Protocol (IWP)

The architecture and component relationships are described in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md). Binary storage, query syntax, network messages, and security boundaries are documented in [docs/FORMAT.md](docs/FORMAT.md), [docs/QUERY_LANGUAGE.md](docs/QUERY_LANGUAGE.md), [docs/PROTOCOL.md](docs/PROTOCOL.md), and [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md). A step-by-step introduction is available in [docs/GETTING_STARTED.md](docs/GETTING_STARTED.md).
