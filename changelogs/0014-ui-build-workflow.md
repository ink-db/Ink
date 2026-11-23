# 0014 — Plain Application Labels and Independent Package Builds

**Date:** 2026-11-23  
**Area:** Maintenance / CI

## Summary

Removed decorative emoji and checkmark characters from Ink Browser, the CLI, and the client shell. Added separate GitHub Actions build jobs for each workspace package and a Windows Ink Browser build.

## Main components

- `.github/workflows/build.yml`.
- Plain-text UI labels and operation status output.
- Linux desktop libraries for the Ink Browser build job.

## Verification record

The source search found no emoji or checkmark characters in Rust application files. The workflow build was not run locally.
