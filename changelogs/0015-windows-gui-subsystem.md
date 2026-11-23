# 0015 — Windows Desktop Application Subsystem

**Date:** 2026-11-23  
**Area:** Desktop

## Summary

Configured the Windows `ink-browser` executable to use the GUI subsystem, preventing a separate terminal window from appearing when the desktop application is launched. The `ink` command-line executable retains its console behavior.

## Main component

- `ink-browser/src/main.rs`.

## Verification record

The Windows application build is represented by a separate GitHub Actions job. No local Windows build was run.
