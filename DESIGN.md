---
version: alpha
name: Auditex
description: Plain operator reporting system with minimal HTML styling, clean tabular hierarchy, and severity-first readability for audits and evidence packs.
colors:
  background: "#FFFFFF"
  background-alt: "#F6F6F6"
  surface: "#FFFFFF"
  surface-alt: "#F8FAFC"
  primary: "#0F172A"
  secondary: "#475569"
  tertiary: "#CBD5E1"
  text: "#0F172A"
  text-muted: "#475569"
  success: "#166534"
  warning: "#92400E"
  danger: "#B91C1C"
typography:
  display-lg:
    fontFamily: "system-ui, sans-serif"
    fontSize: "28px"
    fontWeight: 700
    lineHeight: "34px"
    letterSpacing: "0em"
  headline-md:
    fontFamily: "system-ui, sans-serif"
    fontSize: "18px"
    fontWeight: 700
    lineHeight: "24px"
    letterSpacing: "0em"
  body-md:
    fontFamily: "system-ui, sans-serif"
    fontSize: "14px"
    fontWeight: 400
    lineHeight: "20px"
    letterSpacing: "0em"
  label-sm:
    fontFamily: "system-ui, sans-serif"
    fontSize: "12px"
    fontWeight: 600
    lineHeight: "16px"
    letterSpacing: "0.04em"
  mono-sm:
    fontFamily: "ui-monospace, monospace"
    fontSize: "12px"
    fontWeight: 400
    lineHeight: "16px"
    letterSpacing: "0em"
rounded:
  sm: "8px"
  md: "12px"
  lg: "16px"
  xl: "20px"
  full: "999px"
spacing:
  xs: "4px"
  sm: "8px"
  md: "12px"
  lg: "16px"
  xl: "24px"
  xxl: "32px"
components:
  report-shell:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.text}"
    typography: "{typography.body-md}"
    rounded: "{rounded.lg}"
    padding: "{spacing.xl}"
  table:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.text}"
    typography: "{typography.body-md}"
    rounded: "{rounded.sm}"
    padding: "{spacing.sm}"
  section-card:
    backgroundColor: "{colors.surface-alt}"
    textColor: "{colors.text}"
    typography: "{typography.body-md}"
    rounded: "{rounded.md}"
    padding: "{spacing.lg}"
  severity-pill:
    backgroundColor: "{colors.background-alt}"
    textColor: "{colors.danger}"
    typography: "{typography.label-sm}"
    rounded: "{rounded.full}"
    padding: "{spacing.sm}"
---

## Overview
Auditex is an operator tool and report renderer, not a branded product shell. It should feel plain, rigorous, and easy to print, paste, diff, and review under time pressure.

## Colors
The system is neutral and quiet. Dark text on white remains the default. Severity color should appear only where it helps triage findings and blockers.

## Typography
Use plain system UI text with simple weight changes for hierarchy. Tables, evidence fragments, and machine-like values can use monospaced text when precision matters.

## Layout
Reports should be vertically structured, sectioned clearly, and highly scannable. Tables and key-value blocks matter more than decorative layout.

## Elevation & Depth
Depth is intentionally minimal. Light borders, quiet section backgrounds, and spacing do the hierarchy work instead of visual effects.

## Shapes
Rounded corners may be used sparingly for report shells or grouped sections, but the system should remain closer to document layout than app chrome.

## Components
The important pieces are report shells, findings tables, summary blocks, action lists, blocker sections, and export-friendly key-value rows.

## Do's and Don'ts
- Do optimize for audit clarity and evidence review speed.
- Do keep severity styling obvious but restrained.
- Don't invent a fake dashboard around CLI and report output.
- Don't rely on visual flourish where structure should do the work.
