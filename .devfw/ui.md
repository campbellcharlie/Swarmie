---
artifact: ui
version: 1
status: approved
owners: []
last_updated: 2026-08-29
---

# UI

## Visual Direction

Not applicable: this slice is CLI and structured hook context only.

## Design Principles

Evidence first, compact, deterministic, and readable without a dedicated interface.

## Layout System

Hook context uses one short block per signal with stable field ordering.

## Typography

Inherited monospace terminal rendering; no custom typography.

## Color and Surfaces

No color dependency; verified/inferred/unknown state is expressed in text.

## Motion

Not applicable.

## Responsive Behavior

Output is bounded by signal count and per-field limits to fit varying context windows.

## Accessibility Constraints

All meaning must survive plain-text rendering and screen-reader traversal.

## Open Questions

A visual inbox is outside this slice.
