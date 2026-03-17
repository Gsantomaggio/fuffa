# Agent instructions – Fuffa

This repo is **Fuffa**: a small Go project that experiments with eBPF and XDP (eXtensible Data Path).

## Project overview

- **Language**: Go
- **Domain**: eBPF, XDP, kernel networking
- **Layout**: `main.go` loads an XDP program; `pkg/xdp-ebpf/` holds the loader; `kernel_ebpf/` has the C eBPF code
- **Build**: `make` (see [Makefile](Makefile)); tests: `make test`, `make test-in-docker`
- **Releases**: GitHub releases use [.github/workflows/release-notes.yml](.github/workflows/release-notes.yml) and [.github/scripts/generate-release-notes.sh](.github/scripts/generate-release-notes.sh)

## Model-specific instructions

Use the file that matches the model you’re running in:

| Model   | File        | Purpose                          |
|--------|-------------|-----------------------------------|
| Claude | [CLAUDE.md](CLAUDE.md) | Instructions and conventions for Claude |
| Gemini | [GEMINI.md](GEMINI.md) | Instructions and conventions for Gemini |

If your environment doesn’t use one of these, follow [README.md](README.md) and this file as the main references.
