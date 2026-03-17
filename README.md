# Fuffa
 

### Play with EBPF

----

How to run:

```
make
```

Tests:

```
make test
```

Tests in docker:

```
make test-in-docker
```

### Release notes

Publishing a GitHub release triggers automatic release notes from merged PRs:

- **Labels** → sections: `bug` → **Bug Fix**, `enhancement` → **Enhancement**, `document` → **Document**
- PRs with a **milestone** show it in the note
- See [.github/workflows/release-notes.yml](.github/workflows/release-notes.yml) and [.github/scripts/generate-release-notes.sh](.github/scripts/generate-release-notes.sh)

