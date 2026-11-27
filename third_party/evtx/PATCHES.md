# Changes to velocidex/evtx v0.2.0

This is a copy of `www.velocidex.com/golang/evtx` v0.2.0 (Apache-2.0, see `LICENSE`), used through a `replace` in Atropos's `go.mod`. Only the package's source files are kept (not its command, test fixtures or documentation). Every change is in `evtx.go` and marked with a comment beginning `Atropos:`.

The library trusts counts in the binary XML of each record. A damaged or crafted record could make it allocate without bound, which Go cannot recover from: an old record in a public event log asked for 35 to 43 GB and stopped the process. The changes:

1. **The number of template arguments** must fit in the bytes left (four bytes per argument descriptor); otherwise the template instance is refused (`ParseTemplateInstance`).
2. **A work budget per record** (`maxWork`, 262,144): one unit per binary XML token read and per template node expanded, shared by every copy of the parse context. A template that uses itself doubles what is expanded at each use; the budget stops it. When the budget runs out, decoding stops and `EventRecord.Truncated` is set, which Atropos reports.
3. `TemplateNode.Expand` keeps its signature and runs under a budget of its own; inside the package the budgeted `expand` is used.

Nothing else is changed: real records decode as before (Atropos's tests over 278 public logs, compared with EvtxECmd, are unchanged).
