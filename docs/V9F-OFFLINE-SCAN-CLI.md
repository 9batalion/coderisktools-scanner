# V9f — offline vulnerability scan CLI

```bash
python -m src vuln scan \
  --root REPOSITORY \
  --database vulnerability.sqlite \
  --format json|sarif|markdown|html|csv \
  [--output REPORT]
```

The command:

- reads only a local regular SQLite file;
- requires an active local snapshot;
- scans supported manifests through the existing inventory/pipeline;
- preserves exact finding fields returned by the pipeline;
- emits exit code `0` for no findings, `1` for findings, and `3` for rejected input/runtime errors;
- does not fetch, execute repository code, invoke subprocesses, or mutate the database/cache;
- supports all V9 report formatters.

The JSON and SARIF reports remain exact-value exports. Text formats apply only syntax escaping; CSV applies a spreadsheet formula-injection safety marker.
