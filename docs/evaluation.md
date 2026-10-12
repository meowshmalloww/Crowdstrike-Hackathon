# Evaluation

`data/evaluation/events.jsonl` is a small labeled synthetic fixture for deterministic detector behavior. It covers benign searches, SQL-injection indicators, scanner probes, and benign punctuation/unicode cases. It is not captured traffic and must not be described as a field-accuracy benchmark.

Run the CLI locally:

```powershell
python -m counterflow_eval --dataset data/evaluation/events.jsonl
```

Or run the same fixture through the authenticated dashboard control action. Each run persists the fixture identifier, creation time, and confusion matrix/precision/recall/F1 metrics. Classification uses a versioned deterministic rule score. Threshold and per-signal contributions are included in the output so reviewers can reproduce each decision.

The UI displays `—` when a latency sample does not exist and `empty` when no runtime telemetry has been stored. Synthetic fixture metrics stay separate from runtime gateway counts. Expand the dataset with independently labeled examples before drawing conclusions about false-positive or detection rates outside this fixed fixture.
