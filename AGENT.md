# Running this as a Cursor background agent

The pipeline is plain Python with a stable CLI, which is exactly what Cursor
background or cloud agents are good at driving on a schedule. Two ways to wire
it:

## Option A - agent as a thin scheduler

You do not need the LLM agent to be clever here; the Python does the recon
deterministically. Use the background agent to run it on a cadence and escalate
only when the diff is non-empty.

Drop this in as the agent's task or `.cursor` instructions:

```text
Goal: monitor the live HackMIT site for the appearance/movement of the
admissions-puzzle entry point. Do NOT attempt to solve any puzzle. Only locate
and report candidate entry points.

Each run:
1. Execute: python -m hackmit_recon.run --render --out runs
2. Read the "change since last run" section of the output.
3. If there are NEW findings, summarize them in plain language: what kind of
   seam, where (URL), and the evidence snippet. Rank by the score field.
4. If nothing changed, reply with a single line: "no change".
5. Never modify the target site, never submit answers, never brute-force.
   Keep config.py politeness settings as-is.

Constraints:
- Treat hackmit.org as a production server owned by someone else.
- If a run errors with rate-limit / 429 / connection issues, back off and stop;
  do not retry aggressively.
```

Then schedule it. A sane cadence while waiting for a stage to unlock is every
30-60 minutes, not every few seconds.

## Option B - let the agent reason over the JSON

If you want the agent to do more interpretation, have it run the CLI, load the
newest `runs/recon-*.json`, and reason about which findings most plausibly form
a chain, such as a hidden comment pointing at a path, then that path serving JS
that `fetch()`es a subdomain.

Prompt it to produce a short "most likely door" shortlist with its reasoning,
but keep the hard rule: locate, do not solve.

## Environment notes

- The sandbox needs outbound network to `hackmit.org`.
- The static pass needs only `requests` and `beautifulsoup4`.
- The `--render` pass needs `pip install playwright && playwright install chromium`.
- Artifacts in `runs/` and `runs/.state/last_ids.json` persist the snapshot
  between runs if the working directory is stable.

## Done criteria

When a run flags a high-score `suspicious_link`, `meta_redirect`, or
`render_network` pointing at a fresh path or subdomain that was not there
before, that is your candidate door. Open it yourself and start the actual
puzzle. The pipeline's job ends at the threshold.
