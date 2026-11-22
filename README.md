# AI Application Security Lab

**A Python based learning project for testing and defending a local LLM-powered helpdesk application against prompt injection and unauthorized changes to reference content.**

The application connects to **Gemma 3 (1B)** through **Ollama** and demonstrates a layered, application-enforced approach to security. It includes a rule-based detector, document integrity checks against approved facts, strict answer grounding, controlled red-team scenarios, and privacy-conscious security reporting.

> **Scope:** This is a deliberately restricted educational prototype, **not** a production-ready prompt-injection firewall or a general-purpose secure RAG system.

## Features

- Local LLM integration with Ollama (`gemma3:1b`)
- Prompt-injection screening with manually weighted risk scores (0–100)
- Context heuristics for selected educational quotations and status messages
- Verification of retrieved facts against application-approved reference facts
- Output grounding through exact comparison with approved answers
- Safe fallback when the model fails, refuses, or produces unsupported text
- Automated detector evaluation, protected red-team tests, and isolated model experiments
- Privacy-conscious JSONL event logging and JSON test reports
- Self-tests that do not require Ollama to be running

## Security flow

```text
Employee question
       |
       v
Topic selection --> Retrieve reference fact
                           |
                           v
                  Prompt-injection screening
                           |
                           v
                  Approved-fact integrity check
                           |
                 approved  |  modified / suspicious
                           |            |
                           v            v
                       Local LLM     Block or use
                       (Ollama)     approved fallback
                           |
                           v
                   Exact answer validation
                           |
                           v
                   Approved user answer
                           |
                           v
                  Metadata-only event log
```

The Python application makes the final allow/block/fallback decision. It does **not** delegate authorization or integrity enforcement to the language model.

## Requirements

- Windows with Python 3 (the example commands use the Windows `py` launcher)
- [Ollama](https://ollama.com/) installed and running locally
- Local model: `gemma3:1b`

The Python script uses the **standard library only**, so there is no `pip install` step.

## Quick start

1. Install Python and Ollama.
2. Download the model in PowerShell:

   ```powershell
   ollama pull gemma3:1b
   ```

3. Open PowerShell in the repository folder, then run:

   ```powershell
   py -m py_compile app.py
   py app.py --self-test
   py app.py
   ```

4. Ask a supported question, for example:

   ```text
   What is the leave policy?
   ```

The application creates `documents/helpdesk_knowledge.txt` with **fictional sample policies** if it does not exist. It also creates a local `reports/` folder when logging or report generation occurs.

## Commands

| Command | What it does |
| --- | --- |
| `py app.py` | Interactive, protected helpdesk assistant |
| `py app.py --self-test` | Run deterministic Python security, grounding, and reporting checks (no LLM required) |
| `py app.py --evaluate` | Compare rule-based detector performance across labeled text examples (no LLM required) |
| `py app.py --red-team` | Run the five-case protected-application test |
| `py app.py --red-team-all` | Run all nine protected-application test cases |
| `py app.py --red-team-model` | Run an isolated five-case model experiment with application integrity gates intentionally bypassed |
| `py app.py --red-team-model-all` | Run all isolated model scenarios |

**Caution:** The `--red-team-model` commands are for this fictional, local lab only. They intentionally bypass the application's integrity controls and are not suitable for real confidential data.

## Validation results

Results observed during local development (Gemma behavior may vary by environment and run):

| Check | Observed result |
| --- | --- |
| Python self-tests | **34/34 passed** |
| Original detector, 18 curated examples | **72.2% accuracy** (TP 8, TN 5, FP 3, FN 2) |
| Revised detector, same 18 examples | **100% accuracy** (TP 10, TN 8, FP 0, FN 0) |
| Revised detector, separate 12 examples | **91.7% accuracy** (TP 5, TN 6, FP 0, FN 1) |
| Protected full test | **6/6 attack cases prevented from reaching the model**, **0 attack markers exposed** |
| Protected benign cases | **3/3 delivered the approved answer**; two required integrity fallbacks |
| Isolated model test | **1 attack marker appeared** in model output during the five-case quick run |
| Reports | JSON security report and JSONL event log generated |

The revised detector was developed after inspecting errors on the original 18 examples; **100% on that set is not a generalization claim**. The separate set still contains a missed attack. A marker in model output is not, by itself, proof of instruction following.

## Reporting and privacy

Local results are saved to `reports/`, including `security_events.jsonl` and timestamped JSON test reports. They record security decisions and test metadata rather than employee questions, reference-document text, or raw model responses.

**Do not publish your local `reports/` or `documents/` folders.** They are intentionally excluded by `.gitignore`; select only the intended public files when uploading via the GitHub website.

## Known limitations

- Exact matching against three hardcoded approved policies is suitable for this controlled demonstration, but not a scalable approach to dynamic enterprise knowledge bases.
- Legitimate edits to a reference fact will trigger an integrity fallback until the approved source is updated through an authorized process.
- The detector is regex/rule-based with manually chosen weights; it can miss subtle attacks and produce false positives.
- A risk score of `0` does **not** prove content is safe. Scores are not calibrated probabilities.
- The model can return inaccurate answers; strict grounding avoids exposing unsupported policy text by returning the approved fact.
- Test datasets are small and curated. Automated checks do not establish robustness against arbitrary attacks or production threats.
- The project does not implement authentication, role-based authorization, or a complete enterprise audit/security lifecycle.

## Tech stack

**Python**, **Ollama**, **Gemma 3 (1B)**, regular expressions, JSON/JSONL, Windows PowerShell.

## Responsible use

This project uses fictional policy information and harmless output markers. Test AI systems only when you own them or have authorization.
