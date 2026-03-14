# Dataset Policy

Default training uses a **clean-license** profile only.

Allowed licenses in this profile:

- Apache-2.0
- MIT
- CC-BY-4.0 (attribution required)

## Allowed (default)

| Dataset | Source | License | Status | Notes |
|---|---|---|---|---|
| deepset/prompt-injections | https://huggingface.co/datasets/deepset/prompt-injections | Apache-2.0 | allowed | Binary prompt injection labels. |
| JailbreakBench/JBB-Behaviors | https://huggingface.co/datasets/JailbreakBench/JBB-Behaviors | MIT | allowed | Harmful behavior prompts for jailbreak/misuse intent. |
| OpenAssistant/oasst1 | https://huggingface.co/datasets/OpenAssistant/oasst1 | Apache-2.0 | allowed | High-volume benign prompter messages after filtering. |
| neuralchemy/Prompt-injection-dataset | https://huggingface.co/datasets/neuralchemy/Prompt-injection-dataset | Apache-2.0 | allowed | Benign + prompt-injection labeled prompts. |
| Smooth-3/llm-prompt-injection-attacks | https://huggingface.co/datasets/Smooth-3/llm-prompt-injection-attacks | Apache-2.0 | allowed | Multi-label prompt attack intents including exfiltration and jailbreak. |
| jackhhao/jailbreak-classification | https://huggingface.co/datasets/jackhhao/jailbreak-classification | Apache-2.0 | allowed | Benign vs jailbreak prompts. |
| nvidia/Aegis-AI-Content-Safety-Dataset-2.0 | https://huggingface.co/datasets/nvidia/Aegis-AI-Content-Safety-Dataset-2.0 | CC-BY-4.0 | allowed | Safety-labeled prompts; selected unsafe categories mapped to existing labels. |
| Synthetic benign prompts | In-repo generator (`prepare_dataset.py`) | N/A | allowed | Used to enforce a minimum benign floor when external benign rows are insufficient. |

## Excluded from default profile

| Dataset | Source | License | Status | Reason |
|---|---|---|---|---|
| Lakera/mosscap_prompt_injection | https://huggingface.co/datasets/Lakera/mosscap_prompt_injection | MIT | excluded | Weak-label mapping produced high false positives; removed from default mix. |
| PKU-Alignment/BeaverTails | https://huggingface.co/datasets/PKU-Alignment/BeaverTails | CC-BY-NC-4.0 | excluded | Non-commercial restriction. |
| allenai/wildjailbreak | https://huggingface.co/datasets/allenai/wildjailbreak | ODC-BY + gated terms | excluded | Additional responsible-use/gating obligations; not default-safe for all deployments. |

If you change dataset selection, re-check license terms before retraining.

## Attribution note for CC-BY-4.0

When using CC-BY-4.0 datasets (for example, Aegis 2.0), keep attribution in:

- Training docs and dataset manifest files.
- Release notes for exported models.
- Any downstream distribution package that ships trained artifacts.
