---
name: ai-copilot
description: Use when integrating an AI assistant, local model, function explanation, decompilation help, vulnerability hints, or AI-driven workflows into Powerfull IDA.
---

# AI Copilot

- Treat model output as an untrusted suggestion, never as executable truth.
- Send the minimum necessary context and redact secrets, credentials, and unrelated file content.
- Include address, architecture, bytes, and analysis confidence in prompts so answers remain auditable.
- Show source context and model explanations in the UI; never silently rename or rewrite analysis.
- Use cancellation, timeouts, retries with limits, and a clear offline/local mode.
- Keep provider credentials outside source control and configuration files.
- Add structured response validation before applying any AI-generated action.
