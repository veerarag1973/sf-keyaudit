# Providers

sf-keyaudit detects credentials for 18 AI providers. Each provider maps to one or more **pattern IDs**.

Pattern IDs follow the naming convention `{provider}-{keytype}-v{N}`. The version suffix is incremented when a provider changes their key format, so existing allowlist entries remain identifiable after updates.

---

## Detection methods

There are two detection strategies:

**Prefix-match** — the key has a unique, provider-specific prefix (e.g. `sk-ant-api03-` for Anthropic). These are high-confidence detections and match anywhere in the file.

**Context-sensitive** — the key body is too generic to match alone (e.g. a 40-char hex string). The pattern requires surrounding context such as an environment variable name (`TOGETHER_AI_KEY=`) or HTTP header (`Ocp-Apim-Subscription-Key:`). These only match when the context is present.

---

## All providers

### Anthropic

| Field | Value |
|---|---|
| Provider slug | `anthropic` |
| Pattern ID | `anthropic-api-key-v1` |
| Method | Prefix-match |
| Prefix | `sk-ant-api03-` |
| Body | 93 Base64-URL characters |
| Min entropy | 3.5 bits/char |

Matches classic Anthropic Claude API keys in any source file or config.

---

### OpenAI — Project key

| Field | Value |
|---|---|
| Provider slug | `openai` |
| Pattern ID | `openai-project-key-v2` |
| Method | Prefix-match |
| Prefix | `sk-proj-` |
| Body | 100–200 alphanumeric + `-_` chars |
| Min entropy | 4.0 bits/char |

Current format for project-scoped OpenAI API keys.

---

### OpenAI — Service account key

| Field | Value |
|---|---|
| Provider slug | `openai` |
| Pattern ID | `openai-svcacct-key-v1` |
| Method | Prefix-match |
| Prefix | `sk-svcacct-` |
| Body | 100–200 alphanumeric + `-_` chars |
| Min entropy | 4.0 bits/char |

Service-account keys used in backend automation.

---

### OpenAI — Legacy key

| Field | Value |
|---|---|
| Provider slug | `openai` |
| Pattern ID | `openai-legacy-key-v1` |
| Method | Prefix-match with negative lookahead |
| Prefix | `sk-` (excluding `sk-proj-`, `sk-svcacct-`, `sk-ant-`, `sk-or-`) |
| Body | Exactly 48 alphanumeric characters |
| Min entropy | 3.5 bits/char |

Older API key format still valid for many accounts. A negative lookahead prevents double-matching with newer OpenAI patterns, Anthropic, and OpenRouter keys.

---

### OpenRouter

| Field | Value |
|---|---|
| Provider slug | `openrouter` |
| Pattern ID | `openrouter-api-key-v1` |
| Method | Prefix-match |
| Prefix | `sk-or-` (optionally followed by `v{N}-`) |
| Body | 40–100 alphanumeric + `-_` chars |
| Min entropy | 3.5 bits/char |

OpenRouter unifies access to many LLM providers under a single API. Patterns appear before the generic `sk-` pattern to prevent misattribution.

---

### Stability AI

| Field | Value |
|---|---|
| Provider slug | `stability-ai` |
| Pattern ID | `stability-ai-key-v1` |
| Method | Context-sensitive |
| Context | `STABILITY_API_KEY` or `STABILITY_AI_API_KEY` (case-insensitive) |
| Body | `sk-` followed by 48 alphanumeric characters |
| Min entropy | 3.5 bits/char |

Stability AI keys use the same `sk-` prefix as OpenAI legacy keys. Context is required to avoid false positives.

---

### Google Gemini / Google AI

| Field | Value |
|---|---|
| Provider slug | `google-gemini` |
| Pattern ID | `google-gemini-key-v1` |
| Method | Prefix-match |
| Prefix | `AIza` |
| Body | 35 alphanumeric + `-_` chars (39 chars total) |
| Min entropy | 3.5 bits/char |

Used for Gemini, PaLM 2, and other Google AI Studio APIs.

---

### Google Vertex AI — Service Account

| Field | Value |
|---|---|
| Provider slug | `google-vertex-ai` |
| Pattern ID | `google-vertex-service-account-v1` |
| Method | Context-sensitive |
| Context | JSON blob containing both `"type": "service_account"` and `"private_key_id"` |
| Body | 20–64 character private key ID value |
| Min entropy | 3.0 bits/char |

Detects committed GCP service account JSON files. The pattern spans up to 1000 characters between the `type` and `private_key_id` fields using a dotall match.

---

### AWS Bedrock

| Field | Value |
|---|---|
| Provider slug | `aws-bedrock` |
| Pattern ID | `aws-access-key-id-v1` |
| Method | Prefix-match |
| Prefix | `AKIA` (long-term) or `ASIA` (temporary STS) |
| Body | Exactly 16 uppercase alphanumeric characters |
| Min entropy | 3.0 bits/char |

Matches AWS access key IDs used to authenticate to Bedrock and other AWS services.

---

### Azure OpenAI

| Field | Value |
|---|---|
| Provider slug | `azure-openai` |
| Pattern ID | `azure-openai-subscription-key-v1` |
| Method | Context-sensitive |
| Context | `Ocp-Apim-Subscription-Key` header (case-insensitive, `=` or `:` separator) |
| Body | 32 hex characters |
| Min entropy | 3.0 bits/char |

Detects Azure Cognitive Services / Azure OpenAI subscription keys typically found in HTTP request code or `.http` files.

---

### Cohere

| Field | Value |
|---|---|
| Provider slug | `cohere` |
| Pattern ID | `cohere-api-key-v1` |
| Method | Prefix-match |
| Prefix | `co-` |
| Body | 40–80 alphanumeric characters |
| Min entropy | 3.5 bits/char |

---

### Mistral AI

| Field | Value |
|---|---|
| Provider slug | `mistral-ai` |
| Pattern ID | `mistral-api-key-v1` |
| Method | Prefix-match |
| Prefix | `mi-` |
| Body | 40–80 alphanumeric characters |
| Min entropy | 3.5 bits/char |

---

### Hugging Face

| Field | Value |
|---|---|
| Provider slug | `huggingface` |
| Pattern ID | `huggingface-token-v1` |
| Method | Prefix-match |
| Prefix | `hf_` |
| Body | 34–50 alphanumeric characters |
| Min entropy | 3.5 bits/char |

Matches Hugging Face User Access Tokens used for the Hub API, Inference API, and Spaces.

---

### Replicate

| Field | Value |
|---|---|
| Provider slug | `replicate` |
| Pattern ID | `replicate-api-token-v1` |
| Method | Prefix-match |
| Prefix | `r8_` |
| Body | Exactly 40 lowercase hex characters |
| Min entropy | 3.5 bits/char |

---

### Together AI

| Field | Value |
|---|---|
| Provider slug | `together-ai` |
| Pattern ID | `together-ai-key-v1` |
| Method | Context-sensitive |
| Context | `TOGETHER_API_KEY` or `TOGETHER_AI_API_KEY` (case-insensitive) |
| Body | 40–64 lowercase hex characters |
| Min entropy | 3.5 bits/char |

---

### Groq

| Field | Value |
|---|---|
| Provider slug | `groq` |
| Pattern ID | `groq-api-key-v1` |
| Method | Prefix-match |
| Prefix | `gsk_` optionally followed by `live_` or `test_` |
| Body | Exactly 52 alphanumeric characters |
| Min entropy | 3.5 bits/char |

---

### Perplexity AI

| Field | Value |
|---|---|
| Provider slug | `perplexity` |
| Pattern ID | `perplexity-key-v1` |
| Method | Prefix-match |
| Prefix | `pplx-` |
| Body | Exactly 48 alphanumeric characters |
| Min entropy | 3.5 bits/char |

---

### ElevenLabs

| Field | Value |
|---|---|
| Provider slug | `elevenlabs` |
| Pattern ID | `elevenlabs-api-key-v1` |
| Method | Context-sensitive |
| Context | `xi-api-key`, `ELEVENLABS_API_KEY`, or `XI_API_KEY` (case-insensitive) |
| Body | 32 hex characters |
| Min entropy | 3.0 bits/char |

---

### Pinecone

| Field | Value |
|---|---|
| Provider slug | `pinecone` |
| Pattern ID | `pinecone-api-key-v1` |
| Method | Context-sensitive |
| Context | `PINECONE_API_KEY` or `PINECONE_KEY` (case-insensitive) |
| Body | UUID format (`xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`) |
| Min entropy | 3.0 bits/char |

UUID format keys are too common to match without context.

---

### Weaviate

| Field | Value |
|---|---|
| Provider slug | `weaviate` |
| Pattern ID | `weaviate-api-key-v1` |
| Method | Context-sensitive |
| Context | `X-Weaviate-Api-Key` header or `WEAVIATE_API_KEY` variable |
| Body | 20–100 Base64/alphanumeric characters |
| Min entropy | 3.0 bits/char |

---

## Quick reference table

| Provider slug | Pattern ID | Method | Prefix / Context |
|---|---|---|---|
| `anthropic` | `anthropic-api-key-v1` | Prefix | `sk-ant-api03-` |
| `openai` | `openai-project-key-v2` | Prefix | `sk-proj-` |
| `openai` | `openai-svcacct-key-v1` | Prefix | `sk-svcacct-` |
| `openai` | `openai-legacy-key-v1` | Prefix | `sk-` (bare) |
| `openrouter` | `openrouter-api-key-v1` | Prefix | `sk-or-` |
| `stability-ai` | `stability-ai-key-v1` | Context | `STABILITY_API_KEY=` |
| `google-gemini` | `google-gemini-key-v1` | Prefix | `AIza` |
| `google-vertex-ai` | `google-vertex-service-account-v1` | Context | `"type":"service_account"` JSON |
| `aws-bedrock` | `aws-access-key-id-v1` | Prefix | `AKIA` / `ASIA` |
| `azure-openai` | `azure-openai-subscription-key-v1` | Context | `Ocp-Apim-Subscription-Key:` |
| `cohere` | `cohere-api-key-v1` | Prefix | `co-` |
| `mistral-ai` | `mistral-api-key-v1` | Prefix | `mi-` |
| `huggingface` | `huggingface-token-v1` | Prefix | `hf_` |
| `replicate` | `replicate-api-token-v1` | Prefix | `r8_` |
| `together-ai` | `together-ai-key-v1` | Context | `TOGETHER_API_KEY=` |
| `groq` | `groq-api-key-v1` | Prefix | `gsk_` |
| `perplexity` | `perplexity-key-v1` | Prefix | `pplx-` |
| `elevenlabs` | `elevenlabs-api-key-v1` | Context | `xi-api-key:` / `ELEVENLABS_API_KEY=` |
| `pinecone` | `pinecone-api-key-v1` | Context | `PINECONE_API_KEY=` |
| `weaviate` | `weaviate-api-key-v1` | Context | `X-Weaviate-Api-Key:` / `WEAVIATE_API_KEY=` |
