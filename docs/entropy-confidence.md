# Entropy and Confidence

sf-keyaudit uses **Shannon entropy** as a secondary filter to reduce false positives. A pattern match alone is not sufficient to raise a high-confidence finding — the matched key body must also have high enough randomness to plausibly be a real secret.

---

## The problem: placeholder keys

Many codebases contain placeholder strings that look structurally like API keys:

```python
OPENAI_API_KEY = "sk-testtesttesttesttesttesttesttesttesttesttesttest"
```

This has the correct `sk-` prefix and 48-character body, so it matches the `openai-legacy-key-v1` pattern. But a human can immediately see it is a fake — the body is a repetition of `test` with almost no randomness.

A real key body is generated from a cryptographically random source and has very high character diversity. Shannon entropy quantifies this diversity precisely.

---

## Shannon entropy

Shannon entropy measures the average information content per character in a string.

$$H = -\sum_{x} p(x) \cdot \log_2 p(x)$$

Where $p(x)$ is the probability (frequency) of character $x$ in the string.

| String | Entropy (bits/char) |
|---|---|
| `"aaaaaaaaaaaaaaaa"` | 0.0 — uniform, zero information |
| `"ababababababababab"` | 1.0 — two equal-frequency characters |
| `"sk-testtesttesttesttesttest..."` | ~1.5 — low diversity |
| `"xK9pQm7vL3nRwT5yJbHf..."` | 4.5+ — high diversity, likely real |

A real API key generated from 256 bits of entropy distributed across a 48-character body typically scores between 4.0 and 5.5 bits/char.

---

## How sf-keyaudit uses entropy

Every pattern has a `min_entropy` threshold. After a regex match, the tool:

1. Extracts the `body` named capture group (the secret portion, excluding the prefix).
2. Computes Shannon entropy of the body string.
3. Compares to `min_entropy`:
   - **≥ threshold**: high-confidence finding → goes into `findings` → contributes to exit code 1
   - **< threshold**: low-confidence finding → goes into `low_confidence_findings` → does not affect exit code

---

## Per-provider thresholds

| Provider | Pattern ID | Min entropy |
|---|---|---|
| Anthropic | `anthropic-api-key-v1` | 3.5 |
| OpenAI (project) | `openai-project-key-v2` | 4.0 |
| OpenAI (service account) | `openai-svcacct-key-v1` | 4.0 |
| OpenAI (legacy) | `openai-legacy-key-v1` | 3.5 |
| OpenRouter | `openrouter-api-key-v1` | 3.5 |
| Stability AI | `stability-ai-key-v1` | 3.5 |
| Google Gemini | `google-gemini-key-v1` | 3.5 |
| Google Vertex AI | `google-vertex-service-account-v1` | 3.0 |
| AWS Bedrock | `aws-access-key-id-v1` | 3.0 |
| Azure OpenAI | `azure-openai-subscription-key-v1` | 3.0 |
| Cohere | `cohere-api-key-v1` | 3.5 |
| Mistral AI | `mistral-api-key-v1` | 3.5 |
| Hugging Face | `huggingface-token-v1` | 3.5 |
| Replicate | `replicate-api-token-v1` | 3.5 |
| Together AI | `together-ai-key-v1` | 3.5 |
| Groq | `groq-api-key-v1` | 3.5 |
| Perplexity | `perplexity-key-v1` | 3.5 |
| ElevenLabs | `elevenlabs-api-key-v1` | 3.0 |
| Pinecone | `pinecone-api-key-v1` | 3.0 |
| Weaviate | `weaviate-api-key-v1` | 3.0 |

Context-sensitive patterns (Google Vertex AI, AWS, Azure OpenAI, ElevenLabs, Pinecone, Weaviate) use a lower threshold of 3.0 because the surrounding context already reduces the false-positive risk significantly.

Prefix-match patterns that accept a wide body character class use 3.5 or 4.0.

---

## Low-confidence findings in the JSON report

Low-confidence matches still appear in the output for visibility:

```json
{
  "findings": [],
  "low_confidence_findings": [
    {
      "id": "f-001",
      "provider": "openai",
      "file": "tests/fixtures/mock.py",
      "line": 3,
      "column": 8,
      "match": "sk-***REDACTED***",
      "pattern_id": "openai-legacy-key-v1",
      "severity": "critical",
      "entropy": 1.20
    }
  ]
}
```

If `findings` is empty but `low_confidence_findings` is non-empty, the exit code is still **0**.

---

## What to do with low-confidence findings

**Review them.** Although they are below threshold, they are worth checking:

- Is the file a test fixture with a well-known placeholder? Fine — consider adding a comment or a `.sfignore` entry for the whole fixtures directory.
- Is it a real key that happens to have low-entropy characters in its body? Arguably impossible for a cryptographically generated key, but if in doubt rotate it.
- Is it a documentation example? Consider adding it to the allowlist with an explanatory reason, or moving it to a file covered by `.sfignore`.

**Do not suppress via allowlist.** Low-confidence findings do not affect exit code so there is nothing to suppress. Use `.sfignore` to exclude entire directories of test fixtures instead.

---

## Worked examples

### Real key (high confidence)

```python
ANTHROPIC_API_KEY = "sk-ant-api03-AbCdEf1234567890GhIjKlMnOpQrStUvWxYzABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxy01"
```

Body: `AbCdEf1234567890GhIjKlMnOpQrStUvWxYzABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxy01`
Entropy: ~5.0 bits/char → **high-confidence** → exits 1

### Placeholder key (low confidence)

```python
ANTHROPIC_API_KEY = "sk-ant-api03-testtesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttest01"
```

Body: `testtesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttest01`
Entropy: ~1.9 bits/char → **low-confidence** → exits 0

### AWS key (context-sensitive, lower threshold)

```python
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
```

Body: `IOSFODNN7EXAMPLE`
Entropy: ~3.3 bits/char → above 3.0 threshold → **high-confidence** → exits 1

> Note: AWS uses the well-known example key `AKIAIOSFODNN7EXAMPLE` in their public documentation. If this appears in your docs, add the file to `.sfignore` or add an allowlist entry with a clear reason.
