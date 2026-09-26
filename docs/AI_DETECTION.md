# AI-Native Detection & Security Review Engine

## 1. Objective & Principles

The AI-Native Detection Engine in VortexDNS detects publicly observable technical indicators that an application or website incorporates artificial intelligence, large language models (LLMs), or vector embeddings.

### Core Principles
1. **Evidence-Based Classification**: A website is never classified as "AI-Native" simply because it contains marketing copy or the word "AI". Classification requires technical signals (SDK imports, streaming endpoints, vector databases, model provider API calls).
2. **Explainable Confidence Scoring**: Every finding includes an exact confidence metric ($0.50$ to $1.00$) and explicit technical evidence.
3. **No False Certainty**: If an AI implementation pattern cannot be verified from the public surface, it is explicitly classified as `"Unable to verify externally"`, never fabricated.
4. **Zero Secret Exposure**: Any discovered API key or provider credential is systematically masked using `RedactSecret` before persistence or transmission.

---

## 2. Classification Tiers

| Classification | Definition |
| :--- | :--- |
| **No public AI evidence detected** | No AI SDKs, streaming routes, model providers, or `llms.txt` observed. |
| **AI-assisted** | Isolated public indicators (e.g. `llms.txt` or an external AI widget embedded via script tag). |
| **AI-enabled** | Active AI client libraries (e.g. `@ai-sdk/react`, OpenAI client) or public inference routes. |
| **AI-native architecture indicators** | Deep structural AI integration (e.g. streaming LLM endpoints, vector database integrations, client-side agent tool loops). |

---

## 3. Technology & Provider Coverage

The engine scans script bundles, HTML meta tags, and network endpoints for signatures belonging to:

- **AI SDKs**: Vercel AI SDK (`@ai-sdk/react`, `useChat`, `useCompletion`), LangChain (`langchain`, `@langchain/core`), LlamaIndex (`llamaindex`), Hugging Face Inference (`@huggingface/inference`).
- **Foundation Model Providers**: OpenAI (`api.openai.com`), Anthropic (`api.anthropic.com`), Google Gemini (`generativelanguage.googleapis.com`), Cohere (`api.cohere.ai`), Mistral (`api.mistral.ai`), Groq (`api.groq.com`), Together AI (`api.together.xyz`), Ollama (`11434`).
- **Vector Databases & Search**: Pinecone (`pinecone.io`), Weaviate (`weaviate.io`), Qdrant (`qdrant.tech`), Milvus (`zilliz.com`), pgvector.
- **Standards & Manifests**: `/llms.txt` and `/.well-known/llms.txt`.

---

## 4. Secret Redaction Specification

Public bundles may inadvertently leak API tokens. The scanner identifies matching regex patterns:
- OpenAI: `sk-proj-[A-Za-z0-9_-]{20,}` / `sk-[A-Za-z0-9]{32,}`
- Anthropic: `sk-ant-[A-Za-z0-9_-]{20,}`
- Google Gemini: `AIza[0-9A-Za-z_-]{35}`
- Hugging Face: `hf_[A-Za-z0-9]{34,}`
- AWS Access Keys: `AKIA[0-9A-Z]{16}`

### Redaction Rules
1. Never log or store the full secret.
2. Preserve recognizable prefix: `sk-proj-` or `sk-ant-`.
3. Mask the central entropy with 16 asterisks: `****************`.
4. Preserve the last 4 characters for rotation identification: `91Ax`.
   - Result: `sk-proj-****************91Ax`
5. Discovered credentials are never executed, probed, or sent to any third party.
