# Installation

## Requirements

- **Python 3.12+**
- pip or Poetry

## Install from PyPI

```bash
pip install medusa-mcp
```

## Install from source

```bash
git clone https://github.com/joshmaster2165/medusa.git
cd medusa
poetry install
```

## Verify installation

```bash
medusa --version
```

You should see:

```
medusa, version 0.1.0
```

## Optional: AI Reasoning Engine

To use the AI reasoning engine (`--reason` flag), you need a Claude API key:

```bash
# Option 1: Environment variable
export ANTHROPIC_API_KEY=sk-ant-...

# Option 2: Save to config
medusa configure --claude-api-key sk-ant-...

# Option 3: Pass directly
medusa scan --reason --claude-api-key sk-ant-...
```

## Optional: Dashboard Integration

To upload scan results to your Medusa dashboard:

```bash
medusa configure --api-key sk_medusa_...
medusa scan --upload
```
