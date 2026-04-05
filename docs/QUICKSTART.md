# Quick Start - TSM Layer

## 30-Second Try (No Setup)

```bash
git clone https://github.com/tsm7979/tsm
cd tsm
python demo.py
```

**That's it.** The demo runs automatically and shows:
1. Normal query → cloud routing
2. Sensitive data → PII detection + local routing

---

## Use It Yourself (60 Seconds)

### 1. Clone

```bash
git clone https://github.com/tsm7979/tsm
cd tsm
```

### 2. Run

```bash
python cli_app.py run "What is AI?"
```

### 3. Try the "Holy Sh*t" Demo

```bash
python cli_app.py run "My name is John, SSN 123-45-6789, help me"
```

Watch TSM:
- Detect the SSN automatically
- Sanitize it
- Route to local model (zero data leak)
- Log everything

---

## Commands

```bash
# Run a request
python cli_app.py run "your prompt"

# View audit log
python cli_app.py audit <trace_id>

# Check configuration
python cli_app.py config
```

---

## Optional: Add Your API Keys

Only needed if you want to use cloud models:

```bash
export TSM_OPENAI_API_KEY=your-key-here
export TSM_ANTHROPIC_API_KEY=your-key-here
```

Without keys, TSM still works with local models.

---

## What Next?

- Read [README.md](README.md) for full docs
- See [LAUNCH_PLAN.md](LAUNCH_PLAN.md) for launch strategy
- Check [100_PERCENT_STEP1_COMPLETE.md](100_PERCENT_STEP1_COMPLETE.md) for architecture

---

**That's it. Start protecting your AI calls now.**
