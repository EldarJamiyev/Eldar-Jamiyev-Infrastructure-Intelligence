---
name: microsoft-ufo
description: "Windows OS desktop automation agent (Microsoft UFO² & UFO³ Galaxy). Automates native Windows applications (Word, Excel, PowerPoint, Edge, File Explorer, Settings, and custom desktop apps) using UI Automation, pywinauto, WinCOM, hybrid visual/control detection, and multi-agent coordination."
metadata:
  openclaw:
    requires:
      python: ">=3.10"
      os: "windows"
---

# Microsoft UFO (UI-Focused Windows Agent)

Microsoft UFO is a UI-focused multi-agent framework designed to fulfill natural-language user requests on **Windows OS** by seamlessly navigating, inspecting, and operating individual or spanning multiple desktop applications.

## Architecture

UFO employs a dual-agent hierarchical architecture:
1. **HostAgent**: Desktop navigator and orchestrator. Inspects the active screen, identifies candidate applications, launches or focuses target apps, and delegates sub-tasks to the corresponding AppAgent.
2. **AppAgent**: In-application execution specialist. Operates within the selected application, identifies UI controls (via Windows UIAutomation and visual grounding), plans action sequences, executes clicks/keystrokes/APIs, and evaluates completion.
3. **UFO³ Galaxy**: Multi-device orchestration layer that decomposes complex workflows into executable Directed Acyclic Graphs (DAGs) across heterogeneous environments.

## Hybrid Control & Perception Engine

UFO bridges UIAutomation (UIA) with computer vision:
- **Native Windows APIs**: Win32, UIAutomation (UIA), and WinCOM for fast, deterministic control manipulation.
- **Visual Grounding**: Multimodal LLM vision perceives non-standard custom controls, Canvas elements, and complex graphics.
- **Speculative Multi-Action**: Bundles multiple predicted steps into a single turn for up to 51% lower latency.

## Installation & Environment

The UFO repository is located at `C:\Users\sahin\.gemini\antigravity\scratch\repos\UFO`.

```powershell
cd C:\Users\sahin\.gemini\antigravity\scratch\repos\UFO
pip install -r requirements.txt
```

Core dependencies: `pywinauto`, `pyautogui`, `uiautomation`, `comtypes`, `art`, `openai`, `anthropic`, `langchain`, `fastmcp`.

## Configuration

Configuration files are located in `config/ufo/`:
- `config/ufo/agents.yaml`: Credentials for `HOST_AGENT` and `APP_AGENT` (OpenAI, Anthropic Claude, or local LLMs).
- `config/ufo/rag.yaml`: Settings for Bing search, offline help documents, and self-experience learning.
- `config/ufo/system.yaml`: Execution timeouts, screenshot settings, and logging.

### Template Setup:
```powershell
copy config\ufo\agents.yaml.template config\ufo\agents.yaml
```

Example configuration snippet for `config/ufo/agents.yaml`:
```yaml
HOST_AGENT:
  VISUAL_MODE: true
  API_TYPE: "openai"  # or "claude", "gemini"
  API_BASE: "https://api.openai.com/v1/chat/completions"
  API_KEY: "YOUR_API_KEY"
  API_MODEL: "gpt-4o"

APP_AGENT:
  VISUAL_MODE: true
  API_TYPE: "openai"
  API_BASE: "https://api.openai.com/v1/chat/completions"
  API_KEY: "YOUR_API_KEY"
  API_MODEL: "gpt-4o"
```

## Running Tasks

### 1. Interactive CLI Mode:
```powershell
cd C:\Users\sahin\.gemini\antigravity\scratch\repos\UFO
python -m ufo --task <task_name>
```

### 2. Direct Automated Execution:
```powershell
python -m ufo --task <task_name> -r "<natural_language_request>"
```

Examples:
```powershell
# Automate Word formatting
python -m ufo --task word_report -r "Open Word, create a title 'Q3 Summary', set font size to 24 bold, and save as report.docx"

# Automate PowerPoint slide creation
python -m ufo --task ppt_deck -r "Open PowerPoint, add a new title slide with 'AI Strategy 2026', and insert a 3-column table"

# Automate Windows Settings & System tasks
python -m ufo --task check_display -r "Open Windows Settings, navigate to System > Display, and tell me the current resolution"
```

## Logs & Artifacts

All screenshots, action sequences, and LLM reasoning steps are stored under:
```
./ufo/logs/<task_name>/
```
Use these traces to inspect, debug, and verify completed workflows.
