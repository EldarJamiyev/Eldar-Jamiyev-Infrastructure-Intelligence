---
name: audio-studio-mcp
description: Local AI music and sound effects generator MCP for Claude Code and coding agents. Generates background music, instrument loops, sound effects using Stable Audio 3 locally without cloud API fees.
---

# audio-studio-mcp

Local AI music and sound effects generator MCP for Claude Code and coding agents. Generates background music, instrument loops, sound effects using Stable Audio 3 locally without cloud API fees.

## Quick Command / Usage
```bash
uvx audio-studio-mcp
```

## Documentation & Reference
<div align="center">

<img src="docs/assets/banner-en.jpg" alt="Audio Studio MCP: local AI music and sound effects for Claude Code and any MCP client" width="820">

<p>
  <a href="LICENSE"><img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-6b4dff?style=flat-square"></a>
  <img alt="macOS Apple Silicon" src="https://img.shields.io/badge/macOS-Apple_Silicon-111?style=flat-square&logo=apple">
  <img alt="Windows NVIDIA GPU" src="https://img.shields.io/badge/Windows-NVIDIA_GPU-76b900?style=flat-square&logo=nvidia&logoColor=white">
  <a href="https://modelcontextprotocol.io"><img alt="MCP server" src="https://img.shields.io/badge/MCP-server-19b8d6?style=flat-square"></a>
  <img alt="Python 3.10 to 3.13" src="https://img.shields.io/badge/python-3.10–3.13-3776ab?style=flat-square&logo=python&logoColor=white">
  <a href="https://github.com/kanaworksai-hue/audio-studio-mcp/actions/workflows/tests.yml"><img alt="Tests" src="https://img.shields.io/github/actions/workflow/status/kanaworksai-hue/audio-studio-mcp/tests.yml?style=flat-square&label=tests"></a>
  <a href="https://github.com/kanaworksai-hue/audio-studio-mcp/stargazers"><img alt="GitHub stars" src="https://img.shields.io/github/stars/kanaworksai-hue/audio-studio-mcp?style=flat-square&logo=github&label=stars&color=f5c518"></a>
</p>

<p><a href="https://github.com/kanaworksai-hue"><img src="docs/brand/kanaworks-mark.png" height="22" alt="" align="absmiddle"></a>&nbsp;<a href="https://github.com/kanaworksai-hue"><b>A KanaWorks_AI project</b></a></p>

**English** | [简体中文](README.zh-CN.md) | [日本語](README.ja.md)

[🎧 Listen to samples](https://kanaworksai-hue.github.io/audio-studio-mcp/) · [Quick start](#-quick-start) · [Tools](#-tools) · [Web UI](#-web-ui) · [FAQ](#-faq) · [⭐ Star](#-like-it-star-it)

</div>

**Audio Studio MCP** gives Claude Code, Claude Desktop, Cursor and any other [MCP](https://modelcontextprotocol.io) client a sound studio that runs on your own Mac or Windows PC. Ask for background music or a sound effect in plain language; the model generates it locally with [Stable Audio 3](https://github.com/Stability-AI/stable-audio-3). Then it can loop it, normalize the loudness and export it for your game engine or video editor. There is no cloud service and no API key, and generating doesn't cost anything.

<p align="center">
  <img src="docs/assets/demo-en.png" alt="A real Claude Code session: one request produces two lo-fi BGM candidates and a seamless OGG loop for Godot" width="820">
  <br><sub>A real session, shortened. Claude picked a loop length of exactly 11 bars so the beat stays in time when it repeats.</sub>
</p>

## ✨ Highlights

<table>
<tr>
<td align="center" width="25%"><img src="docs/assets/icon-generate.png" width="72" alt=""><br><b>Generate</b><br><sub>BGM, instrument loops and sound effects from one sentence, 1–4 candidates per call</sub></td>
<td align="center" width="25%"><img src="docs/assets/icon-edit.png" width="72" alt=""><br><b>Edit</b><br><sub>Re-s
