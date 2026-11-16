<p align="center">
  <img src="docs/icon.png" width="128" alt="iServer icon">
</p>

<h1 align="center">iServer</h1>

<p align="center">
  <strong>Every dev server running on your Mac, plus CPU, storage and clipboard, one click away in the menu bar.</strong>
</p>

<p align="center">
  <a href="https://github.com/AntoniovanDijck/iServer/releases/latest"><img src="https://img.shields.io/github/v/release/AntoniovanDijck/iServer?color=8b5cf6&label=download" alt="Latest release"></a>
  <img src="https://img.shields.io/badge/macOS-13%2B-black?logo=apple" alt="macOS 13+">
  <img src="https://img.shields.io/badge/Swift-single%20file-F05138?logo=swift&logoColor=white" alt="Swift">
  <a href="https://github.com/AntoniovanDijck/iServer/actions/workflows/build.yml"><img src="https://github.com/AntoniovanDijck/iServer/actions/workflows/build.yml/badge.svg" alt="Build"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-10b981" alt="MIT License"></a>
</p>

<p align="center">
  <img src="docs/screenshot.png" width="440" alt="iServer panel showing running dev servers">
</p>

---

`next dev` in one tab, a Vite server you forgot about, a Postgres from last week, a `python -m http.server` an AI agent started somewhere… **iServer** puts them all in your menu bar, named after their project, with one click to open, reveal or stop them. Next to that it shows how busy your Mac is, what is filling your disk, and what you copied recently.

## Features

### Servers

- 🔎 **Finds every local server**: any process listening on a TCP port, named after the project folder it runs in
- 🏷️ **Recognises the stack**: Next.js, Vite, Astro, Nuxt, Remix, Storybook, Django, FastAPI, Flask, Rails, Jupyter, Postgres, MySQL, MongoDB, Redis, Docker, Ollama and plain Node, Bun, Deno or Python each get their own badge
- 🧩 **Groups related processes**: Electron + its Vite server, or Node + an embedded Postgres, show up as one project
- 📈 **Live load per server**: CPU sparkline, memory and uptime on every card
- 🟠 **Flags exposed servers**: orange means it listens on all interfaces and is reachable from your network
- 🌐 **Open in the browser**: click a card for `localhost`, or the **LAN** button to open it via your network IP
- 📂 **Jump to the project** in Finder or a new Terminal window (hover a card)
- 🛑 **Stop a server** with SIGTERM, after confirming; iServer checks each process again first, so a reused PID can't hit something else
- 🤖 **Knows AI agents**: servers started from a Claude Code scratchpad are labelled with their project

### Your Mac

- 📊 **Summary bar**: number of dev servers, plus CPU, RAM and disk gauges that turn orange and red as they fill up
- ⚡ **Activity**: large CPU, GPU and memory gauges, a history chart, and the servers using the most CPU
- 💾 **Storage**: used and free space per volume, and cleanup of caches, Homebrew, Xcode DerivedData, logs and the Trash. It always asks first, and never touches temp files of running apps or Apple/iCloud caches
- 📋 **Clipboard history**: search (just start typing) and re-copy recent text, links and files, and pin what you want to keep. Anything a password manager marks as private is skipped, and only pinned clips are saved to disk
- 🖥️ **Menu bar graph**: the icon is a live mini CPU graph

### Small and native

- 🪶 **Tiny**: one Swift file, no dependencies, no permissions needed
- ✨ **Feels like macOS**: Liquid Glass on macOS 26, smooth animations, light and dark mode, English and Dutch
- 🔋 **Light on battery**: scans every 30 seconds (every 8 while open), and animations only run while something moves

## Install

### Download

1. Download **iServer.zip** from the [latest release](https://github.com/AntoniovanDijck/iServer/releases/latest)
2. Unzip it and drag **iServer.app** to your Applications folder
3. Open it. The app is not notarized, so macOS will ask the first time: right-click → **Open**, or run:

   ```bash
   xattr -dr com.apple.quarantine /Applications/iServer.app
   ```

### Build from source

All you need is the Xcode Command Line Tools (`xcode-select --install`).

```bash
git clone https://github.com/AntoniovanDijck/iServer.git
cd iServer
./build.sh --install
```

This builds `iServer.app`, copies it to `~/Applications` and launches it.

## Usage

Click the CPU graph in the menu bar to open the panel. The top bar shows how many dev servers are running and your CPU, RAM and disk use. The tabs are **Servers**, **Activity**, **Storage** and **Clipboard**.

| | |
|---|---|
| 🟢 / 🟠 | Local only / reachable from your network (with a **LAN** button to open it via your IP) |
| Click a card | Open the server in your browser; hover for Finder, Terminal and Stop |
| **Apps** | Also list regular apps that open ports (Chrome, Spotify, AirPlay…) |
| **Login** | Start iServer automatically |
| <kbd>Esc</kbd> | Clear the clipboard search, or close the panel |

It also works from the command line:

```bash
iServer --list         # print running dev servers
iServer --list --all   # include regular apps
iServer --demo         # show sample data, e.g. for screenshots
iServer --demo --open-menu --tab activity   # open the panel on a tab
```

(`iServer` is at `/Applications/iServer.app/Contents/MacOS/iServer`.)

## How it works

Every 30 seconds (every 8 while the panel is open) iServer:

1. lists listening TCP sockets with `lsof -iTCP -sTCP:LISTEN`
2. skips system services and apps installed in `/Applications`
3. walks the process tree (`ps`) so child processes are grouped under the server that started them
4. reads each process's working directory and turns it into a project name (`~/Projects/acme-web` → **acme-web**)

It only sees processes owned by your user, without any special permissions.

## FAQ

<details>
<summary><strong>A server I expect isn't listed</strong></summary>

If its binary lives inside an app in `/Applications` (LM Studio, Docker Desktop without containers…), it's hidden by default. Turn on **Show apps too**.
</details>

<details>
<summary><strong>Does it use much battery?</strong></summary>

No. It runs `lsof` and `ps` every 30 seconds (every 8 while the panel is open), which takes a few milliseconds. The menu bar graph reads the CPU load counter every 3 seconds, and the panel's animations only run while something is moving.
</details>

<details>
<summary><strong>Which macOS versions does it support?</strong></summary>

macOS 13 and later. On macOS 26 the panel uses Liquid Glass; on older versions it uses a regular translucent background.
</details>

<details>
<summary><strong>Which languages does it support?</strong></summary>

English, and Dutch when Dutch is your preferred macOS language.
</details>

## The icon

The app icon is rendered by a Metal fragment shader (signed distance fields, fbm noise for the aurora, bloom on the status LEDs). To tweak and re-render it:

```bash
./scripts/make-icon.sh   # renders scripts/IconShader.swift → Resources/AppIcon.icns
```

## Contributing

Issues and pull requests are welcome. Please keep it a single file with no dependencies.

## License

[MIT](LICENSE) © 2026 Antonio van Dijck
