// iServer — a menu bar app that shows which development servers are running on your Mac.
import AppKit
import Darwin
import ServiceManagement

// MARK: - Localization (English, with Dutch when that is the preferred language)

let isDutch = Locale.preferredLanguages.first?.hasPrefix("nl") ?? false
func L(_ en: String, _ nl: String) -> String { isDutch ? nl : en }

// MARK: - Model

struct Listener: Hashable {
    let port: Int
    var exposed: Bool  // listening on all interfaces, so reachable from the network
}

struct ServerProcess {
    let pid: Int32
    let ppid: Int32
    let execPath: String
    let args: String
    var cwd: String
    let elapsed: String
    var listeners: [Listener]

    var execName: String { (execPath as NSString).lastPathComponent }
}

struct ServerGroup {
    let id: Int32  // pid of the top-level process
    let title: String
    let detail: String
    let folder: String?
    let processes: [ServerProcess]
    let listeners: [Listener]

    var exposed: Bool { listeners.contains { $0.exposed } }

    // Used to decide whether the menu needs to be rebuilt.
    var signature: String {
        "\(id)|\(title)|\(detail)|" + listeners.map { "\($0.port)\($0.exposed)" }.joined(separator: ",")
            + "|" + processes.map { String($0.pid) }.joined(separator: ",")
    }
}

// MARK: - Scanner

enum Scanner {
    static let home = NSHomeDirectory()

    static let projectContainers: Set<String> = [
        "Desktop", "Documents", "Developer", "Projects", "projects", "code", "Code",
        "src", "dev", "repos", "git", "GitHub", "Sites", "Downloads", "workspace",
    ]

    static let nonHTTPExecs: Set<String> = [
        "postgres", "redis-server", "valkey-server", "mysqld", "mariadbd", "mongod", "memcached",
    ]
    static let nonHTTPPorts: Set<Int> = [5432, 6379, 3306, 27017, 11211]

    static func run(_ path: String, _ args: [String]) -> String {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: path)
        p.arguments = args
        let pipe = Pipe()
        p.standardOutput = pipe
        p.standardError = FileHandle.nullDevice
        do { try p.run() } catch { return "" }
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        return String(decoding: data, as: UTF8.self)
    }

    static func execPath(_ pid: Int32) -> String {
        var buf = [CChar](repeating: 0, count: 4096)
        return proc_pidpath(pid, &buf, UInt32(buf.count)) > 0 ? String(cString: buf) : ""
    }

    static func isAppOrSystem(_ path: String) -> Bool {
        if path.isEmpty { return true }
        if path.contains("Docker.app") || path.contains("OrbStack.app") { return false }
        let systemPrefixes = ["/System/", "/usr/libexec/", "/usr/sbin/", "/Library/Apple/"]
        if systemPrefixes.contains(where: path.hasPrefix) { return true }
        let appRoots = ["/Applications/", home + "/Applications/"]
        return path.contains(".app/Contents/") && appRoots.contains(where: path.hasPrefix)
    }

    static func scan(includeApps: Bool) -> [ServerGroup] {
        // 1. Listening TCP sockets
        var listeners: [Int32: [Int: Bool]] = [:]
        var current: Int32 = 0
        for line in run("/usr/sbin/lsof", ["-nP", "-iTCP", "-sTCP:LISTEN", "-Fpn"]).split(separator: "\n") {
            let value = line.dropFirst()
            switch line.first {
            case "p": current = Int32(value) ?? 0
            case "n":
                guard let colon = value.lastIndex(of: ":"), let port = Int(value[value.index(after: colon)...])
                else { continue }
                let host = value[..<colon]
                let exposed = host == "*" || host == "0.0.0.0" || host == "[::]"
                listeners[current, default: [:]][port] = (listeners[current]?[port] ?? false) || exposed
            default: break
            }
        }
        listeners.removeValue(forKey: getpid())
        if listeners.isEmpty { return [] }

        // 2. Process tree and arguments
        var parent: [Int32: Int32] = [:]
        var argsByPid: [Int32: String] = [:]
        var elapsedByPid: [Int32: String] = [:]
        for line in run("/bin/ps", ["-axww", "-o", "pid=,ppid=,etime=,args="]).split(separator: "\n") {
            let parts = line.split(separator: " ", maxSplits: 3, omittingEmptySubsequences: true)
            guard parts.count >= 3, let pid = Int32(parts[0]), let ppid = Int32(parts[1]) else { continue }
            parent[pid] = ppid
            elapsedByPid[pid] = String(parts[2])
            argsByPid[pid] = parts.count > 3 ? String(parts[3]) : ""
        }

        // 3. Skip regular apps and system processes
        var procs: [Int32: ServerProcess] = [:]
        for (pid, ports) in listeners {
            let path = execPath(pid)
            if !includeApps && isAppOrSystem(path) { continue }
            procs[pid] = ServerProcess(
                pid: pid, ppid: parent[pid] ?? 0, execPath: path, args: argsByPid[pid] ?? "", cwd: "",
                elapsed: elapsedByPid[pid] ?? "",
                listeners: ports.map { Listener(port: $0.key, exposed: $0.value) }.sorted { $0.port < $1.port })
        }
        if procs.isEmpty { return [] }

        // 4. Working directories
        let pidList = procs.keys.map(String.init).joined(separator: ",")
        current = 0
        for line in run("/usr/sbin/lsof", ["-a", "-d", "cwd", "-p", pidList, "-Fn"]).split(separator: "\n") {
            let value = String(line.dropFirst())
            if line.first == "p" { current = Int32(value) ?? 0 }
            if line.first == "n" { procs[current]?.cwd = value }
        }

        // 5. Group child processes under their top-most listening ancestor
        var grouped: [Int32: [ServerProcess]] = [:]
        for proc in procs.values {
            var root = proc.pid
            var cursor = proc.ppid
            var depth = 0
            while cursor > 1, depth < 64 {
                if procs[cursor] != nil { root = cursor }
                cursor = parent[cursor] ?? 0
                depth += 1
            }
            grouped[root, default: []].append(proc)
        }

        return sorted(grouped.compactMap { rootPid, members -> ServerGroup? in
            guard let root = procs[rootPid] else { return nil }
            return makeGroup(root: root, members: members)
        })
    }

    static func makeGroup(root: ServerProcess, members: [ServerProcess]) -> ServerGroup {
        let (title, detail, folder) = describe(root)
        var merged: [Int: Bool] = [:]
        for m in members { for l in m.listeners { merged[l.port] = (merged[l.port] ?? false) || l.exposed } }
        return ServerGroup(
            id: root.pid, title: title, detail: detail, folder: folder,
            processes: members.sorted { $0.pid < $1.pid },
            listeners: merged.map { Listener(port: $0.key, exposed: $0.value) }.sorted { $0.port < $1.port })
    }

    static func sorted(_ groups: [ServerGroup]) -> [ServerGroup] {
        groups.sorted {
            ($0.title.lowercased(), $0.listeners.first?.port ?? 0) < ($1.title.lowercased(), $1.listeners.first?.port ?? 0)
        }
    }

    // Turns a working directory into a readable project name.
    static func describe(_ p: ServerProcess) -> (title: String, detail: String, folder: String?) {
        let cwd = p.cwd

        // Claude Code scratchpads: /private/tmp/claude-501/-Users-x-Desktop-Project/<session>/scratchpad/...
        if let range = cwd.range(of: #"^(/private)?/tmp/claude-\d+/[^/]+/[^/]+/scratchpad"#, options: .regularExpression) {
            let encoded = cwd[range].split(separator: "/").dropFirst(cwd.hasPrefix("/private") ? 3 : 2).first.map(String.init) ?? ""
            let sub = cwd[range.upperBound...].split(separator: "/").joined(separator: "/")
            return (decodeClaudeProject(encoded), L("Claude scratchpad", "Claude-scratchpad") + (sub.isEmpty ? "" : " · \(sub)"), cwd)
        }

        if cwd.hasPrefix(home + "/") {
            let rel = String(cwd.dropFirst(home.count + 1))
            let comps = rel.split(separator: "/").map(String.init)
            let index = comps.count > 1 && projectContainers.contains(comps[0]) ? 1 : 0
            var name = comps[index]
            if name.hasPrefix(".") { name.removeFirst() }
            return (name, "~/" + rel, cwd)
        }

        // No useful working directory (e.g. "/"): derive a name from the command
        if let r = p.args.range(of: "node_modules/") {
            let pkg = p.args[r.upperBound...].split(separator: "/").prefix(2)
            if let first = pkg.first {
                let name = first.hasPrefix("@") && pkg.count == 2 ? "\(first)/\(pkg.last!)" : String(first)
                return (name, p.args.split(separator: " ").first.map(String.init) ?? p.execName, nil)
            }
        }
        let folder = (cwd.isEmpty || cwd == "/") ? nil : cwd
        return (p.execName.isEmpty ? "pid \(p.pid)" : p.execName, folder ?? p.execPath, folder)
    }

    static func decodeClaudeProject(_ encoded: String) -> String {
        var rest = encoded
        let homeEncoded = home.replacingOccurrences(of: "/", with: "-") + "-"
        if rest.hasPrefix(homeEncoded) { rest.removeFirst(homeEncoded.count) }
        for container in projectContainers where rest.hasPrefix(container + "-") {
            rest.removeFirst(container.count + 1)
            break
        }
        return rest.isEmpty ? encoded : rest
    }

    static func isHTTP(_ listener: Listener, in group: ServerGroup) -> Bool {
        if nonHTTPPorts.contains(listener.port) { return false }
        let owner = group.processes.first { $0.listeners.contains { $0.port == listener.port } }
        return !nonHTTPExecs.contains(owner?.execName ?? "")
    }

    static func lanAddress() -> String? {
        var ifaddr: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&ifaddr) == 0, let first = ifaddr else { return nil }
        defer { freeifaddrs(ifaddr) }
        var candidates: [String: String] = [:]
        for ptr in sequence(first: first, next: { $0.pointee.ifa_next }) {
            let iface = ptr.pointee
            guard let addr = iface.ifa_addr, addr.pointee.sa_family == UInt8(AF_INET) else { continue }
            let name = String(cString: iface.ifa_name)
            guard name.hasPrefix("en") else { continue }
            var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            getnameinfo(addr, socklen_t(addr.pointee.sa_len), &host, socklen_t(host.count), nil, 0, NI_NUMERICHOST)
            candidates[name] = String(cString: host)
        }
        return candidates.keys.sorted().first.flatMap { candidates[$0] }
    }

    // "1-02:03:11" → "1d 2h", "02:03:11" → "2h 3m", "03:11" → "3m"
    static func formatElapsed(_ etime: String) -> String {
        let dayParts = etime.split(separator: "-")
        let days = dayParts.count == 2 ? Int(dayParts[0]) ?? 0 : 0
        let clock = (dayParts.last ?? "").split(separator: ":").compactMap { Int($0) }
        let (h, m) = clock.count == 3 ? (clock[0], clock[1]) : (0, clock.first ?? 0)
        let hour = L("h", "u")
        if days > 0 { return "\(days)d \(h)\(hour)" }
        if h > 0 { return "\(h)\(hour) \(m)m" }
        return m > 0 ? "\(m)m" : "<1m"
    }
}

// MARK: - Demo data (`--demo`), for screenshots and trying the UI

enum Demo {
    static func groups() -> [ServerGroup] {
        func proc(_ pid: Int32, _ exec: String, _ cwd: String, _ elapsed: String, _ ports: [(Int, Bool)], args: String = "") -> ServerProcess {
            ServerProcess(pid: pid, ppid: 1, execPath: exec, args: args, cwd: cwd, elapsed: elapsed,
                          listeners: ports.map { Listener(port: $0.0, exposed: $0.1) })
        }
        let h = Scanner.home
        let node = "/opt/homebrew/bin/node"
        let groups: [[ServerProcess]] = [
            [proc(41210, node, "\(h)/Projects/acme-web", "02:14:09", [(3000, true)])],
            [proc(41388, node, "\(h)/Projects/acme-api", "01:52:33", [(8080, false), (9229, false)])],
            [proc(40112, node, "\(h)/Projects/design-system", "1-03:12:00", [(6006, false)])],
            [proc(43007, node, "\(h)/Projects/docs", "18:40", [(5173, false)])],
            [proc(44120, "/usr/bin/python3", "/private/tmp/claude-501/\(h.replacingOccurrences(of: "/", with: "-"))-Projects-landing-page/3f2a/scratchpad/site",
                  "04:02", [(8000, false)])],
            [proc(912, "/opt/homebrew/opt/postgresql@17/bin/postgres", "/opt/homebrew/var/postgresql@17", "6-04:10:00", [(5432, false)])],
            [proc(918, "/opt/homebrew/opt/redis/bin/redis-server", "/opt/homebrew/var/db/redis", "6-04:10:02", [(6379, false)])],
        ]
        return Scanner.sorted(groups.map { Scanner.makeGroup(root: $0[0], members: $0) })
    }
}

// MARK: - App

final class AppDelegate: NSObject, NSApplicationDelegate, NSMenuDelegate {
    private let statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
    private let menu = NSMenu()
    private let demo = CommandLine.arguments.contains("--demo")
    private var groups: [ServerGroup] = []
    private var lastSignature = ""
    private var scanning = false
    private var timer: Timer?

    private var includeApps: Bool {
        get { UserDefaults.standard.bool(forKey: "includeApps") }
        set { UserDefaults.standard.set(newValue, forKey: "includeApps") }
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        menu.delegate = self
        menu.autoenablesItems = false
        statusItem.menu = menu
        statusItem.button?.imagePosition = .imageLeading
        updateButton()
        rebuildMenu()
        refresh()
        timer = Timer.scheduledTimer(withTimeInterval: 5, repeats: true) { [weak self] _ in self?.refresh() }
        timer?.tolerance = 1
        if CommandLine.arguments.contains("--open-menu") {
            DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) {
                NSApp.activate(ignoringOtherApps: true)
                self.statusItem.button?.performClick(nil)
            }
        }
    }

    func menuWillOpen(_ menu: NSMenu) {
        rebuildMenu()
        refresh()
    }

    @objc private func refresh() {
        guard !scanning else { return }
        scanning = true
        let includeApps = self.includeApps
        let demo = self.demo
        DispatchQueue.global(qos: .utility).async {
            let result = demo ? Demo.groups() : Scanner.scan(includeApps: includeApps)
            DispatchQueue.main.async {
                self.scanning = false
                self.groups = result
                let signature = result.map(\.signature).joined(separator: ";")
                if signature != self.lastSignature {
                    self.lastSignature = signature
                    self.updateButton()
                    self.rebuildMenu()
                }
            }
        }
    }

    private func updateButton() {
        guard let button = statusItem.button else { return }
        let image = NSImage(systemSymbolName: "server.rack", accessibilityDescription: "Dev servers")
        image?.isTemplate = true
        button.image = image
        button.title = groups.isEmpty ? "" : " \(groups.count)"
        button.appearsDisabled = groups.isEmpty
        button.toolTip = groups.isEmpty
            ? L("No dev servers running", "Geen dev servers actief")
            : groups.map { "\($0.title)  " + $0.listeners.map { ":\($0.port)" }.joined(separator: " ") }.joined(separator: "\n")
    }

    private func rebuildMenu() {
        menu.removeAllItems()

        let count = groups.count
        let header = NSMenuItem(
            title: count == 0 ? L("No dev servers running", "Geen dev servers actief")
                : L("\(count) dev server\(count == 1 ? "" : "s") running",
                    "\(count) dev server\(count == 1 ? "" : "s") actief"),
            action: nil, keyEquivalent: "")
        header.isEnabled = false
        menu.addItem(header)
        if count > 0 { menu.addItem(.separator()) }

        let lan = demo ? "192.168.1.20" : Scanner.lanAddress()
        for group in groups {
            let item = NSMenuItem(title: group.title, action: nil, keyEquivalent: "")
            let title = NSMutableAttributedString(
                string: "● ", attributes: [.font: NSFont.menuFont(ofSize: 0),
                                           .foregroundColor: group.exposed ? NSColor.systemOrange : NSColor.systemGreen])
            title.append(NSAttributedString(string: group.title, attributes: [.font: NSFont.menuFont(ofSize: 0)]))
            let ports = "   " + group.listeners.map { ":\($0.port)" }.joined(separator: " ")
            title.append(NSAttributedString(
                string: ports,
                attributes: [.font: NSFont.monospacedDigitSystemFont(ofSize: NSFont.systemFontSize - 1, weight: .regular),
                             .foregroundColor: NSColor.secondaryLabelColor]))
            item.attributedTitle = title
            item.toolTip = group.exposed
                ? L("Reachable from your network", "Bereikbaar via het netwerk")
                : L("Local only", "Alleen lokaal bereikbaar")
            item.submenu = submenu(for: group, lan: lan)
            menu.addItem(item)
        }

        menu.addItem(.separator())
        let appsItem = NSMenuItem(title: L("Show apps too", "Toon ook apps"), action: #selector(toggleApps), keyEquivalent: "")
        appsItem.state = includeApps ? .on : .off
        appsItem.target = self
        menu.addItem(appsItem)

        let loginItem = NSMenuItem(title: L("Launch at login", "Open bij inloggen"), action: #selector(toggleLogin), keyEquivalent: "")
        loginItem.state = SMAppService.mainApp.status == .enabled ? .on : .off
        loginItem.target = self
        menu.addItem(loginItem)

        menu.addItem(.separator())
        menu.addItem(withTitle: L("Quit iServer", "Stop iServer"), action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
    }

    private func submenu(for group: ServerGroup, lan: String?) -> NSMenu {
        let sub = NSMenu()
        sub.autoenablesItems = false

        let info = NSMenuItem(title: group.detail, action: nil, keyEquivalent: "")
        info.isEnabled = false
        sub.addItem(info)
        sub.addItem(.separator())

        for listener in group.listeners {
            if Scanner.isHTTP(listener, in: group) {
                sub.addItem(actionItem(L("Open", "Open") + " http://localhost:\(listener.port)", #selector(openURL(_:)),
                                       "http://localhost:\(listener.port)", symbol: "safari"))
                if listener.exposed, let lan {
                    sub.addItem(actionItem(L("Open", "Open") + " http://\(lan):\(listener.port)  " + L("(network)", "(netwerk)"),
                                           #selector(openURL(_:)), "http://\(lan):\(listener.port)", symbol: "network"))
                }
            } else {
                sub.addItem(actionItem(L("Copy", "Kopieer") + " localhost:\(listener.port)", #selector(copyText(_:)),
                                       "localhost:\(listener.port)", symbol: "doc.on.doc"))
            }
        }

        sub.addItem(.separator())
        for proc in group.processes.prefix(12) {
            let ports = proc.listeners.map { ":\($0.port)" }.joined(separator: " ")
            let line = NSMenuItem(
                title: "\(proc.execName)  ·  pid \(proc.pid)  ·  \(Scanner.formatElapsed(proc.elapsed))  ·  \(ports)",
                action: nil, keyEquivalent: "")
            line.isEnabled = false
            line.toolTip = proc.args
            sub.addItem(line)
        }
        if group.processes.count > 12 {
            let rest = group.processes.count - 12
            let more = NSMenuItem(title: L("… and \(rest) more processes", "… en nog \(rest) processen"), action: nil, keyEquivalent: "")
            more.isEnabled = false
            sub.addItem(more)
        }

        sub.addItem(.separator())
        if let folder = group.folder {
            sub.addItem(actionItem(L("Show in Finder", "Toon in Finder"), #selector(revealFolder(_:)), folder, symbol: "folder"))
            sub.addItem(actionItem(L("Open Terminal here", "Open Terminal hier"), #selector(openTerminal(_:)), folder, symbol: "terminal"))
        }
        sub.addItem(actionItem(L("Stop server…", "Stop server…"), #selector(stopGroup(_:)), String(group.id), symbol: "stop.circle"))
        return sub
    }

    private func actionItem(_ title: String, _ action: Selector, _ payload: String, symbol: String) -> NSMenuItem {
        let item = NSMenuItem(title: title, action: action, keyEquivalent: "")
        item.target = self
        item.representedObject = payload
        item.image = NSImage(systemSymbolName: symbol, accessibilityDescription: nil)
        return item
    }

    // MARK: Actions

    @objc private func openURL(_ sender: NSMenuItem) {
        guard let s = sender.representedObject as? String, let url = URL(string: s) else { return }
        NSWorkspace.shared.open(url)
    }

    @objc private func copyText(_ sender: NSMenuItem) {
        guard let s = sender.representedObject as? String else { return }
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(s, forType: .string)
    }

    @objc private func revealFolder(_ sender: NSMenuItem) {
        guard let path = sender.representedObject as? String else { return }
        NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: path)])
    }

    @objc private func openTerminal(_ sender: NSMenuItem) {
        guard let path = sender.representedObject as? String,
              let terminal = NSWorkspace.shared.urlForApplication(withBundleIdentifier: "com.apple.Terminal")
        else { return }
        NSWorkspace.shared.open([URL(fileURLWithPath: path)], withApplicationAt: terminal,
                                configuration: NSWorkspace.OpenConfiguration())
    }

    @objc private func stopGroup(_ sender: NSMenuItem) {
        guard let idString = sender.representedObject as? String, let id = Int32(idString),
              let group = groups.first(where: { $0.id == id }) else { return }
        let n = group.processes.count
        let list = group.processes.prefix(6).map { "\($0.execName) \($0.pid)" }.joined(separator: ", ") + (n > 6 ? ", …" : "")
        let alert = NSAlert()
        alert.messageText = L("Stop \(group.title)?", "\(group.title) stoppen?")
        alert.informativeText = L("Sends SIGTERM to \(n) process\(n == 1 ? "" : "es") (\(list)).",
                                  "Stuurt SIGTERM naar \(n) proces\(n == 1 ? "" : "sen") (\(list)).")
        alert.addButton(withTitle: L("Stop", "Stop"))
        alert.addButton(withTitle: L("Cancel", "Annuleer"))
        NSApp.activate(ignoringOtherApps: true)
        guard alert.runModal() == .alertFirstButtonReturn, !demo else { return }
        for proc in group.processes { kill(proc.pid, SIGTERM) }
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) { self.refresh() }
    }

    @objc private func toggleApps() {
        includeApps.toggle()
        lastSignature = ""
        refresh()
    }

    @objc private func toggleLogin() {
        do {
            if SMAppService.mainApp.status == .enabled {
                try SMAppService.mainApp.unregister()
            } else {
                try SMAppService.mainApp.register()
            }
        } catch {
            let alert = NSAlert(error: error)
            NSApp.activate(ignoringOtherApps: true)
            alert.runModal()
        }
        rebuildMenu()
    }
}

// `iServer --list [--all]` prints the detected servers without showing a menu bar icon.
if CommandLine.arguments.contains("--list") {
    let groups = CommandLine.arguments.contains("--demo")
        ? Demo.groups() : Scanner.scan(includeApps: CommandLine.arguments.contains("--all"))
    for g in groups {
        print("\(g.exposed ? "🟠" : "🟢") \(g.title)  " + g.listeners.map { ":\($0.port)\($0.exposed ? "*" : "")" }.joined(separator: " "))
        print("   \(g.detail)")
        for p in g.processes { print("   - \(p.execName) pid \(p.pid) · \(Scanner.formatElapsed(p.elapsed))") }
    }
    exit(0)
}

let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
app.setActivationPolicy(.accessory)
app.run()
