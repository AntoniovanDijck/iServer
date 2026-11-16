// iServer — a menu bar app that shows which development servers are running on your Mac.
import AppKit
import CryptoKit
import Darwin
import IOKit
import IOKit.ps
import IOKit.pwr_mgt
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
    var cpu: Double
    var rss: UInt64
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
    var cpu: Double { processes.reduce(0) { $0 + $1.cpu } }
    var rss: UInt64 { processes.reduce(0) { $0 + $1.rss } }

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
        var cpuByPid: [Int32: Double] = [:]
        var rssByPid: [Int32: UInt64] = [:]
        for line in run("/bin/ps", ["-axww", "-o", "pid=,ppid=,etime=,%cpu=,rss=,args="]).split(separator: "\n") {
            let parts = line.split(separator: " ", maxSplits: 5, omittingEmptySubsequences: true)
            guard parts.count >= 5, let pid = Int32(parts[0]), let ppid = Int32(parts[1]) else { continue }
            parent[pid] = ppid
            elapsedByPid[pid] = String(parts[2])
            cpuByPid[pid] = Double(parts[3]) ?? 0
            rssByPid[pid] = (UInt64(parts[4]) ?? 0) * 1024
            argsByPid[pid] = parts.count > 5 ? String(parts[5]) : ""
        }

        // 3. Skip regular apps and system processes
        var procs: [Int32: ServerProcess] = [:]
        for (pid, ports) in listeners {
            let path = execPath(pid)
            if !includeApps && isAppOrSystem(path) { continue }
            procs[pid] = ServerProcess(
                pid: pid, ppid: parent[pid] ?? 0, execPath: path, args: argsByPid[pid] ?? "", cwd: "",
                elapsed: elapsedByPid[pid] ?? "", cpu: cpuByPid[pid] ?? 0, rss: rssByPid[pid] ?? 0,
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

    static func formatCPU(_ value: Double) -> String {
        value >= 10 ? String(format: "%.0f%%", value) : String(format: "%.1f%%", value)
    }

    static func formatBytes(_ bytes: UInt64) -> String {
        let mb = Double(bytes) / 1_048_576
        if mb >= 1024 { return String(format: "%.1fG", mb / 1024) }
        if mb >= 10 { return String(format: "%.0fM", mb) }
        if mb >= 1 { return String(format: "%.1fM", mb) }
        return String(format: "%.0fK", Double(bytes) / 1024)
    }

    static func bar(_ fraction: Double, slots: Int = 8) -> String {
        let filled = min(slots, max(0, Int((min(1, max(0, fraction)) * Double(slots)).rounded())))
        return "[" + String(repeating: "#", count: filled) + String(repeating: "-", count: slots - filled) + "]"
    }
}

struct Vitals {
    var cpu: Double
    var gpu: Double
    var used: UInt64
    var total: UInt64

    static let empty = Vitals(cpu: 0, gpu: 0, used: 0, total: ProcessInfo.processInfo.physicalMemory)
    // Sampling happens from several background queues; the tick baseline is shared, so guard it.
    private static let lock = NSLock()
    private static var previousTicks: (UInt32, UInt32, UInt32, UInt32)?
    private static var lastLoad = 0.0

    private static func cpuTicks() -> (UInt32, UInt32, UInt32, UInt32)? {
        var info = host_cpu_load_info()
        var count = mach_msg_type_number_t(MemoryLayout<host_cpu_load_info_data_t>.stride / MemoryLayout<integer_t>.stride)
        let result: kern_return_t = withUnsafeMutablePointer(to: &info) {
            $0.withMemoryRebound(to: integer_t.self, capacity: Int(count)) {
                host_statistics(mach_host_self(), HOST_CPU_LOAD_INFO, $0, &count)
            }
        }
        guard result == KERN_SUCCESS else { return nil }
        let t = info.cpu_ticks
        return (t.0, t.1, t.2, t.3)
    }

    static func cpuLoad() -> Double {
        lock.lock()
        defer { lock.unlock() }
        if previousTicks == nil {
            previousTicks = cpuTicks()
            usleep(200_000)
        }
        guard let previous = previousTicks, let now = cpuTicks() else { return lastLoad }
        let user = Double(now.0 &- previous.0)
        let system = Double(now.1 &- previous.1)
        let idle = Double(now.2 &- previous.2)
        let nice = Double(now.3 &- previous.3)
        let total = user + system + idle + nice
        // Several callers sample this (menu bar, panel, chart). If the last sample was only moments ago
        // the window is too short to mean anything, so repeat the last reading.
        guard total >= 100 else { return lastLoad }
        previousTicks = now
        lastLoad = (user + system + nice) / total * 100
        return lastLoad
    }

    static func sample() -> Vitals {
        let cpu = cpuLoad()

        var vm = vm_statistics64()
        var vmCount = mach_msg_type_number_t(MemoryLayout<vm_statistics64_data_t>.stride / MemoryLayout<integer_t>.stride)
        let memResult: kern_return_t = withUnsafeMutablePointer(to: &vm) {
            $0.withMemoryRebound(to: integer_t.self, capacity: Int(vmCount)) {
                host_statistics64(mach_host_self(), HOST_VM_INFO64, $0, &vmCount)
            }
        }
        let total = ProcessInfo.processInfo.physicalMemory
        var used: UInt64 = 0
        if memResult == KERN_SUCCESS {
            let pages = UInt64(vm.active_count) + UInt64(vm.wire_count) + UInt64(vm.compressor_page_count)
            used = min(total, pages * UInt64(vm_kernel_page_size))
        }
        return Vitals(cpu: cpu, gpu: gpuUtilization(), used: used, total: total)
    }

    // Device Utilization % from the GPU accelerator. Same figure Activity Monitor shows.
    private static func gpuUtilization() -> Double {
        var iterator: io_iterator_t = 0
        guard IOServiceGetMatchingServices(kIOMainPortDefault, IOServiceMatching("IOAccelerator"), &iterator) == KERN_SUCCESS else { return 0 }
        defer { IOObjectRelease(iterator) }
        var peak = 0.0
        while case let service = IOIteratorNext(iterator), service != 0 {
            defer { IOObjectRelease(service) }
            var raw: Unmanaged<CFMutableDictionary>?
            guard IORegistryEntryCreateCFProperties(service, &raw, kCFAllocatorDefault, 0) == KERN_SUCCESS,
                  let props = raw?.takeRetainedValue() as? [String: Any],
                  let stats = props["PerformanceStatistics"] as? [String: Any] else { continue }
            peak = max(peak, percent(stats["Device Utilization %"]), percent(stats["Renderer Utilization %"]))
        }
        return min(100, peak)
    }

    static func fraction(of vitals: Vitals) -> (cpu: Double, gpu: Double, mem: Double) {
        let mem = vitals.total > 0 ? Double(vitals.used) / Double(vitals.total) : 0
        return (min(1, vitals.cpu / 100), min(1, vitals.gpu / 100), min(1, mem))
    }

    private static func percent(_ value: Any?) -> Double {
        if let number = value as? NSNumber { return number.doubleValue }
        if let number = value as? Double { return number }
        if let number = value as? Int { return Double(number) }
        return 0
    }
}

struct Trace {
    var cpu: [Double] = []
    var gpu: [Double] = []
    var mem: [Double] = []
    static let capacity = 48

    mutating func push(_ sample: (cpu: Double, gpu: Double, mem: Double)) {
        cpu.append(min(1, max(0, sample.cpu)))
        gpu.append(min(1, max(0, sample.gpu)))
        mem.append(min(1, max(0, sample.mem)))
        if cpu.count > Trace.capacity {
            cpu.removeFirst(cpu.count - Trace.capacity)
            gpu.removeFirst(gpu.count - Trace.capacity)
            mem.removeFirst(mem.count - Trace.capacity)
        }
    }
}

struct DiskVolume {
    var name: String
    var used: UInt64
    var total: UInt64

    var free: UInt64 { total > used ? total - used : 0 }
    var fraction: Double { total > 0 ? Double(used) / Double(total) : 0 }
}

enum Disks {
    static func mounted() -> [DiskVolume] {
        let keys: Set<URLResourceKey> = [
            .volumeNameKey, .volumeTotalCapacityKey,
            .volumeAvailableCapacityForImportantUsageKey, .volumeIsBrowsableKey,
        ]
        let urls = FileManager.default.mountedVolumeURLs(
            includingResourceValuesForKeys: Array(keys), options: [.skipHiddenVolumes]) ?? []
        var listed: [(String, DiskVolume)] = []
        for url in urls {
            guard let values = try? url.resourceValues(forKeys: keys), values.volumeIsBrowsable != false else { continue }
            let total = UInt64(max(0, values.volumeTotalCapacity ?? 0))
            guard total > 0 else { continue }
            let free = UInt64(max(0, values.volumeAvailableCapacityForImportantUsage ?? Int64(total)))
            let used = total > free ? total - free : 0
            var name = values.volumeName ?? ""
            if name.isEmpty { name = url.path == "/" ? "Macintosh HD" : url.lastPathComponent }
            listed.append((url.path, DiskVolume(name: name, used: used, total: total)))
        }
        return listed.sorted { lhs, rhs in
            if lhs.0 == "/" { return true }
            if rhs.0 == "/" { return false }
            return lhs.1.name.localizedCaseInsensitiveCompare(rhs.1.name) == .orderedAscending
        }.map(\.1)
    }
}

// MARK: - Dev cleanup: find caches and build leftovers, review them, move them to the Trash

enum CleanAction {
    case trash                      // move every path to the Trash (reversible)
    case emptyTrash                 // permanently delete what is in ~/.Trash
    case command(String, [String])  // run a tool, e.g. `docker builder prune` (permanent)
}

enum NoteStyle { case plain, good, danger }

struct CleanItem {
    let id: String
    let title: String
    let detail: String
    let paths: [String]
    var bytes: UInt64
    let preselect: Bool
    var note: String?
    var noteStyle: NoteStyle = .plain
    var age: Int? = nil  // days since last touched (project leftovers, large files)
    let action: CleanAction
    var locked = false   // shown but cannot be selected (a kept duplicate, a running app)

    var permanent: Bool {
        if case .trash = action { return false }
        return true
    }
}

struct CleanGroup {
    let id: String
    let title: String
    let symbol: String
    let color: NSColor
    var items: [CleanItem]
    var iconPath: String? = nil  // app groups show the app's icon
    var note: String? = nil

    // What can be removed; locked items don't count.
    var bytes: UInt64 { items.filter { !$0.locked }.reduce(0) { $0 + $1.bytes } }
    var totalBytes: UInt64 { items.reduce(0) { $0 + $1.bytes } }
}

enum DevClean {
    static let home = NSHomeDirectory()
    static let fm = FileManager.default

    // `running` are the working folders of servers that are up right now; their projects are never preselected.
    // Groups are scanned in parallel; `onGroup` gets each one as soon as it is done (on a background queue).
    static func scan(running: [String], onGroup: @escaping (CleanGroup) -> Void = { _ in }) -> [CleanGroup] {
        let scanners: [() -> CleanGroup] = [packageCaches, xcode, docker, { projects(running: running) }, system]
        var results = [CleanGroup?](repeating: nil, count: scanners.count)
        let lock = NSLock()
        DispatchQueue.concurrentPerform(iterations: scanners.count) { index in
            var group = scanners[index]()
            group.items = group.items.filter { $0.bytes > 0 }.sorted { $0.bytes > $1.bytes }
            lock.lock()
            results[index] = group
            lock.unlock()
            onGroup(group)
        }
        return results.compactMap { $0 }.filter { !$0.items.isEmpty }
    }

    static let order = ["packages", "xcode", "docker", "projects", "system"]

    // MARK: Groups

    static func packageCaches() -> CleanGroup {
        let caches = home + "/Library/Caches"
        let specs: [(String, String, String)] = [
            ("npm", "npm", home + "/.npm/_cacache"),
            ("pnpm", "pnpm store", home + "/Library/pnpm/store"),
            ("pnpm-home", "pnpm store", home + "/.pnpm-store"),
            ("yarn", "Yarn", caches + "/Yarn"),
            ("bun", "Bun", home + "/.bun/install/cache"),
            ("pip", "pip", caches + "/pip"),
            ("uv", "uv", home + "/.cache/uv"),
            ("homebrew", "Homebrew", caches + "/Homebrew"),
            ("cocoapods", "CocoaPods", caches + "/CocoaPods"),
            ("gradle", "Gradle", home + "/.gradle/caches"),
            ("cargo", "Cargo registry", home + "/.cargo/registry/cache"),
            ("go", L("Go build cache", "Go-buildcache"), caches + "/go-build"),
        ]
        let items = sized(specs.compactMap { id, title, path in
            item("pkg." + id, title, path, note: L("re-downloads", "wordt opnieuw gedownload"))
        })
        return CleanGroup(id: "packages", title: L("Package caches", "Pakketcaches"), symbol: "shippingbox.fill",
                          color: .systemBrown, items: items)
    }

    static func xcode() -> CleanGroup {
        let dev = home + "/Library/Developer"
        let items = sized([
            item("xc.derived", "DerivedData", dev + "/Xcode/DerivedData", note: L("rebuilds", "wordt opnieuw gebouwd")),
            item("xc.simcache", L("Simulator caches", "Simulatorcaches"), dev + "/CoreSimulator/Caches"),
            item("xc.ios", "iOS DeviceSupport", dev + "/Xcode/iOS DeviceSupport", preselect: false,
                 note: L("re-copied on connect", "opnieuw bij aansluiten")),
            item("xc.watch", "watchOS DeviceSupport", dev + "/Xcode/watchOS DeviceSupport", preselect: false,
                 note: L("re-copied on connect", "opnieuw bij aansluiten")),
            item("xc.archives", "Archives", dev + "/Xcode/Archives", preselect: false,
                 note: L("your app builds", "je app-builds")),
        ].compactMap { $0 })
        return CleanGroup(id: "xcode", title: "Xcode", symbol: "hammer.fill", color: .systemBlue, items: items)
    }

    static func docker() -> CleanGroup {
        let group = CleanGroup(id: "docker", title: "Docker", symbol: "cube.box.fill", color: .systemTeal, items: [])
        let candidates = ["/opt/homebrew/bin/docker", "/usr/local/bin/docker", home + "/.orbstack/bin/docker",
                          "/Applications/Docker.app/Contents/Resources/bin/docker"]
        guard let docker = candidates.first(where: fm.isExecutableFile) else { return group }
        // Only asks the daemon; if Docker isn't running this fails fast and the group stays empty.
        guard let result = run(docker, ["system", "df", "--format", "{{.Type}}\t{{.Reclaimable}}"], timeout: 8),
              result.status == 0 else { return group }
        // Volumes are left out on purpose: they hold data, not cache.
        let kinds: [String: (String, String, [String])] = [
            "Images": ("docker.images", L("Unused images", "Ongebruikte images"), ["image", "prune", "-af"]),
            "Containers": ("docker.containers", L("Stopped containers", "Gestopte containers"), ["container", "prune", "-f"]),
            "Build Cache": ("docker.build", L("Build cache", "Buildcache"), ["builder", "prune", "-af"]),
        ]
        var items: [CleanItem] = []
        for line in result.output.split(separator: "\n") {
            let parts = line.split(separator: "\t", maxSplits: 1).map(String.init)
            guard parts.count == 2, let kind = kinds[parts[0]] else { continue }
            let amount = parts[1].split(separator: " ").first.map(String.init) ?? ""
            items.append(CleanItem(
                id: kind.0, title: kind.1, detail: "docker " + kind.2.joined(separator: " "), paths: [],
                bytes: parseDockerSize(amount), preselect: false,
                note: L("permanent", "definitief"), noteStyle: .danger, action: .command(docker, kind.2)))
        }
        var filled = group
        filled.items = items
        return filled
    }

    // Folders that tools rebuild, recognised only next to the file that proves what they are.
    static let artifactRules: [(dir: String, markers: [String], preselect: Bool)] = [
        ("node_modules", ["package.json"], true),
        (".next", ["package.json"], true),
        (".nuxt", ["package.json"], true),
        (".svelte-kit", ["package.json"], true),
        (".turbo", ["package.json"], true),
        (".parcel-cache", ["package.json"], true),
        ("target", ["Cargo.toml"], true),
        ("Pods", ["Podfile"], true),
        (".gradle", ["build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts"], true),
        (".venv", ["pyproject.toml", "requirements.txt", "setup.py"], false),
        ("venv", ["pyproject.toml", "requirements.txt", "setup.py"], false),
    ]

    static let staleDays = 30

    static func projects(running: [String]) -> CleanGroup {
        let roots = Scanner.projectContainers.map { home + "/" + $0 }.filter { isDirectory($0) }
        let skip: Set<String> = ["Library", "Applications", ".git", ".Trash"]
        var stack = roots.map { ($0, 0) }
        var seen = Set<String>()
        var visited = 0
        var items: [CleanItem] = []

        while let (dir, depth) = stack.popLast(), visited < 30_000 {
            visited += 1
            guard seen.insert(dir).inserted, let names = try? fm.contentsOfDirectory(atPath: dir) else { continue }
            let present = Set(names)
            let found = artifactRules.filter { present.contains($0.dir) && $0.markers.contains(where: present.contains) }
            if !found.isEmpty {
                let artifacts = Set(found.map(\.dir))
                let days = daysSinceTouched(dir, ignoring: artifacts)
                let active = running.contains { $0 == dir || $0.hasPrefix(dir + "/") }
                let name = (dir as NSString).lastPathComponent
                for rule in found {
                    let path = dir + "/" + rule.dir
                    guard isDirectory(path) else { continue }
                    var item = CleanItem(
                        id: "proj." + path, title: "\(name) · \(rule.dir)", detail: tilde(dir), paths: [path], bytes: 0,
                        preselect: rule.preselect && !active && days >= staleDays,
                        note: active ? L("running", "draait") : "\(days)d", action: .trash)
                    item.age = days
                    if active { item.noteStyle = .good }
                    items.append(item)
                }
            }
            guard depth < 6 else { continue }
            for child in names where !child.hasPrefix(".") && !skip.contains(child) {
                if found.contains(where: { $0.dir == child }) { continue }
                let path = dir + "/" + child
                if isDirectory(path) { stack.append((path, depth + 1)) }
            }
        }
        return CleanGroup(id: "projects", title: L("Project leftovers", "Projectresten"), symbol: "folder.fill.badge.gearshape",
                          color: .systemIndigo, items: sized(items))
    }

    static func system() -> CleanGroup {
        let caches = home + "/Library/Caches"
        // Package-manager caches have their own rows; Apple's and iCloud caches are left alone.
        let claimed: Set<String> = ["Homebrew", "Yarn", "pip", "CocoaPods", "go-build", "CloudKit"]
        let appCaches = children(of: caches).filter {
            let name = ($0 as NSString).lastPathComponent
            return !name.hasPrefix("com.apple.") && !claimed.contains(name)
        }
        var items: [CleanItem] = [
            CleanItem(id: "sys.caches", title: L("App caches", "App-caches"), detail: "~/Library/Caches", paths: appCaches,
                      bytes: 0, preselect: true, note: L("apps rebuild these", "apps maken ze opnieuw"), action: .trash),
            CleanItem(id: "sys.logs", title: L("Logs", "Logs"), detail: "~/Library/Logs", paths: children(of: home + "/Library/Logs"),
                      bytes: 0, preselect: true, action: .trash),
        ]
        let trash = home + "/.Trash"
        if (try? fm.contentsOfDirectory(atPath: trash)) != nil {
            items.append(CleanItem(id: "sys.trash", title: L("Trash", "Prullenmand"), detail: "~/.Trash", paths: [trash],
                                   bytes: 0, preselect: false, note: L("permanent", "definitief"), noteStyle: .danger,
                                   action: .emptyTrash))
        }
        return CleanGroup(id: "system", title: L("System", "Systeem"), symbol: "gearshape.fill", color: .systemGray,
                          items: sized(items))
    }

    // MARK: Cleaning

    struct Outcome {
        var trashed: UInt64 = 0
        var deleted: UInt64 = 0
        var failed: [String] = []
        var cleaned: Set<String> = []  // ids of items that are gone now
    }

    static func clean(_ items: [CleanItem]) -> Outcome {
        var outcome = Outcome()
        for item in items {
            switch item.action {
            case .trash:
                var moved = true
                for path in item.paths where fm.fileExists(atPath: path) {
                    do {
                        try fm.trashItem(at: URL(fileURLWithPath: path), resultingItemURL: nil)
                    } catch {
                        moved = false
                    }
                }
                if moved {
                    outcome.trashed += item.bytes
                    outcome.cleaned.insert(item.id)
                } else {
                    outcome.failed.append(item.title)
                }
            case .emptyTrash:
                var emptied = true
                for path in children(of: home + "/.Trash") {
                    do { try fm.removeItem(atPath: path) } catch { emptied = false }
                }
                if emptied {
                    outcome.deleted += item.bytes
                    outcome.cleaned.insert(item.id)
                } else {
                    outcome.failed.append(item.title)
                }
            case let .command(tool, args):
                if let result = run(tool, args, timeout: 300), result.status == 0 {
                    outcome.deleted += item.bytes
                    outcome.cleaned.insert(item.id)
                } else {
                    outcome.failed.append(item.title)
                }
            }
        }
        return outcome
    }

    // MARK: Helpers

    static func tilde(_ path: String) -> String {
        path.hasPrefix(home) ? "~" + path.dropFirst(home.count) : path
    }

    static func isDirectory(_ path: String) -> Bool {
        let values = try? URL(fileURLWithPath: path).resourceValues(forKeys: [.isDirectoryKey, .isSymbolicLinkKey])
        return values?.isDirectory == true && values?.isSymbolicLink != true
    }

    static func children(of dir: String) -> [String] {
        ((try? fm.contentsOfDirectory(atPath: dir)) ?? []).filter { $0 != ".DS_Store" }.map { dir + "/" + $0 }
    }

    static func item(_ id: String, _ title: String, _ path: String, preselect: Bool = true, note: String? = nil) -> CleanItem? {
        guard fm.fileExists(atPath: path) else { return nil }
        return CleanItem(id: id, title: title, detail: tilde(path), paths: [path], bytes: 0, preselect: preselect,
                         note: note, action: .trash)
    }

    // Fills in sizes, several items at a time.
    static func sized(_ items: [CleanItem]) -> [CleanItem] {
        var out = items
        let lock = NSLock()
        DispatchQueue.concurrentPerform(iterations: items.count) { index in
            let bytes = items[index].paths.reduce(UInt64(0)) { $0 + allocatedSize($1) }
            lock.lock()
            if out[index].bytes == 0 { out[index].bytes = bytes }
            lock.unlock()
        }
        return out
    }

    // Space on disk, like Finder's "on disk" figure. Symbolic links are not followed.
    static func allocatedSize(_ path: String, cancelled: () -> Bool = { false }) -> UInt64 {
        let url = URL(fileURLWithPath: path)
        let keys: [URLResourceKey] = [.isRegularFileKey, .totalFileAllocatedSizeKey, .fileAllocatedSizeKey]
        func size(_ url: URL) -> UInt64 {
            guard let values = try? url.resourceValues(forKeys: Set(keys)), values.isRegularFile == true else { return 0 }
            return UInt64(values.totalFileAllocatedSize ?? values.fileAllocatedSize ?? 0)
        }
        guard isDirectory(path) else { return size(url) }
        guard let enumerator = fm.enumerator(at: url, includingPropertiesForKeys: keys, options: [],
                                             errorHandler: { _, _ in true }) else { return 0 }
        var total: UInt64 = 0
        var count = 0
        for case let child as URL in enumerator {
            total += size(child)
            count += 1
            if count % 2000 == 0, cancelled() { return total }
        }
        return total
    }

    // Days since anything outside the build folders changed, looking two levels deep.
    static func daysSinceTouched(_ dir: String, ignoring artifacts: Set<String>) -> Int {
        var latest = Date.distantPast
        var checked = 0
        func visit(_ path: String, depth: Int) {
            guard let names = try? fm.contentsOfDirectory(atPath: path) else { return }
            for name in names where !artifacts.contains(name) && name != ".git" && name != ".DS_Store" {
                checked += 1
                if checked > 600 { return }
                let child = path + "/" + name
                let url = URL(fileURLWithPath: child)
                if let date = try? url.resourceValues(forKeys: [.contentModificationDateKey]).contentModificationDate, date > latest {
                    latest = date
                }
                if depth < 2, !name.hasPrefix("."), isDirectory(child) { visit(child, depth: depth + 1) }
            }
        }
        visit(dir, depth: 0)
        guard latest != .distantPast else { return 0 }
        return max(0, Int(Date().timeIntervalSince(latest) / 86_400))
    }

    // "1.25GB" → bytes. Docker uses decimal units.
    static func parseDockerSize(_ text: String) -> UInt64 {
        let units: [(String, Double)] = [("TB", 1e12), ("GB", 1e9), ("MB", 1e6), ("kB", 1e3), ("KB", 1e3), ("B", 1)]
        for (unit, factor) in units where text.hasSuffix(unit) {
            return UInt64((Double(text.dropLast(unit.count)) ?? 0) * factor)
        }
        return 0
    }

    // Runs a tool and gives up after `timeout` seconds.
    static func run(_ path: String, _ args: [String], timeout: TimeInterval) -> (status: Int32, output: String)? {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: path)
        process.arguments = args
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice
        let done = DispatchSemaphore(value: 0)
        process.terminationHandler = { _ in done.signal() }
        do { try process.run() } catch { return nil }
        var output = Data()
        let reader = DispatchQueue.global(qos: .utility)
        let readDone = DispatchSemaphore(value: 0)
        reader.async {
            output = pipe.fileHandleForReading.readDataToEndOfFile()
            readDone.signal()
        }
        if done.wait(timeout: .now() + timeout) == .timedOut {
            process.terminate()
            _ = done.wait(timeout: .now() + 2)
            return nil
        }
        _ = readDone.wait(timeout: .now() + 2)
        return (process.terminationStatus, String(decoding: output, as: UTF8.self))
    }
}

// MARK: - Storage tools: large & old files, duplicates, apps and their leftovers

enum StorageTools {
    static let home = NSHomeDirectory()
    static let fm = FileManager.default
    static let skipFolders: Set<String> = ["node_modules", ".git", "Library", ".Trash"]

    static var userFolders: [String] {
        ["Downloads", "Desktop", "Documents", "Movies", "Music", "Pictures"].map { home + "/" + $0 }.filter(DevClean.isDirectory)
    }

    struct FileInfo {
        let path: String
        let size: UInt64
        let modified: Date
        let created: Date
    }

    // Walks the user folders. Packages (apps, the Photos library) count as one item and are not entered;
    // symbolic links, build folders and files that only live in iCloud (no local data) are skipped.
    static func walk(minSize: UInt64, _ body: (FileInfo) -> Void) {
        let keys: [URLResourceKey] = [.isRegularFileKey, .isSymbolicLinkKey, .totalFileAllocatedSizeKey, .fileAllocatedSizeKey,
                                      .contentModificationDateKey, .creationDateKey]
        for root in userFolders {
            guard let enumerator = fm.enumerator(at: URL(fileURLWithPath: root), includingPropertiesForKeys: keys,
                                                 options: [.skipsPackageDescendants], errorHandler: { _, _ in true }) else { continue }
            for case let url as URL in enumerator {
                if skipFolders.contains(url.lastPathComponent) {
                    enumerator.skipDescendants()
                    continue
                }
                guard let values = try? url.resourceValues(forKeys: Set(keys)),
                      values.isRegularFile == true, values.isSymbolicLink != true else { continue }
                let size = UInt64(values.totalFileAllocatedSize ?? values.fileAllocatedSize ?? 0)
                guard size >= minSize else { continue }
                // An iCloud file that isn't fully on this Mac would be downloaded (or block) when read.
                // Asked only for files that pass the size check, because the iCloud lookup is slow.
                if let cloud = try? url.resourceValues(forKeys: [.isUbiquitousItemKey, .ubiquitousItemDownloadingStatusKey]),
                   cloud.isUbiquitousItem == true, cloud.ubiquitousItemDownloadingStatus != .current { continue }
                body(FileInfo(path: url.path, size: size, modified: values.contentModificationDate ?? .distantPast,
                              created: values.creationDate ?? .distantPast))
            }
        }
    }

    static func ageText(_ days: Int) -> String {
        days >= 730 ? "\(days / 365)" + L("y", "j") : "\(days)d"
    }

    // MARK: Large & old files

    static func largeFiles() -> [CleanGroup] {
        let now = Date()
        var items: [CleanItem] = []
        walk(minSize: 10_000_000) { file in
            let days = max(0, Int(now.timeIntervalSince(file.modified) / 86_400))
            guard file.size >= 100_000_000 || days >= 365, items.count < 3000 else { return }
            var item = CleanItem(
                id: "large." + file.path, title: (file.path as NSString).lastPathComponent,
                detail: DevClean.tilde((file.path as NSString).deletingLastPathComponent), paths: [file.path],
                bytes: file.size, preselect: false, note: ageText(days), action: .trash)
            item.age = days
            items.append(item)
        }
        guard !items.isEmpty else { return [] }
        return [CleanGroup(id: "large", title: L("Large & old files", "Grote en oude bestanden"), symbol: "doc.fill",
                           color: .systemOrange, items: items.sorted { $0.bytes > $1.bytes })]
    }

    // MARK: Duplicates

    // Same size, then the same samples (start, middle, end), then the same SHA-256 of the whole file.
    // Hard links are one file. In every set the oldest copy is kept and cannot be selected.
    // Sets are reported through `onGroup` as soon as they are found; size buckets are checked in parallel.
    static func duplicates(onGroup: @escaping (CleanGroup) -> Void = { _ in }) -> [CleanGroup] {
        var bySize: [UInt64: [FileInfo]] = [:]
        walk(minSize: 1_000_000) { bySize[$0.size, default: []].append($0) }
        let buckets: [[FileInfo]] = bySize.values.compactMap { files in
            guard files.count > 1 else { return nil }
            var inodes = Set<UInt64>()
            let unique = files.filter { inodes.insert(inode($0.path)).inserted }
            return unique.count > 1 ? unique : nil
        }
        var groups: [CleanGroup] = []
        let lock = NSLock()
        DispatchQueue.concurrentPerform(iterations: buckets.count) { index in
            lock.lock()
            let full = groups.count >= 300
            lock.unlock()
            guard !full else { return }
            for (sample, sameSample) in Dictionary(grouping: buckets[index], by: { samples($0.path, size: $0.size) ?? "" })
            where !sample.isEmpty && sameSample.count > 1 {
                for (digest, same) in Dictionary(grouping: sameSample, by: { hash($0.path, limit: nil) ?? "" })
                where !digest.isEmpty && same.count > 1 {
                    let group = duplicateGroup(digest, same)
                    lock.lock()
                    groups.append(group)
                    lock.unlock()
                    onGroup(group)
                }
            }
        }
        return groups.sorted { $0.bytes > $1.bytes }
    }

    static func duplicateGroup(_ digest: String, _ files: [FileInfo]) -> CleanGroup {
        let sorted = files.sorted { $0.created < $1.created }
        let items = sorted.enumerated().map { index, file -> CleanItem in
            var item = CleanItem(
                id: "dup." + file.path, title: (file.path as NSString).lastPathComponent,
                detail: DevClean.tilde((file.path as NSString).deletingLastPathComponent), paths: [file.path],
                bytes: file.size, preselect: false, note: index == 0 ? L("kept", "blijft") : L("copy", "kopie"),
                action: .trash)
            if index == 0 {
                item.locked = true
                item.noteStyle = .good
            }
            return item
        }
        return CleanGroup(id: "dup." + digest, title: items[0].title, symbol: "doc.on.doc.fill", color: .systemPink, items: items)
    }

    // Hash of 64 KB at the start, middle and end: cheap, and rules out most same-size files.
    static func samples(_ path: String, size: UInt64) -> String? {
        guard let handle = FileHandle(forReadingAtPath: path) else { return nil }
        defer { try? handle.close() }
        var hasher = SHA256()
        let chunk = 65_536
        for offset in [0, size / 2, size > UInt64(chunk) ? size - UInt64(chunk) : 0] {
            guard (try? handle.seek(toOffset: offset)) != nil, let data = try? handle.read(upToCount: chunk) else { return nil }
            hasher.update(data: data)
        }
        return hasher.finalize().map { String(format: "%02x", $0) }.joined()
    }

    static func inode(_ path: String) -> UInt64 {
        var info = stat()
        return lstat(path, &info) == 0 ? UInt64(info.st_ino) : UInt64.random(in: 1...UInt64.max)
    }

    static func hash(_ path: String, limit: Int?) -> String? {
        guard let handle = FileHandle(forReadingAtPath: path) else { return nil }
        defer { try? handle.close() }
        var hasher = SHA256()
        var remaining = limit ?? Int.max
        while remaining > 0 {
            guard let chunk = try? handle.read(upToCount: min(1 << 20, remaining)), !chunk.isEmpty else { break }
            hasher.update(data: chunk)
            remaining -= chunk.count
        }
        return hasher.finalize().map { String(format: "%02x", $0) }.joined()
    }

    // MARK: Apps and leftovers

    // One group per app: the app itself plus the files it keeps in ~/Library. Apple's apps are left out.
    // Apps that are running are shown but locked. A last group lists files of apps that are gone.
    static func apps(running: Set<String>) -> [CleanGroup] {
        var groups: [CleanGroup] = []
        var installed = Set<String>()
        for appPath in appBundles() {
            guard let bundle = Bundle(path: appPath), let id = bundle.bundleIdentifier else { continue }
            installed.insert(id)
            guard !id.hasPrefix("com.apple.") else { continue }
            let display = ((appPath as NSString).lastPathComponent as NSString).deletingPathExtension
            let name = bundle.object(forInfoDictionaryKey: "CFBundleName") as? String ?? display
            var items = [CleanItem(id: "app." + appPath, title: display, detail: DevClean.tilde(appPath), paths: [appPath],
                                   bytes: 0, preselect: false, note: L("app", "app"), action: .trash)]
            for path in leftovers(id: id, names: [name, display]) {
                let relative = path.hasPrefix(home + "/Library/") ? String(path.dropFirst(home.count + 9)) : DevClean.tilde(path)
                items.append(CleanItem(id: "app." + path, title: relative, detail: DevClean.tilde((path as NSString).deletingLastPathComponent),
                                       paths: [path], bytes: 0, preselect: false, action: .trash))
            }
            let isRunning = running.contains(id)
            if isRunning {
                items = items.map {
                    var item = $0
                    item.locked = true
                    return item
                }
            }
            var group = CleanGroup(id: "app." + id, title: display, symbol: "app.fill", color: .systemGray, items: DevClean.sized(items))
            group.iconPath = appPath
            group.note = isRunning ? L("running, quit it first", "draait, sluit hem eerst af") : nil
            groups.append(group)
        }
        groups.sort { $0.totalBytes > $1.totalBytes }
        installed.formUnion(otherInstalledIDs())
        if let orphans = orphans(installed: installed) { groups.append(orphans) }
        return groups
    }

    static func appBundles() -> [String] {
        var out: [String] = []
        for dir in ["/Applications", home + "/Applications"] {
            for path in DevClean.children(of: dir) {
                if path.hasSuffix(".app") {
                    out.append(path)
                } else if DevClean.isDirectory(path) {
                    out += DevClean.children(of: path).filter { $0.hasSuffix(".app") }
                }
            }
        }
        return out
    }

    // Apps anywhere on disk (Spotlight), so leftovers of apps that live elsewhere aren't called orphans.
    static func otherInstalledIDs() -> Set<String> {
        var ids = Set<String>()
        for dir in ["/System/Applications", "/System/Applications/Utilities"] {
            for path in DevClean.children(of: dir) where path.hasSuffix(".app") {
                if let id = Bundle(path: path)?.bundleIdentifier { ids.insert(id) }
            }
        }
        if let result = DevClean.run("/usr/bin/mdfind", ["kMDItemContentType == 'com.apple.application-bundle'"], timeout: 15) {
            for line in result.output.split(separator: "\n") {
                if let id = Bundle(path: String(line))?.bundleIdentifier { ids.insert(id) }
            }
        }
        return ids
    }

    static func leftovers(id: String, names: [String]) -> [String] {
        let lib = home + "/Library/"
        var candidates = [
            "Application Support/\(id)", "Caches/\(id)", "Containers/\(id)", "Preferences/\(id).plist",
            "Saved Application State/\(id).savedState", "HTTPStorages/\(id)", "HTTPStorages/\(id).binarycookies",
            "WebKit/\(id)", "Cookies/\(id).binarycookies", "Application Scripts/\(id)", "Logs/\(id)", "LaunchAgents/\(id).plist",
        ]
        for name in Set(names) where name.count >= 3 {
            candidates += ["Application Support/\(name)", "Caches/\(name)", "Logs/\(name)"]
        }
        var found = candidates.map { lib + $0 }.filter { fm.fileExists(atPath: $0) }
        for dir in ["Group Containers", "LaunchAgents"] {
            found += DevClean.children(of: lib + dir).filter {
                let name = ($0 as NSString).lastPathComponent
                return name.hasSuffix("." + id) || name.hasPrefix(id + ".")
            }
        }
        var seen = Set<String>()
        return found.filter { seen.insert($0).inserted }
    }

    // Folders named like a bundle id ("com.vendor.app") whose vendor has no app installed at all.
    // Matching by vendor is deliberately cautious; everything here still needs a human look.
    static func orphans(installed: Set<String>) -> CleanGroup? {
        let vendors = Set(installed.map(vendor))
        let lib = home + "/Library/"
        var items: [CleanItem] = []
        for dir in ["Application Support", "Caches", "Containers", "Saved Application State", "HTTPStorages", "WebKit",
                    "Preferences", "Logs"] {
            for path in DevClean.children(of: lib + dir) {
                var id = (path as NSString).lastPathComponent
                for suffix in [".plist", ".savedState", ".binarycookies"] where id.hasSuffix(suffix) { id.removeLast(suffix.count) }
                guard looksLikeBundleID(id), !id.lowercased().hasPrefix("com.apple."), !vendors.contains(vendor(id)) else { continue }
                items.append(CleanItem(id: "orphan." + path, title: id, detail: "~/Library/" + dir, paths: [path], bytes: 0,
                                       preselect: false, note: L("check", "controleer"), action: .trash))
            }
        }
        let sized = DevClean.sized(items).filter { $0.bytes > 0 }.sorted { $0.bytes > $1.bytes }
        guard !sized.isEmpty else { return nil }
        return CleanGroup(id: "orphans", title: L("Leftovers of removed apps", "Resten van verwijderde apps"),
                          symbol: "questionmark.folder.fill", color: .systemBrown, items: sized)
    }

    static func vendor(_ id: String) -> String {
        id.lowercased().split(separator: ".").prefix(2).joined(separator: ".")
    }

    static func looksLikeBundleID(_ text: String) -> Bool {
        let parts = text.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count >= 3, (2...6).contains(parts[0].count), parts[0].allSatisfy(\.isLetter) else { return false }
        return parts.allSatisfy { !$0.isEmpty && $0.allSatisfy { $0.isLetter || $0.isNumber || $0 == "-" || $0 == "_" } }
    }
}

// MARK: - Stay awake (like KeepingYouAwake): a power assertion that keeps the Mac and display awake

enum Awake {
    private static var assertion: IOPMAssertionID = 0
    static var isOn: Bool { assertion != 0 }

    // macOS drops the assertion by itself when iServer quits.
    @discardableResult
    static func set(_ on: Bool) -> Bool {
        if on, assertion == 0 {
            var id: IOPMAssertionID = 0
            let result = IOPMAssertionCreateWithName(kIOPMAssertionTypePreventUserIdleDisplaySleep as CFString,
                                                     IOPMAssertionLevel(kIOPMAssertionLevelOn),
                                                     "iServer: Stay awake" as CFString, &id)
            if result == kIOReturnSuccess { assertion = id }
        } else if !on, assertion != 0 {
            IOPMAssertionRelease(assertion)
            assertion = 0
        }
        return isOn
    }
}

// MARK: - Apps and processes, battery and thermals (Activity tab)

struct AppUsage {
    let id: String          // app bundle path, or the executable path of a plain process
    let name: String
    let bundlePath: String?
    var pids: [Int32] = []
    var cpu = 0.0
    var rss: UInt64 = 0
    var owned = true        // every process runs as you, so it can be quit from here
}

enum ProcessMonitor {
    // One entry per app (helpers and renderers counted under the app they live in) or per executable.
    static func sample() -> [AppUsage] {
        let me = getuid()
        let own = getpid()
        var usage: [String: AppUsage] = [:]
        for line in Scanner.run("/bin/ps", ["-axww", "-o", "pid=,uid=,%cpu=,rss=,comm="]).split(separator: "\n") {
            let parts = line.split(separator: " ", maxSplits: 4, omittingEmptySubsequences: true)
            guard parts.count == 5, let pid = Int32(parts[0]), let uid = UInt32(parts[1]) else { continue }
            let path = String(parts[4])
            var entry = usage[key(path)] ?? identity(path)
            entry.pids.append(pid)
            entry.cpu += Double(parts[2]) ?? 0
            entry.rss += (UInt64(parts[3]) ?? 0) * 1024
            if uid != me || pid == own { entry.owned = false }
            usage[entry.id] = entry
        }
        return Array(usage.values)
    }

    static func key(_ path: String) -> String {
        guard let range = path.range(of: ".app/") else { return path }
        return String(path[..<range.lowerBound]) + ".app"
    }

    static func identity(_ path: String) -> AppUsage {
        let id = key(path)
        if id.hasSuffix(".app") {
            return AppUsage(id: id, name: ((id as NSString).lastPathComponent as NSString).deletingPathExtension, bundlePath: id)
        }
        return AppUsage(id: id, name: (path as NSString).lastPathComponent, bundlePath: nil)
    }

    // Quits gracefully, or force quits. Plain processes only get the signal if they still run the same executable.
    static func quit(_ usage: AppUsage, force: Bool) {
        if let bundle = usage.bundlePath,
           let app = NSWorkspace.shared.runningApplications.first(where: { $0.bundleURL?.path == bundle }) {
            _ = force ? app.forceTerminate() : app.terminate()
            if !force { return }
        }
        for pid in usage.pids where pid != getpid() {
            let path = Scanner.execPath(pid)
            guard !path.isEmpty, ProcessMonitor.key(path) == usage.id else { continue }
            kill(pid, force ? SIGKILL : SIGTERM)
        }
    }
}

struct PowerInfo {
    var hasBattery = false
    var level = 0           // percent
    var charging = false
    var pluggedIn = true
    var minutesLeft: Int?   // to empty, or to full while charging
    var cycles: Int?
    var health: Double?     // full-charge capacity against the design capacity
    var watts: Double?      // into the battery while charging, out of it on battery
    var thermal = ProcessInfo.ThermalState.nominal

    static func sample() -> PowerInfo {
        var info = PowerInfo()
        info.thermal = ProcessInfo.processInfo.thermalState
        if let blob = IOPSCopyPowerSourcesInfo()?.takeRetainedValue(),
           let sources = IOPSCopyPowerSourcesList(blob)?.takeRetainedValue() as? [CFTypeRef] {
            for source in sources {
                guard let details = IOPSGetPowerSourceDescription(blob, source)?.takeUnretainedValue() as? [String: Any],
                      details[kIOPSTypeKey] as? String == kIOPSInternalBatteryType else { continue }
                info.hasBattery = true
                let current = (details[kIOPSCurrentCapacityKey] as? NSNumber)?.intValue ?? 0
                let maximum = (details[kIOPSMaxCapacityKey] as? NSNumber)?.intValue ?? 100
                info.level = maximum > 0 ? current * 100 / maximum : current
                info.charging = (details[kIOPSIsChargingKey] as? NSNumber)?.boolValue ?? false
                info.pluggedIn = details[kIOPSPowerSourceStateKey] as? String == kIOPSACPowerValue
                let key = info.charging ? kIOPSTimeToFullChargeKey : kIOPSTimeToEmptyKey
                if let minutes = (details[key] as? NSNumber)?.intValue, minutes > 0 { info.minutesLeft = minutes }
            }
        }
        let service = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching("AppleSmartBattery"))
        guard service != 0 else { return info }
        defer { IOObjectRelease(service) }
        var raw: Unmanaged<CFMutableDictionary>?
        guard IORegistryEntryCreateCFProperties(service, &raw, kCFAllocatorDefault, 0) == KERN_SUCCESS,
              let props = raw?.takeRetainedValue() as? [String: Any] else { return info }
        // Newer macOS versions keep the capacities inside "BatteryData".
        let data = props["BatteryData"] as? [String: Any] ?? [:]
        func number(_ key: String) -> Int64? { ((props[key] ?? data[key]) as? NSNumber)?.int64Value }
        info.cycles = number("CycleCount").map(Int.init)
        if let design = number("DesignCapacity"), design > 0,
           let full = number("AppleRawMaxCapacity") ?? number("NominalChargeCapacity") {
            info.health = min(1, Double(full) / Double(design))
        }
        if let volts = number("Voltage"), let amps = number("InstantAmperage") ?? number("Amperage"), amps != 0 {
            info.watts = Double(volts) * Double(amps) / 1_000_000
        }
        return info
    }
}

struct ClipItem: Codable, Equatable {
    var id: UUID
    var text: String
    var kind: String
    var app: String
    var date: Date
    var pinned: Bool
}

final class ClipBook {
    private(set) var items: [ClipItem] = []
    var onChange: () -> Void = {}
    private var suppressChange = -1
    private var seenChange = NSPasteboard.general.changeCount
    private var sourceApp = ""
    private let file: URL

    init() {
        let dir = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("iServer", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        file = dir.appendingPathComponent("clips.json")
        if let data = try? Data(contentsOf: file),
           let saved = try? JSONDecoder().decode([ClipItem].self, from: data) {
            items = saved.filter(\.pinned)
            if items.count != saved.count { store() }  // scrub unpinned history written by older versions
        }
        noteFrontmost()
        NSWorkspace.shared.notificationCenter.addObserver(
            self, selector: #selector(appActivated), name: NSWorkspace.didActivateApplicationNotification, object: nil)
    }

    func poll() {
        let board = NSPasteboard.general
        let change = board.changeCount
        guard change != seenChange else { return }
        noteFrontmost()
        seenChange = change
        guard change != suppressChange else { return }
        // Skip what password managers and other apps mark as private (nspasteboard.org conventions).
        let privateTypes = ["org.nspasteboard.ConcealedType", "org.nspasteboard.TransientType",
                            "org.nspasteboard.AutoGeneratedType", "com.agilebits.onepassword"]
        if let types = board.types, types.contains(where: { privateTypes.contains($0.rawValue) }) { return }
        if let raw = board.string(forType: .fileURL), let path = URL(string: raw)?.path, !path.isEmpty {
            remember(path, kind: "file")
            return
        }
        guard let text = board.string(forType: .string) else { return }
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, trimmed.count <= 50_000 else { return }
        let kind = (trimmed.hasPrefix("http://") || trimmed.hasPrefix("https://")) ? "link" : "text"
        remember(String(trimmed.prefix(50_000)), kind: kind)
    }

    func copy(_ item: ClipItem) {
        let board = NSPasteboard.general
        board.clearContents()
        if item.kind == "file" {
            board.writeObjects([URL(fileURLWithPath: item.text) as NSURL])
        } else {
            board.setString(item.text, forType: .string)
        }
        suppressChange = board.changeCount
        seenChange = board.changeCount
    }

    func copyString(_ text: String) {
        let board = NSPasteboard.general
        board.clearContents()
        board.setString(text, forType: .string)
        suppressChange = board.changeCount
        seenChange = board.changeCount
    }

    func togglePin(_ id: UUID) {
        guard let index = items.firstIndex(where: { $0.id == id }) else { return }
        items[index].pinned.toggle()
        items.sort { lhs, rhs in
            if lhs.pinned != rhs.pinned { return lhs.pinned && !rhs.pinned }
            return lhs.date > rhs.date
        }
        store()
        onChange()
    }

    private func remember(_ text: String, kind: String) {
        if items.contains(where: { $0.text == text && $0.pinned }) { return }
        items.removeAll { $0.text == text && !$0.pinned }
        let clip = ClipItem(id: UUID(), text: text, kind: kind, app: sourceApp, date: Date(), pinned: false)
        let pinCount = items.filter(\.pinned).count
        items.insert(clip, at: min(pinCount, items.count))
        var loose = items.filter { !$0.pinned }
        if loose.count > 40 { loose = Array(loose.prefix(40)) }
        items = items.filter(\.pinned) + loose
        store()
        onChange()
    }

    // Only pinned clips go to disk; the rest of the history lives in memory, so copied secrets
    // are not left behind in a plaintext file.
    private func store() {
        guard let data = try? JSONEncoder().encode(items.filter(\.pinned)) else { return }
        try? data.write(to: file, options: .atomic)
        try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file.path)
    }

    @objc private func appActivated(_ note: Notification) {
        noteFrontmost()
    }

    private func noteFrontmost() {
        guard let app = NSWorkspace.shared.frontmostApplication,
              app.bundleIdentifier != Bundle.main.bundleIdentifier else { return }
        sourceApp = app.localizedName ?? ""
    }
}

// MARK: - Demo data (`--demo`), for screenshots and trying the UI

enum Demo {
    static func groups() -> [ServerGroup] {
        func proc(_ pid: Int32, _ exec: String, _ cwd: String, _ elapsed: String, _ ports: [(Int, Bool)], cpu: Double, rssMB: Double, args: String = "") -> ServerProcess {
            ServerProcess(pid: pid, ppid: 1, execPath: exec, args: args, cwd: cwd, elapsed: elapsed,
                          cpu: cpu * Double.random(in: 0.4...1.7), rss: UInt64(rssMB * 1_048_576),
                          listeners: ports.map { Listener(port: $0.0, exposed: $0.1) })
        }
        let h = Scanner.home
        let node = "/opt/homebrew/bin/node"
        let groups: [[ServerProcess]] = [
            [
                proc(41210, node, "\(h)/Projects/acme-web", "02:14:09", [(3000, true)], cpu: 6.4, rssMB: 240),
                proc(41211, node, "\(h)/Projects/acme-web", "02:14:08", [], cpu: 1.2, rssMB: 64),
            ],
            [proc(41388, node, "\(h)/Projects/acme-api", "01:52:33", [(8080, false), (9229, false)], cpu: 2.8, rssMB: 160)],
            [proc(40112, node, "\(h)/Projects/design-system", "1-03:12:00", [(6006, false)], cpu: 0.6, rssMB: 90)],
            [proc(43007, node, "\(h)/Projects/docs", "18:40", [(5173, false)], cpu: 0.4, rssMB: 48)],
            [proc(44120, "/usr/bin/python3", "/private/tmp/claude-501/\(h.replacingOccurrences(of: "/", with: "-"))-Projects-landing-page/3f2a/scratchpad/site",
                  "04:02", [(8000, false)], cpu: 1.1, rssMB: 32)],
            [proc(912, "/opt/homebrew/opt/postgresql@17/bin/postgres", "/opt/homebrew/var/postgresql@17", "6-04:10:00", [(5432, false)], cpu: 0.3, rssMB: 86)],
            [proc(918, "/opt/homebrew/opt/redis/bin/redis-server", "/opt/homebrew/var/db/redis", "6-04:10:02", [(6379, false)], cpu: 0.2, rssMB: 8)],
        ]
        return Scanner.sorted(groups.map { Scanner.makeGroup(root: $0[0], members: $0) })
    }
}

// MARK: - Palette

enum Term {
    static var ink: NSColor { .labelColor }
    static var dim: NSColor { .secondaryLabelColor }
    static var faint: NSColor { .tertiaryLabelColor }
    static var line: NSColor { .separatorColor }
    static var fill: NSColor { .labelColor.withAlphaComponent(0.06) }
    static var fillHot: NSColor { .labelColor.withAlphaComponent(0.11) }
    static var stroke: NSColor { .labelColor.withAlphaComponent(0.07) }
    static var accent: NSColor { .controlAccentColor }
    static var cpu: NSColor { .systemBlue }
    static var gpu: NSColor { .systemTeal }
    static var mem: NSColor { .systemPurple }
    static var disk: NSColor { .systemGreen }
    static var lan: NSColor { .systemOrange }
}

func termFont(_ size: CGFloat, _ weight: NSFont.Weight = .medium) -> NSFont {
    NSFont.systemFont(ofSize: size, weight: weight)
}

// SF Rounded, used for the big numbers.
func roundedFont(_ size: CGFloat, _ weight: NSFont.Weight = .semibold) -> NSFont {
    let base = NSFont.systemFont(ofSize: size, weight: weight)
    guard let descriptor = base.fontDescriptor.withDesign(.rounded) else { return base }
    return NSFont(descriptor: descriptor, size: size) ?? base
}

func digitFont(_ size: CGFloat, _ weight: NSFont.Weight = .medium) -> NSFont {
    NSFont.monospacedDigitSystemFont(ofSize: size, weight: weight)
}

func glassSymbol(_ name: String, pointSize: CGFloat, weight: NSFont.Weight = .medium, color: NSColor) -> NSImage? {
    let config = NSImage.SymbolConfiguration(pointSize: pointSize, weight: weight)
        .applying(NSImage.SymbolConfiguration(paletteColors: [color]))
    return NSImage(systemSymbolName: name, accessibilityDescription: nil)?.withSymbolConfiguration(config)
}

func drawSymbol(_ name: String, in rect: NSRect, pointSize: CGFloat, weight: NSFont.Weight = .medium, color: NSColor) {
    guard let image = glassSymbol(name, pointSize: pointSize, weight: weight, color: color) else { return }
    let size = image.size
    let target = NSRect(x: rect.midX - size.width / 2, y: rect.midY - size.height / 2, width: size.width, height: size.height)
    image.draw(in: target, from: .zero, operation: .sourceOver, fraction: 1, respectFlipped: true, hints: nil)
}

// MARK: - Server kinds (framework / runtime badge)

struct Kind {
    let label: String
    let mono: String
    let symbol: String?
    let color: NSColor

    init(_ label: String, _ mono: String, _ color: NSColor, symbol: String? = nil) {
        self.label = label
        self.mono = mono
        self.color = color
        self.symbol = symbol
    }

    // Matched against the executable path and arguments of every process in the group.
    static let rules: [([String], Kind)] = [
        (["next dev", "next start", "next-server", "/next/dist"], Kind("Next.js", "N", .systemGray)),
        (["vite"], Kind("Vite", "V", .systemPurple)),
        (["astro"], Kind("Astro", "A", .systemOrange)),
        (["nuxt"], Kind("Nuxt", "Nu", .systemGreen)),
        (["remix"], Kind("Remix", "R", .systemBlue)),
        (["storybook"], Kind("Storybook", "Sb", .systemPink)),
        (["webpack"], Kind("Webpack", "W", .systemBlue)),
        (["expo start", "/expo/", "metro"], Kind("Expo", "Ex", .systemIndigo)),
        (["jupyter"], Kind("Jupyter", "Ju", .systemOrange)),
        (["uvicorn", "fastapi"], Kind("FastAPI", "Fa", .systemTeal)),
        (["manage.py", "django"], Kind("Django", "Dj", .systemGreen)),
        (["flask"], Kind("Flask", "Fl", .systemGray)),
        (["rails", "puma"], Kind("Rails", "Rb", .systemRed)),
        (["postgres"], Kind("PostgreSQL", "", .systemBlue, symbol: "cylinder.split.1x2.fill")),
        (["mysqld", "mariadbd"], Kind("MySQL", "", .systemOrange, symbol: "cylinder.split.1x2.fill")),
        (["mongod"], Kind("MongoDB", "", .systemGreen, symbol: "cylinder.split.1x2.fill")),
        (["redis-server", "valkey"], Kind("Redis", "", .systemRed, symbol: "bolt.fill")),
        (["docker", "orbstack"], Kind("Docker", "", .systemBlue, symbol: "shippingbox.fill")),
        (["ollama"], Kind("Ollama", "", .systemGray, symbol: "brain.head.profile")),
        (["claude"], Kind("Claude", "", .systemOrange, symbol: "sparkle")),
    ]

    // Fallback on the executable name.
    static let runtimes: [(String, Kind)] = [
        ("node", Kind("Node.js", "JS", .systemGreen)),
        ("bun", Kind("Bun", "Bn", .systemBrown)),
        ("deno", Kind("Deno", "De", .systemGray)),
        ("python", Kind("Python", "Py", .systemBlue)),
        ("ruby", Kind("Ruby", "Rb", .systemRed)),
        ("java", Kind("Java", "Jv", .systemOrange)),
        ("php", Kind("PHP", "P", .systemIndigo)),
    ]

    static func of(_ group: ServerGroup) -> Kind {
        let text = group.processes.map { ($0.execPath + " " + $0.args).lowercased() }.joined(separator: " ")
        for (keys, kind) in rules where keys.contains(where: text.contains) { return kind }
        let execs = group.processes.map { $0.execName.lowercased() }
        for (prefix, kind) in runtimes where execs.contains(where: { $0.hasPrefix(prefix) }) { return kind }
        return Kind(L("Server", "Server"), "", .systemGray, symbol: "server.rack")
    }
}

// MARK: - Drawing helpers

enum Draw {
    static func card(_ rect: NSRect, hot: Bool = false, radius: CGFloat = 14) {
        let path = NSBezierPath(roundedRect: rect.insetBy(dx: 0.5, dy: 0.5), xRadius: radius, yRadius: radius)
        (hot ? Term.fillHot : Term.fill).setFill()
        path.fill()
        Term.stroke.setStroke()
        path.lineWidth = 1
        path.stroke()
    }

    static func text(_ string: String, font: NSFont, color: NSColor, centeredAt point: NSPoint) {
        let attrs: [NSAttributedString.Key: Any] = [.font: font, .foregroundColor: color]
        let size = (string as NSString).size(withAttributes: attrs)
        (string as NSString).draw(at: NSPoint(x: point.x - size.width / 2, y: point.y - size.height / 2), withAttributes: attrs)
    }

    @discardableResult
    static func text(_ string: String, font: NSFont, color: NSColor, at point: NSPoint) -> CGFloat {
        let attrs: [NSAttributedString.Key: Any] = [.font: font, .foregroundColor: color]
        (string as NSString).draw(at: point, withAttributes: attrs)
        return (string as NSString).size(withAttributes: attrs).width
    }

    static func width(_ string: String, font: NSFont) -> CGFloat {
        ceil((string as NSString).size(withAttributes: [.font: font]).width)
    }

    // Warmer colour as a gauge fills up.
    static func level(_ fraction: Double, _ tint: NSColor) -> NSColor {
        if fraction >= 0.9 { return .systemRed }
        if fraction >= 0.75 { return .systemOrange }
        return tint
    }

    // Draw only in non-flipped views: the arc runs clockwise from 12 o'clock.
    static func ring(center: NSPoint, radius: CGFloat, width: CGFloat, fraction: Double, tint: NSColor) {
        let track = NSBezierPath()
        track.appendArc(withCenter: center, radius: radius, startAngle: 0, endAngle: 360)
        track.lineWidth = width
        NSColor.labelColor.withAlphaComponent(0.09).setStroke()
        track.stroke()
        let f = min(1, max(0, fraction))
        guard f > 0.004 else { return }
        let arc = NSBezierPath()
        arc.appendArc(withCenter: center, radius: radius, startAngle: 90, endAngle: 90 - 360 * CGFloat(f), clockwise: true)
        arc.lineWidth = width
        arc.lineCapStyle = .round
        tint.setStroke()
        arc.stroke()
    }

    static func smooth(_ points: [NSPoint]) -> NSBezierPath {
        let path = NSBezierPath()
        guard let first = points.first else { return path }
        path.move(to: first)
        guard points.count > 1 else { return path }
        for i in 1..<points.count {
            let p0 = points[max(i - 2, 0)], p1 = points[i - 1], p2 = points[i], p3 = points[min(i + 1, points.count - 1)]
            // Control points stay within the segment's vertical range, so the curve never overshoots.
            let low = min(p1.y, p2.y), high = max(p1.y, p2.y)
            let c1 = NSPoint(x: p1.x + (p2.x - p0.x) / 6, y: min(high, max(low, p1.y + (p2.y - p0.y) / 6)))
            let c2 = NSPoint(x: p2.x - (p3.x - p1.x) / 6, y: min(high, max(low, p2.y - (p3.y - p1.y) / 6)))
            path.curve(to: p2, controlPoint1: c1, controlPoint2: c2)
        }
        return path
    }

    // Samples are 0...1. With a capacity the line is right-aligned, so it grows in from the right.
    // Draw only in non-flipped views.
    static func spark(_ samples: [Double], in rect: NSRect, tint: NSColor, lineWidth: CGFloat = 1.5, fill: Bool = true, capacity: Int? = nil) {
        guard samples.count > 1 else {
            let base = NSBezierPath()
            base.move(to: NSPoint(x: rect.minX, y: rect.minY + 1))
            base.line(to: NSPoint(x: rect.maxX, y: rect.minY + 1))
            base.lineWidth = 1
            tint.withAlphaComponent(0.35).setStroke()
            base.stroke()
            return
        }
        let slots = max(capacity ?? samples.count, samples.count)
        let step = rect.width / CGFloat(max(slots - 1, 1))
        let offset = CGFloat(slots - samples.count) * step
        let points = samples.enumerated().map { index, value in
            NSPoint(x: rect.minX + offset + CGFloat(index) * step,
                    y: rect.minY + CGFloat(min(1, max(0, value))) * rect.height)
        }
        let line = smooth(points)
        if fill, let first = points.first, let last = points.last {
            let area = line.copy() as! NSBezierPath
            area.line(to: NSPoint(x: last.x, y: rect.minY))
            area.line(to: NSPoint(x: first.x, y: rect.minY))
            area.close()
            NSGraphicsContext.saveGraphicsState()
            NSBezierPath(rect: rect.insetBy(dx: -2, dy: 0)).addClip()
            NSGradient(starting: tint.withAlphaComponent(0.0), ending: tint.withAlphaComponent(0.32))?.draw(in: area, angle: 90)
            NSGraphicsContext.restoreGraphicsState()
        }
        tint.setStroke()
        line.lineWidth = lineWidth
        line.lineCapStyle = .round
        line.lineJoinStyle = .round
        line.stroke()
    }

    // Rounded tile with a monogram or symbol. Draw only in non-flipped views.
    static func monogram(_ kind: Kind, in rect: NSRect) {
        let radius = rect.width * 0.28
        let path = NSBezierPath(roundedRect: rect, xRadius: radius, yRadius: radius)
        let top = kind.color.blended(withFraction: 0.22, of: .white) ?? kind.color
        NSGradient(starting: top, ending: kind.color)?.draw(in: path, angle: -90)
        NSColor.white.withAlphaComponent(0.18).setStroke()
        let rim = NSBezierPath(roundedRect: rect.insetBy(dx: 0.5, dy: 0.5), xRadius: radius, yRadius: radius)
        rim.lineWidth = 1
        rim.stroke()
        if let symbol = kind.symbol {
            drawSymbol(symbol, in: rect, pointSize: rect.width * 0.42, weight: .semibold, color: .white)
        } else {
            text(kind.mono, font: roundedFont(rect.width * (kind.mono.count > 1 ? 0.36 : 0.44), .bold), color: .white,
                 centeredAt: NSPoint(x: rect.midX, y: rect.midY))
        }
    }

    // Small tinted tile with a symbol (cleanup groups, clipboard kinds).
    static func tile(_ symbol: String, in rect: NSRect, color: NSColor) {
        let path = NSBezierPath(roundedRect: rect, xRadius: 8, yRadius: 8)
        color.withAlphaComponent(0.16).setFill()
        path.fill()
        drawSymbol(symbol, in: rect, pointSize: rect.width * 0.46, weight: .semibold, color: color)
    }
}

// MARK: - Animation

// A value that eases toward its target, one step per frame.
struct Eased {
    var value: Double
    var target: Double

    init(_ value: Double) {
        self.value = value
        target = value
    }

    // Returns true while still moving.
    mutating func step() -> Bool {
        let delta = target - value
        if abs(delta) < 0.0015 {
            value = target
            return false
        }
        value += delta * 0.16
        return true
    }
}

// Runs per-frame steps at about 60 fps, only while something is moving.
final class Animator {
    static let shared = Animator()
    private var timer: Timer?
    private var steps: [ObjectIdentifier: () -> Bool] = [:]

    // `step` returns true while it still needs frames. One step per owner; a new one replaces the old.
    func run(_ owner: AnyObject, step: @escaping () -> Bool) {
        steps[ObjectIdentifier(owner)] = step
        guard timer == nil else { return }
        let timer = Timer(timeInterval: 1.0 / 60, repeats: true) { [weak self] _ in self?.tick() }
        RunLoop.main.add(timer, forMode: .common)
        self.timer = timer
    }

    private func tick() {
        steps = steps.filter { $0.value() }
        if steps.isEmpty {
            timer?.invalidate()
            timer = nil
        }
    }
}

// Eases a list of values and redraws the view until they settle.
final class EasedValues {
    private(set) var values: [Eased]
    private weak var view: NSView?

    init(count: Int, view: NSView) {
        values = Array(repeating: Eased(0), count: count)
        self.view = view
    }

    subscript(index: Int) -> Double { index < values.count ? values[index].value : 0 }

    func set(_ targets: [Double]) {
        if targets.count != values.count { values = targets.map { _ in Eased(0) } }
        for index in targets.indices { values[index].target = targets[index] }
        Animator.shared.run(self) { [weak self] in
            guard let self, let view = self.view else { return false }
            var moving = false
            for index in self.values.indices where self.values[index].step() { moving = true }
            view.needsDisplay = true
            return moving
        }
    }
}

// MARK: - Menu bar icon

enum StatusIcon {
    static let bars = 6

    // Just a small CPU history graph. Drawn lazily so it follows the menu bar's light/dark appearance.
    static func image(cpu: [Double]) -> NSImage {
        let barWidth: CGFloat = 2.5, gap: CGFloat = 1.5
        let size = NSSize(width: CGFloat(bars) * (barWidth + gap) - gap, height: 18)
        let samples = Array(repeating: 0.0, count: max(0, bars - cpu.count)) + cpu.suffix(bars)

        let image = NSImage(size: size, flipped: false) { _ in
            let ink = NSColor.labelColor
            var x: CGFloat = 0
            for value in samples {
                let v = min(1, max(0, value))
                // Faint full-height track, so the graph reads as a graph even when the Mac is idle.
                let track = NSRect(x: x, y: 2, width: barWidth, height: 14)
                ink.withAlphaComponent(0.2).setFill()
                NSBezierPath(roundedRect: track, xRadius: 1, yRadius: 1).fill()
                let bar = NSRect(x: x, y: 2, width: barWidth, height: max(2, CGFloat(v) * 14))
                (v >= 0.8 ? NSColor.systemOrange : ink).setFill()
                NSBezierPath(roundedRect: bar, xRadius: 1, yRadius: 1).fill()
                x += barWidth + gap
            }
            return true
        }
        image.isTemplate = false
        image.accessibilityDescription = L("CPU load", "CPU-belasting")
        return image
    }
}

// MARK: - Panel metrics

enum Metrics {
    static let width: CGFloat = 440
    static let hero: CGFloat = 70
    static let tabs: CGFloat = 40
    static var header: CGFloat { hero + tabs }
    static let footer: CGFloat = 46
    static let row: CGFloat = 76
    static let gauges: CGFloat = 128
    static let history: CGFloat = 124
    static let proc: CGFloat = 40
    static let power: CGFloat = 92
    static let volume: CGFloat = 84
    static let cleanHeader: CGFloat = 70
    static let groupRow: CGFloat = 50
    static let itemRow: CGFloat = 40
    static let filterRow: CGFloat = 42
    static let modeBar: CGFloat = 40
    static let explorerRow: CGFloat = 42
    static let clip: CGFloat = 50
    static let section: CGFloat = 28
    static let listPad: CGFloat = 4
    static let empty: CGFloat = 150
    static let inset: CGFloat = 12
    static var chrome: CGFloat { header + footer }

    static func clipHeight(count: Int) -> CGFloat {
        46 + CGFloat(max(count, 1)) * clip + listPad * 2
    }

    static func listHeight(count: Int, maxHeight: CGFloat) -> CGFloat {
        let natural = count == 0 ? empty : listPad * 2 + CGFloat(count) * row
        return capped(natural, maxHeight: maxHeight)
    }

    static func capped(_ natural: CGFloat, maxHeight: CGFloat) -> CGFloat {
        min(natural, max(empty, maxHeight - chrome - 8))
    }
}

func makeLabel(_ text: String, size: CGFloat, weight: NSFont.Weight, color: NSColor) -> NSTextField {
    let field = NSTextField(labelWithString: text)
    field.font = termFont(size, weight)
    field.textColor = color
    field.lineBreakMode = .byTruncatingTail
    field.maximumNumberOfLines = 1
    field.cell?.usesSingleLineMode = true
    field.cell?.lineBreakMode = .byTruncatingTail
    return field
}

// MARK: - Controls

class HoverView: NSView {
    var onClick: () -> Void = {}
    var hovered = false
    var pressed = false

    override func acceptsFirstMouse(for event: NSEvent?) -> Bool { true }

    override func updateTrackingAreas() {
        super.updateTrackingAreas()
        trackingAreas.forEach(removeTrackingArea)
        addTrackingArea(NSTrackingArea(
            rect: bounds,
            options: [.mouseEnteredAndExited, .activeAlways, .inVisibleRect],
            owner: self, userInfo: nil))
    }

    override func mouseEntered(with event: NSEvent) { hovered = true; refresh() }
    override func mouseExited(with event: NSEvent) { hovered = false; pressed = false; refresh() }
    override func mouseDown(with event: NSEvent) { pressed = true; refresh() }
    override func mouseUp(with event: NSEvent) {
        let inside = bounds.contains(convert(event.locationInWindow, from: nil))
        pressed = false
        hovered = inside
        refresh()
        if inside { onClick() }
    }

    override func resetCursorRects() { addCursorRect(bounds, cursor: .pointingHand) }
    func refresh() { needsDisplay = true }
}

// Port pill. Optional symbol and tint (orange for ports reachable from the network).
final class Chip: HoverView {
    let title: String
    let preferredWidth: CGFloat
    private let symbol: String?
    private let tint: NSColor?
    private var confirmed = false
    private static let font = digitFont(11, .semibold)

    init(title: String, help: String, symbol: String? = nil, tint: NSColor? = nil) {
        self.title = title
        self.symbol = symbol
        self.tint = tint
        preferredWidth = max(34, Draw.width(title, font: Chip.font) + 16 + (symbol == nil ? 0 : 14))
        super.init(frame: .zero)
        toolTip = help
        setAccessibilityRole(.button)
        setAccessibilityLabel(help)
    }

    required init?(coder: NSCoder) { fatalError() }

    func confirm() {
        confirmed = true
        needsDisplay = true
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.7) { [weak self] in
            self?.confirmed = false
            self?.needsDisplay = true
        }
    }

    override func draw(_ dirtyRect: NSRect) {
        let path = NSBezierPath(roundedRect: bounds, xRadius: bounds.height / 2, yRadius: bounds.height / 2)
        let ink: NSColor
        if confirmed {
            Term.accent.setFill()
            ink = .white
        } else if let tint {
            tint.withAlphaComponent(hovered ? 0.3 : 0.18).setFill()
            ink = tint
        } else {
            (hovered ? Term.fillHot : Term.fill).setFill()
            ink = Term.ink
        }
        path.fill()
        let attrs: [NSAttributedString.Key: Any] = [.font: Chip.font, .foregroundColor: ink]
        let size = (title as NSString).size(withAttributes: attrs)
        var x = bounds.midX - (size.width + (symbol == nil ? 0 : 14)) / 2
        if let symbol {
            drawSymbol(symbol, in: NSRect(x: x, y: 0, width: 11, height: bounds.height), pointSize: 9, weight: .semibold, color: ink)
            x += 14
        }
        (title as NSString).draw(at: NSPoint(x: x, y: (bounds.height - size.height) / 2), withAttributes: attrs)
    }
}

final class IconButton: HoverView {
    private var symbolName: String
    private let destructive: Bool

    init(symbol: String, help: String, destructive: Bool = false, action: @escaping () -> Void) {
        symbolName = symbol
        self.destructive = destructive
        super.init(frame: .zero)
        onClick = action
        toolTip = help
        setAccessibilityRole(.button)
        setAccessibilityLabel(help)
    }

    required init?(coder: NSCoder) { fatalError() }

    // Shows a check mark for a moment, e.g. after copying.
    func flash() {
        let original = symbolName
        symbolName = "checkmark"
        needsDisplay = true
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.9) { [weak self] in
            self?.symbolName = original
            self?.needsDisplay = true
        }
    }

    override func draw(_ dirtyRect: NSRect) {
        let active = hovered || pressed
        if active {
            let path = NSBezierPath(roundedRect: bounds.insetBy(dx: 1, dy: 1), xRadius: 7, yRadius: 7)
            (destructive ? NSColor.systemRed.withAlphaComponent(0.18) : Term.fillHot).setFill()
            path.fill()
        }
        let color: NSColor = destructive ? (active ? .systemRed : Term.dim) : (active ? Term.ink : Term.dim)
        drawSymbol(symbolName, in: bounds, pointSize: 12, color: color)
    }
}

final class QuietButton: HoverView {
    let title: NSTextField

    init(_ text: String, action: @escaping () -> Void) {
        title = makeLabel(text, size: 12, weight: .semibold, color: Term.ink)
        title.alignment = .center
        super.init(frame: .zero)
        onClick = action
        addSubview(title)
        setAccessibilityRole(.button)
        setAccessibilityLabel(text)
    }

    required init?(coder: NSCoder) { fatalError() }

    override func layout() {
        super.layout()
        title.sizeToFit()
        title.frame = NSRect(
            x: (bounds.width - title.bounds.width) / 2,
            y: (bounds.height - title.bounds.height) / 2,
            width: title.bounds.width, height: title.bounds.height)
    }

    override func draw(_ dirtyRect: NSRect) {
        let path = NSBezierPath(roundedRect: bounds, xRadius: bounds.height / 2, yRadius: bounds.height / 2)
        (hovered ? Term.fillHot : Term.fill).setFill()
        path.fill()
    }
}

// Footer toggle: symbol + caption in a pill, accent-tinted when on.
final class TogglePill: HoverView {
    let caption: String
    let symbol: String
    var checked = false { didSet { needsDisplay = true } }
    var onChange: (Bool) -> Void = { _ in }
    private static let font = termFont(12, .medium)

    var preferredWidth: CGFloat { Draw.width(caption, font: TogglePill.font) + 40 }

    init(_ caption: String, symbol: String, help: String) {
        self.caption = caption
        self.symbol = symbol
        super.init(frame: .zero)
        toolTip = help
        setAccessibilityRole(.checkBox)
        setAccessibilityLabel(help)
        onClick = { [weak self] in
            guard let self else { return }
            self.checked.toggle()
            self.onChange(self.checked)
        }
    }

    required init?(coder: NSCoder) { fatalError() }

    override func draw(_ dirtyRect: NSRect) {
        let path = NSBezierPath(roundedRect: bounds, xRadius: bounds.height / 2, yRadius: bounds.height / 2)
        if checked {
            Term.accent.withAlphaComponent(hovered ? 0.3 : 0.2).setFill()
        } else {
            (hovered ? Term.fillHot : Term.fill).setFill()
        }
        path.fill()
        let color: NSColor = checked ? Term.accent : Term.dim
        drawSymbol(symbol, in: NSRect(x: 9, y: 0, width: 16, height: bounds.height), pointSize: 11, weight: .semibold, color: color)
        Draw.text(caption, font: TogglePill.font, color: checked ? Term.ink : Term.dim,
                  at: NSPoint(x: 29, y: (bounds.height - 15) / 2))
    }
}

// MARK: - Hero: server count and live system gauges

final class HeroView: NSView {
    private lazy var eased = EasedValues(count: 3, view: self)
    private var count = 0
    private var exposed = 0
    private var stats: [(caption: String, fraction: Double, value: String, tint: NSColor)] = []

    func set(groups: [ServerGroup], vitals: Vitals, disk: DiskVolume?) {
        count = groups.count
        exposed = groups.filter(\.exposed).count
        let mem = vitals.total > 0 ? Double(vitals.used) / Double(vitals.total) : 0
        stats = [
            ("CPU", vitals.cpu / 100, "\(Int(vitals.cpu.rounded()))%", Term.cpu),
            ("RAM", mem, "\(Int((mem * 100).rounded()))%", Term.mem),
            (L("Disk", "Schijf"), disk?.fraction ?? 0, disk.map { "\(Int(($0.fraction * 100).rounded()))%" } ?? "–", Term.disk),
        ]
        eased.set(stats.map(\.fraction))
        needsDisplay = true
    }

    override func draw(_ dirtyRect: NSRect) {
        let card = NSRect(x: Metrics.inset, y: 4, width: bounds.width - Metrics.inset * 2, height: bounds.height - 10)
        Draw.card(card, radius: 16)

        // Left: big count with a status line
        let numberFont = roundedFont(30, .bold)
        let number = "\(count)"
        let numberWidth = Draw.width(number, font: numberFont)
        Draw.text(number, font: numberFont, color: count == 0 ? Term.dim : Term.ink,
                  at: NSPoint(x: card.minX + 16, y: card.midY - 19))
        let textX = card.minX + 16 + numberWidth + 9
        let noun = count == 1 ? L("dev server", "dev server") : L("dev servers", "dev servers")
        Draw.text(noun, font: termFont(13, .semibold), color: Term.ink, at: NSPoint(x: textX, y: card.midY + 1))
        let status: String
        let statusColor: NSColor
        if count == 0 {
            status = L("nothing running", "niets actief")
            statusColor = Term.dim
        } else if exposed > 0 {
            status = "\(exposed) " + L("on your network", "in je netwerk")
            statusColor = Term.lan
        } else {
            status = L("all local", "alles lokaal")
            statusColor = .systemGreen
        }
        let dot = NSRect(x: textX, y: card.midY - 12, width: 6, height: 6)
        statusColor.setFill()
        NSBezierPath(ovalIn: dot).fill()
        Draw.text(status, font: termFont(11, .medium), color: Term.dim, at: NSPoint(x: textX + 10, y: card.midY - 17))

        // Right: three mini gauges
        let slot: CGFloat = 76
        var x = card.maxX - 10 - slot * CGFloat(stats.count)
        for (index, stat) in stats.enumerated() {
            let center = NSPoint(x: x + 14, y: card.midY)
            let shown = eased[index]
            Draw.ring(center: center, radius: 11, width: 4, fraction: shown, tint: Draw.level(shown, stat.tint))
            Draw.text(stat.caption, font: termFont(10, .semibold), color: Term.dim, at: NSPoint(x: x + 31, y: card.midY + 1))
            Draw.text(stat.value, font: roundedFont(13, .semibold), color: Term.ink, at: NSPoint(x: x + 31, y: card.midY - 15))
            x += slot
        }
    }
}

// MARK: - Server card

final class ServerCard: HoverView {
    let groupID: Int32
    private let kind: Kind
    private let exposed: Bool
    var expanded = false { didSet { needsDisplay = true } }
    private let titleLabel: NSTextField
    private let subtitleLabel: NSTextField
    private let cpuLabel: NSTextField
    private let statsLabel: NSTextField
    private var chips: [Chip] = []
    private var buttons: [IconButton] = []
    private var history: [Double]

    init(group: ServerGroup, history: [Double], lan: String?,
         openURL: @escaping (String) -> Void,
         copyText: @escaping (String) -> Void,
         reveal: @escaping (String) -> Void,
         terminal: @escaping (String) -> Void,
         toggle: @escaping () -> Void,
         stop: @escaping () -> Void) {
        groupID = group.id
        kind = Kind.of(group)
        exposed = group.exposed
        self.history = history
        let primary = group.listeners.first { Scanner.isHTTP($0, in: group) }

        titleLabel = makeLabel(group.title, size: 13, weight: .semibold, color: Term.ink)
        subtitleLabel = makeLabel(kind.label + "  ·  " + group.detail, size: 11, weight: .regular, color: Term.dim)
        subtitleLabel.lineBreakMode = .byTruncatingMiddle
        subtitleLabel.cell?.lineBreakMode = .byTruncatingMiddle
        cpuLabel = makeLabel("", size: 13, weight: .semibold, color: Term.ink)
        cpuLabel.font = roundedFont(14, .semibold)
        cpuLabel.alignment = .right
        statsLabel = makeLabel("", size: 11, weight: .medium, color: Term.dim)
        statsLabel.font = digitFont(11, .medium)
        statsLabel.alignment = .right

        super.init(frame: .zero)
        onClick = toggle
        for view in [titleLabel, subtitleLabel, cpuLabel, statsLabel] { addSubview(view) }

        for listener in group.listeners {
            let http = Scanner.isHTTP(listener, in: group)
            let help = http
                ? L("Open", "Open") + " http://localhost:\(listener.port)"
                : L("Copy", "Kopieer") + " localhost:\(listener.port)"
            let chip = Chip(title: ":\(listener.port)", help: help, tint: listener.exposed && http ? Term.lan : nil)
            chip.onClick = { [weak chip] in
                if http {
                    openURL("http://localhost:\(listener.port)")
                } else {
                    copyText("localhost:\(listener.port)")
                    chip?.confirm()
                }
            }
            chips.append(chip)
        }
        if let lan, let listener = group.listeners.first(where: { $0.exposed && Scanner.isHTTP($0, in: group) }) {
            let url = "http://\(lan):\(listener.port)"
            let chip = Chip(title: "LAN", help: L("Open", "Open") + " " + url, symbol: "wifi", tint: Term.lan)
            chip.onClick = { openURL(url) }
            chips.append(chip)
        }
        chips.forEach(addSubview)

        if let primary {
            buttons.append(IconButton(symbol: "safari", help: L("Open in browser", "Open in browser")) {
                openURL("http://localhost:\(primary.port)")
            })
        }
        if let folder = group.folder {
            buttons.append(IconButton(symbol: "folder", help: L("Show in Finder", "Toon in Finder")) { reveal(folder) })
            buttons.append(IconButton(symbol: "terminal", help: L("Open Terminal here", "Open Terminal hier")) { terminal(folder) })
        }
        buttons.append(IconButton(symbol: "stop.circle", help: L("Stop server…", "Stop server…"), destructive: true, action: stop))
        buttons.forEach {
            $0.isHidden = true
            addSubview($0)
        }
        apply(group)
    }

    required init?(coder: NSCoder) { fatalError() }

    func applyStats(_ group: ServerGroup, history: [Double]) {
        self.history = history
        apply(group)
        needsDisplay = true
        needsLayout = true
    }

    private func apply(_ group: ServerGroup) {
        cpuLabel.stringValue = Scanner.formatCPU(group.cpu)
        cpuLabel.textColor = group.cpu >= 40 ? .systemOrange : (group.cpu < 1 ? Term.dim : Term.ink)
        let root = group.processes.first { $0.pid == group.id } ?? group.processes.first
        statsLabel.stringValue = "\(Scanner.formatBytes(group.rss))  ·  \(Scanner.formatElapsed(root?.elapsed ?? ""))"
        toolTip = ServerCard.tip(group, kind: kind)
    }

    override func refresh() {
        super.refresh()
        let showActions = hovered
        buttons.forEach { $0.isHidden = !showActions }
        statsLabel.isHidden = showActions
        needsLayout = true
    }

    override func hitTest(_ point: NSPoint) -> NSView? {
        let local = convert(point, from: superview)
        guard bounds.contains(local) else { return nil }
        for view in (chips as [NSView]) + (buttons as [NSView]) where !view.isHidden && view.frame.contains(local) {
            return view
        }
        return self
    }

    private var card: NSRect { bounds.insetBy(dx: Metrics.inset, dy: 3) }
    private var sparkRect: NSRect { NSRect(x: card.maxX - 12 - 54 - 62, y: card.maxY - 27, width: 56, height: 20) }

    override func layout() {
        super.layout()
        let card = self.card
        let left = card.minX + 58
        let right = card.maxX - 12
        cpuLabel.frame = NSRect(x: right - 54, y: card.maxY - 27, width: 54, height: 19)
        titleLabel.frame = NSRect(x: left, y: card.maxY - 26, width: max(40, sparkRect.minX - 8 - left), height: 17)
        subtitleLabel.frame = NSRect(x: left, y: card.maxY - 43, width: max(40, right - left), height: 14)
        statsLabel.frame = NSRect(x: right - 130, y: card.minY + 9, width: 130, height: 14)

        var x = right - 24
        for button in buttons.reversed() {
            button.frame = NSRect(x: x, y: card.minY + 6, width: 24, height: 20)
            x -= 26
        }
        let statsWidth = Draw.width(statsLabel.stringValue, font: statsLabel.font ?? digitFont(11))
        let limit = (hovered ? x + 26 : right - statsWidth) - 8
        var chipX = left
        for chip in chips {
            let fits = chipX + chip.preferredWidth <= limit
            chip.isHidden = !fits
            guard fits else { continue }
            chip.frame = NSRect(x: chipX, y: card.minY + 7, width: chip.preferredWidth, height: 18)
            chipX += chip.preferredWidth + 4
        }
    }

    override func draw(_ dirtyRect: NSRect) {
        let card = self.card
        Draw.card(card, hot: hovered || pressed || expanded)
        if expanded {
            let ring = NSBezierPath(roundedRect: card.insetBy(dx: 0.5, dy: 0.5), xRadius: 14, yRadius: 14)
            ring.lineWidth = 1.5
            Term.accent.withAlphaComponent(0.6).setStroke()
            ring.stroke()
        }
        let tile = NSRect(x: card.minX + 12, y: card.midY - 18, width: 36, height: 36)
        Draw.monogram(kind, in: tile)
        let dot = NSRect(x: tile.maxX - 8, y: tile.minY - 3, width: 12, height: 12)
        NSColor.windowBackgroundColor.setFill()
        NSBezierPath(ovalIn: dot).fill()
        (exposed ? Term.lan : NSColor.systemGreen).setFill()
        NSBezierPath(ovalIn: dot.insetBy(dx: 2.5, dy: 2.5)).fill()

        let peak = max(5, history.max() ?? 0)
        let padded = Array(repeating: history.first ?? 0, count: max(0, 20 - history.count)) + history
        Draw.spark(padded.map { $0 / peak }, in: sparkRect, tint: exposed ? Term.lan : Term.cpu,
                   lineWidth: 1.4, fill: true, capacity: 20)
    }

    private static func tip(_ group: ServerGroup, kind: Kind) -> String {
        var lines = [kind.label + "  ·  " + group.detail]
        lines.append("\(Scanner.formatCPU(group.cpu))  \(Scanner.formatBytes(group.rss))")
        for proc in group.processes.prefix(8) {
            let ports = proc.listeners.map { ":\($0.port)" }.joined(separator: " ")
            lines.append("\(proc.execName)  pid \(proc.pid)  \(Scanner.formatCPU(proc.cpu))  \(Scanner.formatBytes(proc.rss))  \(Scanner.formatElapsed(proc.elapsed))  \(ports)")
        }
        if group.processes.count > 8 {
            let rest = group.processes.count - 8
            lines.append(L("… and \(rest) more processes", "… en nog \(rest) processen"))
        }
        lines.append(group.exposed
            ? L("Reachable from your network", "Bereikbaar via het netwerk")
            : L("Local only", "Alleen lokaal bereikbaar"))
        lines.append(L("Click for details", "Klik voor details"))
        return lines.joined(separator: "\n")
    }
}

// Small chart card used in the server details.
final class MiniChart: NSView {
    private let title: String
    private let tint: NSColor
    private var value = ""
    private var samples: [Double] = []

    init(title: String, tint: NSColor) {
        self.title = title
        self.tint = tint
        super.init(frame: .zero)
    }

    required init?(coder: NSCoder) { fatalError() }

    // Samples are scaled to their own peak so small changes stay visible. With `relative`, the line spans
    // the lowest to highest sample instead (memory barely moves, so against zero it would be a flat line).
    func set(value: String, samples raw: [Double], floor: Double, relative: Bool = false) {
        self.value = value
        let padded = Array(repeating: raw.first ?? 0, count: max(0, 20 - raw.count)) + raw
        if relative {
            let low = padded.min() ?? 0, high = padded.max() ?? 0
            let span = high - low
            samples = padded.map { span > high * 0.01 ? 0.15 + 0.7 * ($0 - low) / span : 0.5 }
        } else {
            let peak = max(floor, raw.max() ?? 0)
            samples = padded.map { peak > 0 ? $0 / peak : 0 }
        }
        needsDisplay = true
    }

    override func draw(_ dirtyRect: NSRect) {
        let card = bounds.insetBy(dx: 3, dy: 3)
        let path = NSBezierPath(roundedRect: card, xRadius: 12, yRadius: 12)
        Term.fill.setFill()
        path.fill()
        Draw.text(title, font: termFont(11, .semibold), color: Term.dim, at: NSPoint(x: card.minX + 10, y: card.maxY - 20))
        let font = roundedFont(13, .semibold)
        Draw.text(value, font: font, color: Term.ink, at: NSPoint(x: card.maxX - 10 - Draw.width(value, font: font), y: card.maxY - 21))
        Draw.spark(samples, in: NSRect(x: card.minX + 10, y: card.minY + 8, width: card.width - 20, height: card.height - 36),
                   tint: tint, lineWidth: 1.6, fill: true, capacity: 20)
    }
}

// One process of a server: name, pid, ports, load, uptime and its full command line.
final class ProcessDetailRow: NSView {
    let pid: Int32
    private let head: NSTextField
    private let stats: NSTextField
    private let command: NSTextField
    private let copy: IconButton

    init(process: ServerProcess, copy copyAction: @escaping (String) -> Void) {
        pid = process.pid
        let line = process.args.isEmpty ? process.execPath : process.args
        head = makeLabel("", size: 12, weight: .semibold, color: Term.ink)
        stats = makeLabel("", size: 11, weight: .medium, color: Term.dim)
        stats.font = digitFont(11, .medium)
        stats.alignment = .right
        command = makeLabel(line, size: 10.5, weight: .regular, color: Term.dim)
        command.font = NSFont.monospacedSystemFont(ofSize: 10.5, weight: .regular)
        command.lineBreakMode = .byTruncatingMiddle
        command.cell?.lineBreakMode = .byTruncatingMiddle
        command.toolTip = line
        copy = IconButton(symbol: "doc.on.doc", help: L("Copy command", "Kopieer opdracht")) {}
        super.init(frame: .zero)
        copy.onClick = { [weak self] in
            copyAction(line)
            self?.copy.flash()
        }
        for view in [head, stats, command, copy] as [NSView] { addSubview(view) }
        update(process)
    }

    required init?(coder: NSCoder) { fatalError() }

    func update(_ process: ServerProcess) {
        let ports = process.listeners.map { ":\($0.port)" }.joined(separator: " ")
        head.stringValue = "\(process.execName)  ·  pid \(process.pid)" + (ports.isEmpty ? "" : "  ·  " + ports)
        stats.stringValue = "\(Scanner.formatCPU(process.cpu))  ·  \(Scanner.formatBytes(process.rss))  ·  \(Scanner.formatElapsed(process.elapsed))"
    }

    override func layout() {
        super.layout()
        let left = Metrics.inset + 14
        let right = bounds.width - Metrics.inset - 10
        copy.frame = NSRect(x: right - 24, y: 3, width: 24, height: 20)
        stats.frame = NSRect(x: right - 150, y: bounds.height - 21, width: 150, height: 14)
        head.frame = NSRect(x: left, y: bounds.height - 21, width: max(40, stats.frame.minX - left - 6), height: 15)
        command.frame = NSRect(x: left, y: 6, width: max(40, copy.frame.minX - left - 6), height: 14)
    }
}

// Shown under a server card when it is clicked: CPU and memory over time, and every process.
final class ServerDetail: NSView {
    private let cpuChart = MiniChart(title: "CPU", tint: Term.cpu)
    private let memChart = MiniChart(title: L("Memory", "Geheugen"), tint: Term.mem)
    private let title = makeLabel("", size: 11, weight: .semibold, color: Term.dim)
    private let more = makeLabel("", size: 11, weight: .medium, color: Term.dim)
    private var rows: [ProcessDetailRow] = []
    private let copy: (String) -> Void
    private static let maxRows = 8
    private static let chartHeight: CGFloat = 78
    private static let rowHeight: CGFloat = 44

    init(copy: @escaping (String) -> Void) {
        self.copy = copy
        super.init(frame: .zero)
        for view in [cpuChart, memChart, title, more] as [NSView] { addSubview(view) }
    }

    required init?(coder: NSCoder) { fatalError() }

    var contentHeight: CGFloat {
        8 + ServerDetail.chartHeight + 24 + CGFloat(rows.count) * ServerDetail.rowHeight + (more.isHidden ? 0 : 20) + 10
    }

    func show(_ group: ServerGroup, cpu: [Double], mem: [Double]) {
        cpuChart.set(value: Scanner.formatCPU(group.cpu), samples: cpu, floor: 5)
        memChart.set(value: Scanner.formatBytes(group.rss), samples: mem, floor: 1, relative: true)
        let count = group.processes.count
        title.stringValue = count == 1 ? L("1 process", "1 proces") : L("\(count) processes", "\(count) processen")
        // Busiest first; rows are reused per pid so they don't flicker.
        let shown = group.processes.sorted { $0.cpu == $1.cpu ? $0.rss > $1.rss : $0.cpu > $1.cpu }.prefix(ServerDetail.maxRows)
        var existing = Dictionary(rows.map { ($0.pid, $0) }, uniquingKeysWith: { first, _ in first })
        rows = shown.map { process in
            if let row = existing.removeValue(forKey: process.pid) {
                row.update(process)
                return row
            }
            let row = ProcessDetailRow(process: process, copy: copy)
            addSubview(row)
            return row
        }
        existing.values.forEach { $0.removeFromSuperview() }
        let hidden = count - rows.count
        more.stringValue = L("… and \(hidden) more", "… en nog \(hidden)")
        more.isHidden = hidden <= 0
        needsLayout = true
        needsDisplay = true
    }

    override var isFlipped: Bool { true }

    override func layout() {
        super.layout()
        let inner = bounds.insetBy(dx: Metrics.inset + 6, dy: 0)
        var y: CGFloat = 8
        let half = inner.width / 2
        cpuChart.frame = NSRect(x: inner.minX, y: y, width: half, height: ServerDetail.chartHeight)
        memChart.frame = NSRect(x: inner.minX + half, y: y, width: half, height: ServerDetail.chartHeight)
        y += ServerDetail.chartHeight
        title.frame = NSRect(x: Metrics.inset + 14, y: y + 6, width: 200, height: 14)
        y += 24
        for row in rows {
            row.frame = NSRect(x: 0, y: y, width: bounds.width, height: ServerDetail.rowHeight)
            y += ServerDetail.rowHeight
        }
        more.frame = NSRect(x: Metrics.inset + 14, y: y + 2, width: 200, height: 14)
    }

    override func draw(_ dirtyRect: NSRect) {
        // A soft panel that hangs under the card it belongs to.
        let panel = NSRect(x: Metrics.inset + 4, y: 0, width: bounds.width - (Metrics.inset + 4) * 2, height: bounds.height - 4)
        let path = NSBezierPath(roundedRect: panel, xRadius: 12, yRadius: 12)
        NSColor.labelColor.withAlphaComponent(0.035).setFill()
        path.fill()
        for (index, row) in rows.enumerated() where index > 0 {
            Term.line.setFill()
            NSRect(x: Metrics.inset + 14, y: row.frame.minY, width: bounds.width - (Metrics.inset + 14) * 2, height: 1).fill()
        }
    }
}

final class EmptyState: NSView {
    override func draw(_ dirtyRect: NSRect) {
        let circle = NSRect(x: bounds.midX - 24, y: bounds.midY + 4, width: 48, height: 48)
        Term.fill.setFill()
        NSBezierPath(ovalIn: circle).fill()
        drawSymbol("server.rack", in: circle, pointSize: 19, color: Term.dim)
        Draw.text(L("No dev servers running", "Geen dev servers actief"), font: termFont(13, .semibold), color: Term.ink,
                  centeredAt: NSPoint(x: bounds.midX, y: bounds.midY - 12))
        Draw.text(L("Start one (npm run dev, …) and it shows up here", "Start er een (npm run dev, …) en hij verschijnt hier"),
                  font: termFont(11, .regular), color: Term.dim, centeredAt: NSPoint(x: bounds.midX, y: bounds.midY - 30))
    }
}

final class ListColumn: NSView {
    override var isFlipped: Bool { true }
}

// Liquid Glass on macOS 26+, a rounded vibrancy backdrop on older systems.
final class ChromeView: NSView {
    private let surface: NSView

    override init(frame frameRect: NSRect) {
        if #available(macOS 26.0, *) {
            let glass = NSGlassEffectView()
            glass.style = .regular
            glass.cornerRadius = 22
            surface = glass
        } else {
            let blur = NSVisualEffectView()
            blur.material = .menu
            blur.blendingMode = .behindWindow
            blur.state = .active
            blur.wantsLayer = true
            blur.layer?.cornerRadius = 14
            blur.layer?.masksToBounds = true
            surface = blur
        }
        super.init(frame: frameRect)
        pin(surface, to: self)
    }

    required init?(coder: NSCoder) { fatalError() }

    func host(_ content: NSView) {
        if #available(macOS 26.0, *), let glass = surface as? NSGlassEffectView {
            glass.contentView = content
        } else {
            surface.addSubview(content)
        }
        content.translatesAutoresizingMaskIntoConstraints = false
        NSLayoutConstraint.activate([
            content.leadingAnchor.constraint(equalTo: surface.leadingAnchor),
            content.trailingAnchor.constraint(equalTo: surface.trailingAnchor),
            content.topAnchor.constraint(equalTo: surface.topAnchor),
            content.bottomAnchor.constraint(equalTo: surface.bottomAnchor),
        ])
    }

    private func pin(_ view: NSView, to parent: NSView) {
        view.translatesAutoresizingMaskIntoConstraints = false
        parent.addSubview(view)
        NSLayoutConstraint.activate([
            view.leadingAnchor.constraint(equalTo: parent.leadingAnchor),
            view.trailingAnchor.constraint(equalTo: parent.trailingAnchor),
            view.topAnchor.constraint(equalTo: parent.topAnchor),
            view.bottomAnchor.constraint(equalTo: parent.bottomAnchor),
        ])
    }
}

final class MenuPanel: NSPanel {
    override var canBecomeKey: Bool { true }
    override var canBecomeMain: Bool { false }

    init() {
        super.init(
            contentRect: NSRect(x: 0, y: 0, width: Metrics.width, height: 320),
            styleMask: [.borderless, .nonactivatingPanel],
            backing: .buffered,
            defer: false)
        isFloatingPanel = true
        level = .popUpMenu
        isOpaque = false
        backgroundColor = .clear
        hasShadow = true
        hidesOnDeactivate = false
        isMovable = false
        isReleasedWhenClosed = false
        acceptsMouseMovedEvents = true
        animationBehavior = .utilityWindow
        collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary, .transient, .ignoresCycle]
    }
}


final class TabBar: NSView {
    let titles = [L("Servers", "Servers"), L("Activity", "Activiteit"), L("Storage", "Opslag"), L("Clipboard", "Klembord")]
    let symbols = ["server.rack", "waveform.path.ecg", "internaldrive", "list.clipboard"]
    var selected = 0 { didSet { needsDisplay = true } }
    var onSelect: (Int) -> Void = { _ in }
    private var hover = -1

    override init(frame frameRect: NSRect) {
        super.init(frame: frameRect)
        let area = NSTrackingArea(rect: .zero, options: [.mouseMoved, .mouseEnteredAndExited, .activeAlways, .inVisibleRect], owner: self, userInfo: nil)
        addTrackingArea(area)
    }

    required init?(coder: NSCoder) { fatalError() }

    private var track: NSRect { bounds.insetBy(dx: Metrics.inset, dy: 5) }

    override func draw(_ dirtyRect: NSRect) {
        let track = self.track
        let trackPath = NSBezierPath(roundedRect: track, xRadius: track.height / 2, yRadius: track.height / 2)
        Term.fill.setFill()
        trackPath.fill()

        let width = track.width / CGFloat(titles.count)
        for (index, title) in titles.enumerated() {
            let rect = NSRect(x: track.minX + CGFloat(index) * width, y: track.minY, width: width, height: track.height)
            let on = index == selected
            if on {
                let pill = rect.insetBy(dx: 3, dy: 3)
                let path = NSBezierPath(roundedRect: pill, xRadius: pill.height / 2, yRadius: pill.height / 2)
                NSGraphicsContext.saveGraphicsState()
                let shadow = NSShadow()
                shadow.shadowColor = NSColor.black.withAlphaComponent(0.18)
                shadow.shadowBlurRadius = 4
                shadow.shadowOffset = NSSize(width: 0, height: -1)
                shadow.set()
                NSColor.labelColor.withAlphaComponent(0.14).setFill()
                path.fill()
                NSGraphicsContext.restoreGraphicsState()
            }
            let face = termFont(12, on ? .semibold : .medium)
            let color: NSColor = on || index == hover ? Term.ink : Term.dim
            let textWidth = Draw.width(title, font: face)
            let total = textWidth + 18
            let x = rect.midX - total / 2
            drawSymbol(symbols[index], in: NSRect(x: x, y: rect.minY, width: 13, height: rect.height), pointSize: 11,
                       weight: on ? .semibold : .medium, color: on ? Term.accent : color)
            let attrs: [NSAttributedString.Key: Any] = [.font: face, .foregroundColor: color]
            let height = (title as NSString).size(withAttributes: attrs).height
            (title as NSString).draw(at: NSPoint(x: x + 18, y: rect.midY - height / 2), withAttributes: attrs)
        }
    }

    override func mouseMoved(with event: NSEvent) {
        let index = index(at: event)
        guard index != hover else { return }
        hover = index
        needsDisplay = true
    }

    override func mouseExited(with event: NSEvent) {
        hover = -1
        needsDisplay = true
    }

    override func mouseDown(with event: NSEvent) {
        let index = index(at: event)
        guard index != selected else { return }
        selected = index
        onSelect(index)
    }

    private func index(at event: NSEvent) -> Int {
        let x = convert(event.locationInWindow, from: nil).x - track.minX
        let width = max(1, track.width / CGFloat(titles.count))
        return min(titles.count - 1, max(0, Int(x / width)))
    }
}

// MARK: - Activity

final class Gauge: NSView {
    private lazy var eased = EasedValues(count: 1, view: self)
    private let caption: String
    private let tint: NSColor
    private var fraction = 0.0
    private var value = "–"
    private var detail = ""

    init(caption: String, tint: NSColor) {
        self.caption = caption
        self.tint = tint
        super.init(frame: .zero)
    }

    required init?(coder: NSCoder) { fatalError() }

    func set(fraction: Double, value: String, detail: String) {
        self.fraction = fraction
        self.value = value
        self.detail = detail
        eased.set([fraction])
        needsDisplay = true
    }

    override func draw(_ dirtyRect: NSRect) {
        let diameter: CGFloat = min(80, bounds.width - 16)
        let center = NSPoint(x: bounds.midX, y: bounds.maxY - 8 - diameter / 2)
        let shown = eased[0]
        Draw.ring(center: center, radius: diameter / 2 - 5, width: 9, fraction: shown, tint: Draw.level(shown, tint))
        Draw.text(value, font: roundedFont(18, .bold), color: Term.ink, centeredAt: center)
        let captionY = bounds.maxY - 8 - diameter - 12
        Draw.text(caption, font: termFont(12, .semibold), color: Term.ink, centeredAt: NSPoint(x: bounds.midX, y: captionY))
        if !detail.isEmpty {
            Draw.text(detail, font: digitFont(10, .regular), color: Term.dim, centeredAt: NSPoint(x: bounds.midX, y: captionY - 15))
        }
    }
}

final class HistoryCard: NSView {
    private var trace = Trace()

    func set(_ trace: Trace) {
        self.trace = trace
        needsDisplay = true
    }

    override func draw(_ dirtyRect: NSRect) {
        let card = bounds.insetBy(dx: Metrics.inset, dy: 4)
        Draw.card(card)
        Draw.text(L("History", "Verloop"), font: termFont(12, .semibold), color: Term.ink, at: NSPoint(x: card.minX + 14, y: card.maxY - 24))

        var x = card.maxX - 14
        for (name, color) in [(L("Mem", "Geh."), Term.mem), ("GPU", Term.gpu), ("CPU", Term.cpu)] {
            let width = Draw.width(name, font: termFont(10, .semibold))
            x -= width
            Draw.text(name, font: termFont(10, .semibold), color: Term.dim, at: NSPoint(x: x, y: card.maxY - 23))
            x -= 10
            color.setFill()
            NSBezierPath(ovalIn: NSRect(x: x, y: card.maxY - 18, width: 6, height: 6)).fill()
            x -= 12
        }

        let plot = NSRect(x: card.minX + 14, y: card.minY + 12, width: card.width - 28, height: card.height - 44)
        Term.stroke.setFill()
        for step in 0...2 {
            NSRect(x: plot.minX, y: plot.minY + plot.height * CGFloat(step) / 2, width: plot.width, height: 1).fill()
        }
        Draw.spark(trace.mem, in: plot, tint: Term.mem, lineWidth: 1.4, fill: false, capacity: Trace.capacity)
        Draw.spark(trace.gpu, in: plot, tint: Term.gpu, lineWidth: 1.4, fill: false, capacity: Trace.capacity)
        Draw.spark(trace.cpu, in: plot, tint: Term.cpu, lineWidth: 1.8, fill: true, capacity: Trace.capacity)
    }
}

// Battery level, charging state, health and the Mac's thermal state.
final class PowerCard: NSView {
    private var info = PowerInfo()
    private lazy var eased = EasedValues(count: 1, view: self)

    func set(_ info: PowerInfo) {
        self.info = info
        eased.set([Double(info.level) / 100])
        needsDisplay = true
    }

    private static func duration(_ minutes: Int) -> String {
        minutes >= 60 ? "\(minutes / 60)\(L("h", "u")) \(minutes % 60)m" : "\(minutes)m"
    }

    override func draw(_ dirtyRect: NSRect) {
        let card = bounds.insetBy(dx: Metrics.inset, dy: 4)
        Draw.card(card)
        let center = NSPoint(x: card.minX + 14 + 28, y: card.midY)
        if info.hasBattery {
            let tint: NSColor = info.level <= 20 ? .systemRed : (info.level <= 40 ? .systemOrange : .systemGreen)
            Draw.ring(center: center, radius: 25, width: 7, fraction: eased[0], tint: tint)
            Draw.text("\(info.level)%", font: roundedFont(13, .bold), color: Term.ink, centeredAt: center)
        } else {
            Draw.tile("powerplug.fill", in: NSRect(x: center.x - 18, y: center.y - 18, width: 36, height: 36), color: .systemGreen)
        }

        let x = card.minX + 86
        let state: String
        let time: String
        if !info.hasBattery {
            state = L("Power adapter", "Netstroom")
            time = L("No battery", "Geen batterij")
        } else if info.charging {
            state = L("Charging", "Opladen")
            time = info.minutesLeft.map { PowerCard.duration($0) + " " + L("to full", "tot vol") } ?? L("Calculating…", "Berekenen…")
        } else if info.pluggedIn {
            state = L("Plugged in", "Aan de lader")
            time = L("Not charging", "Laadt niet")
        } else {
            state = L("On battery", "Op batterij")
            time = info.minutesLeft.map { PowerCard.duration($0) + " " + L("left", "over") } ?? L("Calculating…", "Berekenen…")
        }
        if info.charging {
            drawSymbol("bolt.fill", in: NSRect(x: x, y: card.midY + 10, width: 10, height: 16), pointSize: 10, weight: .bold, color: .systemGreen)
        }
        Draw.text(state, font: termFont(13, .semibold), color: Term.ink, at: NSPoint(x: x + (info.charging ? 14 : 0), y: card.midY + 10))
        Draw.text(time, font: digitFont(11, .regular), color: Term.dim, at: NSPoint(x: x, y: card.midY - 6))
        var facts: [String] = []
        if let health = info.health { facts.append(L("Health", "Conditie") + " \(Int((health * 100).rounded()))%") }
        if let cycles = info.cycles { facts.append("\(cycles) " + L("cycles", "cycli")) }
        if let watts = info.watts { facts.append(String(format: "%.1f W", abs(watts))) }
        if !facts.isEmpty {
            Draw.text(facts.joined(separator: "  ·  "), font: digitFont(11, .regular), color: Term.dim, at: NSPoint(x: x, y: card.midY - 22))
        }

        // Thermal state pill, top right
        let (label, color): (String, NSColor) = {
            switch info.thermal {
            case .nominal: return (L("Cool", "Koel"), .systemGreen)
            case .fair: return (L("Warm", "Warm"), .systemYellow)
            case .serious: return (L("Hot", "Heet"), .systemOrange)
            case .critical: return (L("Critical", "Kritiek"), .systemRed)
            @unknown default: return ("–", Term.dim)
            }
        }()
        let font = termFont(10.5, .semibold)
        let text = L("Thermals", "Warmte") + ": " + label
        let width = Draw.width(text, font: font) + 24
        let pill = NSRect(x: card.maxX - 12 - width, y: card.maxY - 12 - 20, width: width, height: 20)
        color.withAlphaComponent(0.16).setFill()
        NSBezierPath(roundedRect: pill, xRadius: 10, yRadius: 10).fill()
        drawSymbol("thermometer.medium", in: NSRect(x: pill.minX + 6, y: pill.minY, width: 10, height: pill.height), pointSize: 9, weight: .semibold, color: color)
        Draw.text(text, font: font, color: color, at: NSPoint(x: pill.minX + 18, y: pill.midY - 7))
    }
}

// One app (with its helpers) or one plain process.
final class ProcessRow: HoverView {
    private(set) var usage: AppUsage
    var fraction: Double = 0 { didSet { needsDisplay = true } }
    private let name: NSTextField
    private let detail: NSTextField
    private let cpu: NSTextField
    private let mem: NSTextField
    private let quit: IconButton
    private static var icons: [String: NSImage] = [:]

    init(usage: AppUsage, quit quitAction: @escaping (AppUsage) -> Void) {
        self.usage = usage
        name = makeLabel(usage.name, size: 12, weight: .medium, color: Term.ink)
        detail = makeLabel("", size: 10, weight: .regular, color: Term.dim)
        cpu = makeLabel("", size: 12, weight: .semibold, color: Term.ink)
        cpu.font = roundedFont(12, .semibold)
        cpu.alignment = .right
        mem = makeLabel("", size: 11, weight: .medium, color: Term.dim)
        mem.font = digitFont(11, .medium)
        mem.alignment = .right
        quit = IconButton(symbol: "xmark.circle", help: L("Quit…", "Stop…"), destructive: true) {}
        super.init(frame: .zero)
        quit.onClick = { [weak self] in
            guard let self else { return }
            quitAction(self.usage)
        }
        toolTip = usage.id
        for view in [name, detail, cpu, mem, quit] as [NSView] { addSubview(view) }
        quit.isHidden = true
        update(usage)
    }

    required init?(coder: NSCoder) { fatalError() }

    func update(_ usage: AppUsage) {
        self.usage = usage
        cpu.stringValue = Scanner.formatCPU(usage.cpu)
        cpu.textColor = usage.cpu >= 50 ? .systemOrange : (usage.cpu < 0.5 ? Term.dim : Term.ink)
        mem.stringValue = Scanner.formatBytes(usage.rss)
        let count = usage.pids.count
        var text = count == 1 ? "pid \(usage.pids[0])" : "\(count) " + L("processes", "processen")
        if !usage.owned { text += "  ·  " + L("system", "systeem") }
        detail.stringValue = text
    }

    override func refresh() {
        super.refresh()
        quit.isHidden = !(hovered && usage.owned)
    }

    override func hitTest(_ point: NSPoint) -> NSView? {
        let local = convert(point, from: superview)
        guard bounds.contains(local) else { return nil }
        if !quit.isHidden, quit.frame.contains(local) { return quit }
        return self
    }

    override func resetCursorRects() {}

    override func layout() {
        super.layout()
        let right = bounds.width - Metrics.inset - 8
        mem.frame = NSRect(x: right - 52, y: (bounds.height - 14) / 2, width: 52, height: 14)
        cpu.frame = NSRect(x: mem.frame.minX - 56, y: (bounds.height - 16) / 2, width: 52, height: 16)
        quit.frame = NSRect(x: cpu.frame.minX - 30, y: (bounds.height - 22) / 2, width: 24, height: 22)
        let left = Metrics.inset + 44
        name.frame = NSRect(x: left, y: bounds.height / 2, width: max(30, quit.frame.minX - left - 6), height: 15)
        detail.frame = NSRect(x: left, y: bounds.height / 2 - 14, width: max(30, quit.frame.minX - left - 6), height: 13)
    }

    override func draw(_ dirtyRect: NSRect) {
        if hovered {
            let path = NSBezierPath(roundedRect: bounds.insetBy(dx: Metrics.inset, dy: 1), xRadius: 10, yRadius: 10)
            Term.fill.setFill()
            path.fill()
        }
        let iconRect = NSRect(x: Metrics.inset + 10, y: bounds.midY - 13, width: 26, height: 26)
        if let bundle = usage.bundlePath {
            let icon = ProcessRow.icons[bundle] ?? NSWorkspace.shared.icon(forFile: bundle)
            ProcessRow.icons[bundle] = icon
            icon.draw(in: iconRect, from: .zero, operation: .sourceOver, fraction: 1)
        } else {
            Draw.tile(usage.owned ? "terminal.fill" : "gearshape.fill", in: iconRect.insetBy(dx: 1, dy: 1),
                      color: usage.owned ? .systemIndigo : .systemGray)
        }
        // CPU share of the busiest entry
        let bar = NSRect(x: cpu.frame.minX - 4 - 44, y: bounds.midY - 2, width: 44, height: 4)
        if fraction > 0.01, bar.minX > name.frame.minX + 60 {
            Term.fill.setFill()
            NSBezierPath(roundedRect: bar, xRadius: 2, yRadius: 2).fill()
            var filled = bar
            filled.size.width = max(bar.height, bar.width * CGFloat(min(1, fraction)))
            (usage.cpu >= 50 ? NSColor.systemOrange : Term.cpu).setFill()
            NSBezierPath(roundedRect: filled, xRadius: 2, yRadius: 2).fill()
        }
    }
}

final class ActivityPane: NSView {
    override var isFlipped: Bool { true }
    var onQuit: (AppUsage) -> Void = { _ in }
    var onResize: () -> Void = {}
    private let cpu = Gauge(caption: "CPU", tint: Term.cpu)
    private let gpu = Gauge(caption: "GPU", tint: Term.gpu)
    private let mem = Gauge(caption: L("Memory", "Geheugen"), tint: Term.mem)
    private let history = HistoryCard()
    private let power = PowerCard()
    private let section = makeLabel(L("Apps & processes", "Apps en processen"), size: 11, weight: .semibold, color: Term.dim)
    private let filter = CleanFilterRow(placeholder: L("Search apps and processes", "Zoek apps en processen"),
                                        titles: ["CPU", L("Memory", "Geheugen"), L("Name", "Naam")])
    private let more = makeLabel("", size: 11, weight: .medium, color: Term.dim)
    private var all: [AppUsage] = []
    private var rows: [ProcessRow] = []
    private var query = ""
    private var sort = 0  // 0 CPU, 1 memory, 2 name
    private static let limit = 40

    override init(frame frameRect: NSRect) {
        super.init(frame: frameRect)
        for view in [cpu, gpu, mem, history, power, section, filter, more] as [NSView] { addSubview(view) }
        more.alignment = .center
        more.isHidden = true
        filter.onChange = { [weak self] query, sort in
            guard let self else { return }
            self.query = query
            self.sort = sort.rawValue
            self.rebuild()
            self.onResize()
        }
    }

    required init?(coder: NSCoder) { fatalError() }

    var contentHeight: CGFloat {
        Metrics.listPad + Metrics.gauges + Metrics.history + Metrics.power + Metrics.section + Metrics.filterRow
            + CGFloat(rows.count) * Metrics.proc + (more.isHidden ? 0 : 30) + Metrics.listPad * 2
    }

    func setCharts(_ vitals: Vitals, _ trace: Trace) {
        let cores = ProcessInfo.processInfo.activeProcessorCount
        cpu.set(fraction: vitals.cpu / 100, value: "\(Int(vitals.cpu.rounded()))%", detail: "\(cores) " + L("cores", "kernen"))
        gpu.set(fraction: vitals.gpu / 100, value: "\(Int(vitals.gpu.rounded()))%", detail: L("utilization", "belasting"))
        let used = vitals.total > 0 ? Double(vitals.used) / Double(vitals.total) : 0
        mem.set(fraction: used, value: "\(Int((used * 100).rounded()))%",
                detail: "\(Scanner.formatBytes(vitals.used)) / \(Scanner.formatBytes(vitals.total))")
        history.set(trace)
    }

    func showPower(_ info: PowerInfo) {
        power.set(info)
    }

    func showProcesses(_ list: [AppUsage]) {
        all = list
        rebuild()
        onResize()
    }

    // Rows are kept per app so they update in place instead of flickering.
    private func rebuild() {
        let needle = query.trimmingCharacters(in: .whitespaces).lowercased()
        var shown = needle.isEmpty ? all : all.filter { $0.name.lowercased().contains(needle) || $0.id.lowercased().contains(needle) }
        switch sort {
        case 1: shown.sort { $0.rss > $1.rss }
        case 2: shown.sort { $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending }
        default: shown.sort { $0.cpu == $1.cpu ? $0.rss > $1.rss : $0.cpu > $1.cpu }
        }
        let hidden = max(0, shown.count - ActivityPane.limit)
        shown = Array(shown.prefix(ActivityPane.limit))
        let peak = max(1, shown.map(\.cpu).max() ?? 0)
        var existing = Dictionary(rows.map { ($0.usage.id, $0) }, uniquingKeysWith: { first, _ in first })
        rows = shown.map { usage in
            let row = existing.removeValue(forKey: usage.id) ?? {
                let row = ProcessRow(usage: usage) { [weak self] in self?.onQuit($0) }
                addSubview(row)
                return row
            }()
            row.update(usage)
            row.fraction = usage.cpu / peak
            return row
        }
        existing.values.forEach { $0.removeFromSuperview() }
        more.stringValue = L("\(hidden) more — search to find them", "nog \(hidden) — zoek om ze te vinden")
        more.isHidden = hidden == 0
        needsLayout = true
    }

    override func layout() {
        super.layout()
        var y = Metrics.listPad
        let slot = (bounds.width - Metrics.inset * 2) / 3
        for (index, gauge) in [cpu, gpu, mem].enumerated() {
            gauge.frame = NSRect(x: Metrics.inset + CGFloat(index) * slot, y: y, width: slot, height: Metrics.gauges)
        }
        y += Metrics.gauges
        history.frame = NSRect(x: 0, y: y, width: bounds.width, height: Metrics.history)
        y += Metrics.history
        power.frame = NSRect(x: 0, y: y, width: bounds.width, height: Metrics.power)
        y += Metrics.power
        section.frame = NSRect(x: Metrics.inset + 6, y: y + 10, width: 200, height: 14)
        y += Metrics.section
        filter.frame = NSRect(x: 0, y: y, width: bounds.width, height: Metrics.filterRow)
        y += Metrics.filterRow
        for row in rows {
            row.frame = NSRect(x: 0, y: y, width: bounds.width, height: Metrics.proc)
            y += Metrics.proc
        }
        more.frame = NSRect(x: 16, y: y + 7, width: max(0, bounds.width - 32), height: 16)
    }
}

// MARK: - Storage

final class VolumeCard: NSView {
    private var volume: DiskVolume
    private lazy var eased = EasedValues(count: 1, view: self)

    init(volume: DiskVolume) {
        self.volume = volume
        super.init(frame: .zero)
        eased.set([volume.fraction])
    }

    func update(_ volume: DiskVolume) {
        self.volume = volume
        eased.set([volume.fraction])
    }

    required init?(coder: NSCoder) { fatalError() }

    override func draw(_ dirtyRect: NSRect) {
        let card = bounds.insetBy(dx: Metrics.inset, dy: 4)
        Draw.card(card)
        let f = volume.fraction
        let center = NSPoint(x: card.minX + 14 + 28, y: card.midY)
        Draw.ring(center: center, radius: 25, width: 7, fraction: eased[0], tint: Draw.level(eased[0], Term.disk))
        Draw.text("\(Int((f * 100).rounded()))%", font: roundedFont(13, .bold), color: Term.ink, centeredAt: center)

        let x = card.minX + 86
        Draw.text(volume.name, font: termFont(13, .semibold), color: Term.ink, at: NSPoint(x: x, y: card.midY + 3))
        let free = "\(Scanner.formatBytes(volume.free)) " + L("free of", "vrij van") + " \(Scanner.formatBytes(volume.total))"
        Draw.text(free, font: digitFont(11, .regular), color: Term.dim, at: NSPoint(x: x, y: card.midY - 15))

        let used = Scanner.formatBytes(volume.used)
        let usedFont = roundedFont(15, .bold)
        let usedWidth = Draw.width(used, font: usedFont)
        Draw.text(used, font: usedFont, color: Draw.level(f, Term.ink), at: NSPoint(x: card.maxX - 16 - usedWidth, y: card.midY + 1))
        let caption = L("used", "gebruikt")
        let captionWidth = Draw.width(caption, font: termFont(10, .medium))
        Draw.text(caption, font: termFont(10, .medium), color: Term.dim, at: NSPoint(x: card.maxX - 16 - captionWidth, y: card.midY - 15))
    }
}

// Round check mark: 0 = off, 1 = some (group), 2 = on.
func drawCheck(_ state: Int, in rect: NSRect) {
    guard state > 0 else {
        drawSymbol("circle", in: rect, pointSize: 15, weight: .regular, color: Term.faint)
        return
    }
    // Two-tone: white mark on an accent disc.
    let config = NSImage.SymbolConfiguration(pointSize: 15, weight: .semibold)
        .applying(NSImage.SymbolConfiguration(paletteColors: [.white, Term.accent]))
    guard let image = NSImage(systemSymbolName: state == 2 ? "checkmark.circle.fill" : "minus.circle.fill",
                              accessibilityDescription: nil)?.withSymbolConfiguration(config) else { return }
    let size = image.size
    image.draw(in: NSRect(x: rect.midX - size.width / 2, y: rect.midY - size.height / 2, width: size.width, height: size.height),
               from: .zero, operation: .sourceOver, fraction: 1, respectFlipped: true, hints: nil)
}

// Filled pill button for the main action.
final class AccentButton: HoverView {
    var title = "" { didSet { needsDisplay = true } }
    var enabled = true { didSet { needsDisplay = true } }
    private static let font = termFont(12, .semibold)

    var preferredWidth: CGFloat { Draw.width(title, font: AccentButton.font) + 28 }

    init(action: @escaping () -> Void) {
        super.init(frame: .zero)
        onClick = { [weak self] in
            if self?.enabled == true { action() }
        }
        setAccessibilityRole(.button)
    }

    required init?(coder: NSCoder) { fatalError() }

    override func resetCursorRects() {
        if enabled { super.resetCursorRects() }
    }

    override func draw(_ dirtyRect: NSRect) {
        let path = NSBezierPath(roundedRect: bounds, xRadius: bounds.height / 2, yRadius: bounds.height / 2)
        if enabled {
            (hovered ? Term.accent.blended(withFraction: 0.15, of: .white) ?? Term.accent : Term.accent).setFill()
        } else {
            Term.fill.setFill()
        }
        path.fill()
        Draw.text(title, font: AccentButton.font, color: enabled ? .white : Term.dim, centeredAt: NSPoint(x: bounds.midX, y: bounds.midY))
        setAccessibilityLabel(title)
    }
}

// Summary card above the cleanup list: what was found, what is selected, and the Clean button.
final class CleanHeader: NSView {
    var onClean: () -> Void = {}
    var onRescan: () -> Void = {}
    private var scanned = false
    // Before the first scan the main button scans; after that it cleans.
    private lazy var clean = AccentButton { [weak self] in
        guard let self else { return }
        if self.scanned { self.onClean() } else { self.onRescan() }
    }
    private lazy var rescan = IconButton(symbol: "arrow.clockwise", help: L("Scan again", "Opnieuw scannen")) { [weak self] in self?.onRescan() }
    private let spinner = NSProgressIndicator()
    private var subtitle = ""
    private let title: String
    private let symbol: String
    private let idle: String

    init(title: String, symbol: String, idle: String) {
        self.title = title
        self.symbol = symbol
        self.idle = idle
        super.init(frame: .zero)
        spinner.style = .spinning
        spinner.controlSize = .small
        spinner.isDisplayedWhenStopped = false
        addSubview(clean)
        addSubview(rescan)
        addSubview(spinner)
    }

    required init?(coder: NSCoder) { fatalError() }

    func set(found: UInt64, selected: UInt64, count: Int, scanning: Bool, scanned: Bool) {
        self.scanned = scanned
        if !scanned && !scanning {
            subtitle = idle
            rescan.isHidden = true
            clean.title = L("Scan", "Scannen")
            clean.enabled = true
            needsLayout = true
            needsDisplay = true
            return
        }
        if scanning {
            subtitle = L("Scanning…", "Scannen…") + (found > 0 ? "  \(Scanner.formatBytes(found)) " + L("so far", "tot nu toe") : "")
            spinner.startAnimation(nil)
        } else {
            subtitle = found == 0
                ? L("Nothing found yet", "Nog niets gevonden")
                : "\(Scanner.formatBytes(found)) " + L("found", "gevonden") + "  ·  \(count) " + L("selected", "geselecteerd")
            spinner.stopAnimation(nil)
        }
        rescan.isHidden = scanning
        clean.title = selected > 0 ? L("Clean", "Opschonen") + " " + Scanner.formatBytes(selected) : L("Clean", "Opschonen")
        clean.enabled = selected > 0 && !scanning
        needsLayout = true
        needsDisplay = true
    }

    override func layout() {
        super.layout()
        let card = bounds.insetBy(dx: Metrics.inset, dy: 4)
        let width = clean.preferredWidth
        clean.frame = NSRect(x: card.maxX - 12 - width, y: card.midY - 14, width: width, height: 28)
        rescan.frame = NSRect(x: clean.frame.minX - 32, y: card.midY - 12, width: 26, height: 24)
        spinner.frame = NSRect(x: clean.frame.minX - 28, y: card.midY - 8, width: 16, height: 16)
    }

    override func draw(_ dirtyRect: NSRect) {
        let card = bounds.insetBy(dx: Metrics.inset, dy: 4)
        Draw.card(card, radius: 16)
        Draw.tile(symbol, in: NSRect(x: card.minX + 12, y: card.midY - 15, width: 30, height: 30), color: Term.accent)
        Draw.text(title, font: termFont(13, .semibold), color: Term.ink,
                  at: NSPoint(x: card.minX + 52, y: card.midY + 1))
        Draw.text(subtitle, font: digitFont(11, .regular), color: Term.dim, at: NSPoint(x: card.minX + 52, y: card.midY - 15))
    }
}

final class StackBar: NSView {
    private var parts: [(CGFloat, NSColor)] = []

    // Up to six coloured parts, biggest first; the rest is merged into one grey part.
    func set(groups: [CleanGroup]) {
        let total = groups.reduce(UInt64(0)) { $0 + $1.bytes }
        guard total > 0 else {
            parts = []
            needsDisplay = true
            return
        }
        let palette: [NSColor] = [.systemBlue, .systemPurple, .systemTeal, .systemPink, .systemOrange, .systemGreen]
        let distinct = Set(groups.map { $0.color.description }).count == groups.count
        let ranked = groups.count > 6 ? groups.sorted { $0.bytes > $1.bytes } : groups
        parts = ranked.prefix(6).enumerated().map { index, group in
            (CGFloat(group.bytes) / CGFloat(total), distinct && groups.count <= 6 ? group.color : palette[index])
        }
        let rest = ranked.dropFirst(6).reduce(UInt64(0)) { $0 + $1.bytes }
        if rest > 0 { parts.append((CGFloat(rest) / CGFloat(total), NSColor.systemGray)) }
        needsDisplay = true
    }

    override func draw(_ dirtyRect: NSRect) {
        let bar = bounds.insetBy(dx: Metrics.inset + 4, dy: 7)
        let shape = NSBezierPath(roundedRect: bar, xRadius: bar.height / 2, yRadius: bar.height / 2)
        Term.fill.setFill()
        shape.fill()
        guard !parts.isEmpty else { return }
        NSGraphicsContext.saveGraphicsState()
        shape.addClip()
        var x = bar.minX
        for (fraction, color) in parts {
            let width = bar.width * fraction
            color.setFill()
            NSRect(x: x, y: bar.minY, width: max(0, width - 1.5), height: bar.height).fill()
            x += width
        }
        NSGraphicsContext.restoreGraphicsState()
    }
}

// One cleanup category. Click the circle to (de)select all of it, anywhere else to expand.
final class CleanGroupRow: HoverView {
    let group: CleanGroup
    var state = 0 { didSet { needsDisplay = true } }
    var selectedBytes: UInt64 = 0 { didSet { needsDisplay = true } }
    var expanded = false
    var onCheck: () -> Void = {}

    private let icon: NSImage?

    init(group: CleanGroup) {
        self.group = group
        icon = group.iconPath.map { NSWorkspace.shared.icon(forFile: $0) }
        super.init(frame: .zero)
        setAccessibilityRole(.button)
        setAccessibilityLabel(group.title)
    }

    required init?(coder: NSCoder) { fatalError() }

    private var card: NSRect { bounds.insetBy(dx: Metrics.inset, dy: 3) }
    private var checkRect: NSRect { NSRect(x: card.minX + 6, y: card.midY - 12, width: 26, height: 24) }

    override func mouseUp(with event: NSEvent) {
        let point = convert(event.locationInWindow, from: nil)
        pressed = false
        refresh()
        guard bounds.contains(point) else { return }
        if checkRect.insetBy(dx: -4, dy: -6).contains(point) { onCheck() } else { onClick() }
    }

    override func draw(_ dirtyRect: NSRect) {
        let card = self.card
        Draw.card(card, hot: hovered || pressed)
        drawCheck(state, in: checkRect)
        let tile = NSRect(x: card.minX + 36, y: card.midY - 14, width: 28, height: 28)
        if let icon {
            icon.draw(in: tile.insetBy(dx: -2, dy: -2), from: .zero, operation: .sourceOver, fraction: 1)
        } else {
            Draw.tile(group.symbol, in: tile, color: group.color)
        }
        let title = group.title as NSString
        let titleAttrs: [NSAttributedString.Key: Any] = [.font: termFont(12.5, .semibold), .foregroundColor: Term.ink]
        title.draw(with: NSRect(x: card.minX + 74, y: card.midY + 1, width: card.width - 74 - 110, height: 17),
                   options: [.usesLineFragmentOrigin, .truncatesLastVisibleLine], attributes: titleAttrs)
        let count = group.items.count
        var sub = "\(count) " + (count == 1 ? L("item", "item") : L("items", "items"))
        if let note = group.note {
            sub += "  ·  " + note
        } else if selectedBytes > 0 {
            sub += "  ·  \(Scanner.formatBytes(selectedBytes)) " + L("selected", "geselecteerd")
        }
        Draw.text(sub, font: digitFont(10.5, .regular), color: Term.dim, at: NSPoint(x: card.minX + 74, y: card.midY - 14))

        // Reclaimable size; a fully locked group (a running app) shows what it takes up.
        let size = Scanner.formatBytes(group.bytes > 0 ? group.bytes : group.totalBytes)
        let font = roundedFont(13, .semibold)
        let width = Draw.width(size, font: font)
        Draw.text(size, font: font, color: Term.ink, at: NSPoint(x: card.maxX - 32 - width, y: card.midY - 8))
        drawSymbol(expanded ? "chevron.down" : "chevron.right", in: NSRect(x: card.maxX - 24, y: card.minY, width: 14, height: card.height),
                   pointSize: 10, weight: .semibold, color: Term.dim)
    }
}

// One thing that can be removed. Click to (de)select; hover for Reveal in Finder.
final class CleanItemRow: HoverView {
    let item: CleanItem
    var checked = false { didSet { needsDisplay = true } }
    private let title: NSTextField
    private let detail: NSTextField
    private let size: NSTextField
    private var reveal: IconButton?
    private var noteRect = NSRect.zero
    private static let noteFont = termFont(10, .semibold)

    init(item: CleanItem, reveal revealAction: @escaping (String) -> Void) {
        self.item = item
        title = makeLabel(item.title, size: 12, weight: .medium, color: Term.ink)
        detail = makeLabel(item.detail, size: 10, weight: .regular, color: Term.dim)
        detail.lineBreakMode = .byTruncatingMiddle
        detail.cell?.lineBreakMode = .byTruncatingMiddle
        size = makeLabel(Scanner.formatBytes(item.bytes), size: 12, weight: .semibold, color: Term.ink)
        size.font = roundedFont(12, .semibold)
        size.alignment = .right
        super.init(frame: .zero)
        toolTip = item.paths.count == 1 ? item.paths[0] : item.detail
        setAccessibilityRole(.checkBox)
        setAccessibilityLabel(item.title)
        for view in [title, detail, size] { addSubview(view) }
        if item.paths.count == 1, case .trash = item.action {
            let path = item.paths[0]
            let button = IconButton(symbol: "magnifyingglass", help: L("Show in Finder", "Toon in Finder")) { revealAction(path) }
            button.isHidden = true
            addSubview(button)
            reveal = button
        }
    }

    required init?(coder: NSCoder) { fatalError() }

    override func refresh() {
        super.refresh()
        reveal?.isHidden = !hovered
    }

    override func hitTest(_ point: NSPoint) -> NSView? {
        let local = convert(point, from: superview)
        guard bounds.contains(local) else { return nil }
        if let reveal, !reveal.isHidden, reveal.frame.contains(local) { return reveal }
        return self
    }

    override func layout() {
        super.layout()
        let right = bounds.width - Metrics.inset - 6
        reveal?.frame = NSRect(x: right - 24, y: (bounds.height - 22) / 2, width: 24, height: 22)
        size.frame = NSRect(x: right - 28 - 62, y: (bounds.height - 16) / 2, width: 62, height: 16)
        var limit = size.frame.minX - 6
        if let note = item.note {
            let width = Draw.width(note, font: CleanItemRow.noteFont) + 12
            noteRect = NSRect(x: limit - width, y: (bounds.height - 16) / 2, width: width, height: 16)
            limit = noteRect.minX - 6
        } else {
            noteRect = .zero
        }
        let left = Metrics.inset + 40
        title.frame = NSRect(x: left, y: bounds.height / 2, width: max(30, limit - left), height: 15)
        detail.frame = NSRect(x: left, y: bounds.height / 2 - 14, width: max(30, limit - left), height: 13)
    }

    override func draw(_ dirtyRect: NSRect) {
        if hovered || pressed {
            let path = NSBezierPath(roundedRect: bounds.insetBy(dx: Metrics.inset + 4, dy: 1), xRadius: 10, yRadius: 10)
            Term.fill.setFill()
            path.fill()
        }
        let checkRect = NSRect(x: Metrics.inset + 14, y: bounds.midY - 10, width: 20, height: 20)
        if item.locked {
            drawSymbol("lock.fill", in: checkRect, pointSize: 11, weight: .semibold, color: Term.faint)
        } else {
            drawCheck(checked ? 2 : 0, in: checkRect)
        }
        guard let note = item.note, noteRect.width > 0 else { return }
        let color: NSColor
        switch item.noteStyle {
        case .good: color = .systemGreen
        case .danger: color = .systemRed
        case .plain: color = Term.dim
        }
        let pill = NSBezierPath(roundedRect: noteRect, xRadius: 8, yRadius: 8)
        (item.noteStyle == .plain ? Term.fill : color.withAlphaComponent(0.16)).setFill()
        pill.fill()
        Draw.text(note, font: CleanItemRow.noteFont, color: color, centeredAt: NSPoint(x: noteRect.midX, y: noteRect.midY))
    }
}

final class SortChip: HoverView {
    let title: String
    var on = false { didSet { needsDisplay = true } }
    private static let font = termFont(11, .semibold)
    var preferredWidth: CGFloat { Draw.width(title, font: SortChip.font) + 18 }

    init(_ title: String) {
        self.title = title
        super.init(frame: .zero)
        setAccessibilityRole(.radioButton)
        setAccessibilityLabel(title)
    }

    required init?(coder: NSCoder) { fatalError() }

    override func draw(_ dirtyRect: NSRect) {
        let path = NSBezierPath(roundedRect: bounds, xRadius: bounds.height / 2, yRadius: bounds.height / 2)
        if on {
            Term.accent.withAlphaComponent(0.2).setFill()
            path.fill()
        } else if hovered {
            Term.fill.setFill()
            path.fill()
        }
        Draw.text(title, font: SortChip.font, color: on ? Term.accent : Term.dim, centeredAt: NSPoint(x: bounds.midX, y: bounds.midY))
    }
}

// Search field and sort choice for the project leftovers list.
final class CleanFilterRow: NSView, NSTextFieldDelegate {
    enum Sort: Int { case size, age, name }
    var onChange: (String, Sort) -> Void = { _, _ in }
    private let field = NSTextField()
    private var chips: [SortChip] = []
    private var sort = Sort.size

    // The three choices; for storage lists they are size, age and name.
    init(placeholder: String, titles: [String] = [L("Size", "Grootte"), L("Age", "Leeftijd"), L("Name", "Naam")]) {
        super.init(frame: .zero)
        field.isBezeled = false
        field.drawsBackground = false
        field.focusRingType = .none
        field.font = termFont(12, .medium)
        field.textColor = Term.ink
        field.placeholderString = placeholder
        field.delegate = self
        addSubview(field)
        for (index, title) in titles.enumerated() {
            let chip = SortChip(title)
            chip.on = index == sort.rawValue
            chip.onClick = { [weak self] in self?.choose(Sort(rawValue: index) ?? .size) }
            chips.append(chip)
            addSubview(chip)
        }
    }

    required init?(coder: NSCoder) { fatalError() }

    @objc func controlTextDidChange(_ obj: Notification) {
        onChange(field.stringValue, sort)
    }

    private func choose(_ next: Sort) {
        sort = next
        for (index, chip) in chips.enumerated() { chip.on = index == next.rawValue }
        onChange(field.stringValue, sort)
    }

    private var searchRect: NSRect {
        let chipsWidth = chips.reduce(CGFloat(0)) { $0 + $1.preferredWidth + 2 }
        return NSRect(x: Metrics.inset + 10, y: (bounds.height - 28) / 2, width: bounds.width - Metrics.inset * 2 - 26 - chipsWidth, height: 28)
    }

    override func layout() {
        super.layout()
        let search = searchRect
        field.frame = NSRect(x: search.minX + 30, y: search.midY - 8.5, width: search.width - 40, height: 17)
        var x = search.maxX + 8
        for chip in chips {
            chip.frame = NSRect(x: x, y: (bounds.height - 24) / 2, width: chip.preferredWidth, height: 24)
            x += chip.preferredWidth + 2
        }
    }

    override func draw(_ dirtyRect: NSRect) {
        let search = searchRect
        let path = NSBezierPath(roundedRect: search, xRadius: search.height / 2, yRadius: search.height / 2)
        Term.fill.setFill()
        path.fill()
        drawSymbol("magnifyingglass", in: NSRect(x: search.minX + 9, y: search.minY, width: 16, height: search.height),
                   pointSize: 11, weight: .semibold, color: Term.dim)
    }
}

// What a cleanup list shows and how it scans. Cleanup, large files, apps and duplicates are all one of these.
struct CleanListConfig {
    let title: String
    let symbol: String
    let idle: String          // subtitle before the first scan
    let searchPlaceholder: String
    let filterable: Set<String>   // groups that get a search/sort row when expanded
    let expanded: Set<String>     // groups that start expanded
    let order: [String]           // group order while results stream in
}

typealias CleanScanWork = (@escaping (CleanGroup) -> Void) -> [CleanGroup]

// A scannable list of groups with checkboxes, a summary header and one Clean button.
final class CleanListView: NSView {
    override var isFlipped: Bool { true }
    var makeScan: () -> CleanScanWork = { { _ in [] } }  // called on the main thread; the work runs in the background
    var onClean: ([CleanItem], @escaping (Set<String>) -> Void) -> Void = { _, _ in }
    var onReveal: (String) -> Void = { _ in }
    var onResize: () -> Void = {}
    private let config: CleanListConfig
    private let header: CleanHeader
    private let stack = StackBar()
    private let placeholder = makeLabel("", size: 12, weight: .medium, color: Term.dim)
    private let filterRow: CleanFilterRow
    private var groups: [CleanGroup] = []
    private var scanning = false
    private var scanned = false
    private var selected = Set<String>()
    private var known = Set<String>()
    private var expanded: Set<String>
    private var groupRows: [String: CleanGroupRow] = [:]
    private var itemRows: [String: CleanItemRow] = [:]
    private var rows: [NSView] = []
    private var query = ""
    private var sort = CleanFilterRow.Sort.size

    init(config: CleanListConfig) {
        self.config = config
        expanded = config.expanded
        header = CleanHeader(title: config.title, symbol: config.symbol, idle: config.idle)
        filterRow = CleanFilterRow(placeholder: config.searchPlaceholder)
        super.init(frame: .zero)
        placeholder.alignment = .center
        header.onClean = { [weak self] in self?.cleanSelected() }
        header.onRescan = { [weak self] in self?.startScan() }
        filterRow.onChange = { [weak self] query, sort in
            guard let self else { return }
            self.query = query
            self.sort = sort
            self.rebuildRows()
            self.onResize()
        }
        addSubview(header)
        addSubview(stack)
        addSubview(placeholder)
        rebuildRows()
    }

    required init?(coder: NSCoder) { fatalError() }

    var contentHeight: CGFloat {
        var height = Metrics.cleanHeader + 22
        if rows.isEmpty {
            height += Metrics.groupRow
        } else {
            for row in rows { height += rowHeight(row) }
        }
        return height + Metrics.listPad * 2
    }

    // MARK: Scanning

    func startScan() {
        guard !scanning else { return }
        scanning = true
        scanned = true
        let work = makeScan()
        rebuildRows()
        onResize()
        DispatchQueue.global(qos: .utility).async { [weak self] in
            let found = work { group in
                DispatchQueue.main.async { [weak self] in
                    guard let self, self.scanning else { return }
                    self.groups.removeAll { $0.id == group.id }
                    if !group.items.isEmpty { self.groups.append(group) }
                    let order = self.config.order
                    if order.isEmpty {
                        self.groups.sort { $0.bytes > $1.bytes }
                    } else {
                        self.groups.sort { (order.firstIndex(of: $0.id) ?? 99) < (order.firstIndex(of: $1.id) ?? 99) }
                    }
                    self.apply()
                }
            }
            DispatchQueue.main.async { [weak self] in
                guard let self else { return }
                self.scanning = false
                self.groups = found
                self.apply()
            }
        }
    }

    // New items start with their default selection; the user's own choices are kept across scans.
    private func apply() {
        for item in groups.flatMap(\.items) where known.insert(item.id).inserted && item.preselect && !item.locked {
            selected.insert(item.id)
        }
        if !scanning {
            let present = Set(groups.flatMap { $0.items.map(\.id) })
            selected.formIntersection(present)
            known.formIntersection(present)
        }
        rebuildRows()
        onResize()
    }

    // MARK: Rows

    private func rowHeight(_ row: NSView) -> CGFloat {
        if row is CleanGroupRow { return Metrics.groupRow }
        if row === filterRow { return Metrics.filterRow }
        return Metrics.itemRow
    }

    private func visibleItems(_ group: CleanGroup) -> [CleanItem] {
        guard config.filterable.contains(group.id) else { return group.items }
        let needle = query.trimmingCharacters(in: .whitespaces).lowercased()
        let matched = needle.isEmpty ? group.items : group.items.filter {
            $0.title.lowercased().contains(needle) || $0.detail.lowercased().contains(needle)
        }
        switch sort {
        case .size: return matched.sorted { $0.bytes > $1.bytes }
        case .age: return matched.sorted { ($0.age ?? 0) > ($1.age ?? 0) }
        case .name: return matched.sorted { $0.title.localizedCaseInsensitiveCompare($1.title) == .orderedAscending }
        }
    }

    private func rebuildRows() {
        // The filter row is reused, so its search field keeps focus while typing.
        rows.filter { $0 !== filterRow }.forEach { $0.removeFromSuperview() }
        rows = []
        groupRows = [:]
        itemRows = [:]
        for group in groups {
            let row = CleanGroupRow(group: group)
            row.expanded = expanded.contains(group.id)
            row.onClick = { [weak self] in self?.toggleExpanded(group.id) }
            row.onCheck = { [weak self] in self?.toggleGroup(group) }
            groupRows[group.id] = row
            rows.append(row)
            guard row.expanded else { continue }
            if config.filterable.contains(group.id) { rows.append(filterRow) }
            for item in visibleItems(group) {
                let itemRow = CleanItemRow(item: item) { [weak self] in self?.onReveal($0) }
                itemRow.onClick = { [weak self] in self?.toggleItem(item) }
                itemRows[item.id] = itemRow
                rows.append(itemRow)
            }
        }
        if !rows.contains(where: { $0 === filterRow }) { filterRow.removeFromSuperview() }
        rows.filter { $0.superview == nil }.forEach(addSubview)
        if scanning {
            placeholder.stringValue = L("Scanning…", "Scannen…")
        } else if !scanned {
            placeholder.stringValue = L("Press Scan to start", "Druk op Scannen om te beginnen")
        } else {
            placeholder.stringValue = L("Nothing found", "Niets gevonden")
        }
        placeholder.isHidden = !rows.isEmpty
        stack.set(groups: groups)
        refreshChecks()
        needsLayout = true
    }

    private func refreshChecks() {
        var selectedBytes: UInt64 = 0
        var count = 0
        for group in groups {
            let open = group.items.filter { !$0.locked }
            let picked = open.filter { selected.contains($0.id) }
            let bytes = picked.reduce(UInt64(0)) { $0 + $1.bytes }
            groupRows[group.id]?.state = picked.isEmpty ? 0 : (picked.count == open.count ? 2 : 1)
            groupRows[group.id]?.selectedBytes = bytes
            selectedBytes += bytes
            count += picked.count
        }
        for (id, row) in itemRows { row.checked = selected.contains(id) }
        let found = groups.reduce(UInt64(0)) { $0 + $1.bytes }
        header.set(found: found, selected: selectedBytes, count: count, scanning: scanning, scanned: scanned)
    }

    private func toggleItem(_ item: CleanItem) {
        guard !item.locked else { return }
        if selected.contains(item.id) { selected.remove(item.id) } else { selected.insert(item.id) }
        refreshChecks()
    }

    // Acts on what is shown, so a search narrows what gets (de)selected. Locked items are never selected.
    private func toggleGroup(_ group: CleanGroup) {
        let ids = (expanded.contains(group.id) ? visibleItems(group) : group.items).filter { !$0.locked }.map(\.id)
        guard !ids.isEmpty else { return }
        if ids.allSatisfy(selected.contains) {
            ids.forEach { selected.remove($0) }
        } else {
            ids.forEach { selected.insert($0) }
        }
        refreshChecks()
    }

    private func toggleExpanded(_ id: String) {
        if expanded.contains(id) { expanded.remove(id) } else { expanded.insert(id) }
        rebuildRows()
        onResize()
    }

    private func cleanSelected() {
        let items = groups.flatMap(\.items).filter { selected.contains($0.id) && !$0.locked }
        guard !items.isEmpty else { return }
        onClean(items) { [weak self] cleaned in
            guard let self, !cleaned.isEmpty else { return }
            // Drop what is gone instead of rescanning; Scan again refreshes everything.
            self.groups = self.groups.compactMap { group in
                var group = group
                group.items.removeAll { cleaned.contains($0.id) }
                return group.items.contains(where: { !$0.locked }) ? group : nil
            }
            self.selected.subtract(cleaned)
            self.rebuildRows()
            self.onResize()
        }
    }

    override func layout() {
        super.layout()
        var y = Metrics.listPad
        header.frame = NSRect(x: 0, y: y, width: bounds.width, height: Metrics.cleanHeader)
        y += Metrics.cleanHeader
        stack.frame = NSRect(x: 0, y: y, width: bounds.width, height: 22)
        y += 22
        placeholder.frame = NSRect(x: 16, y: y + (Metrics.groupRow - 16) / 2, width: max(0, bounds.width - 32), height: 16)
        for row in rows {
            let height = rowHeight(row)
            row.frame = NSRect(x: 0, y: y, width: bounds.width, height: height)
            y += height
        }
    }
}

// MARK: - Space explorer

final class ExplorerRow: HoverView {
    struct Entry {
        let name: String
        let path: String
        let isFolder: Bool
        var bytes: UInt64?
    }

    private(set) var entry: Entry
    var fraction: Double = 0 { didSet { needsDisplay = true } }
    private let icon: NSImage
    private let name: NSTextField
    private let size: NSTextField
    private let reveal: IconButton
    private let trash: IconButton

    init(entry: Entry, reveal revealAction: @escaping (String) -> Void, trash trashAction: @escaping (Entry) -> Void) {
        self.entry = entry
        icon = NSWorkspace.shared.icon(forFile: entry.path)
        name = makeLabel(entry.name, size: 12, weight: .medium, color: Term.ink)
        size = makeLabel("", size: 12, weight: .semibold, color: Term.ink)
        size.font = roundedFont(12, .semibold)
        size.alignment = .right
        reveal = IconButton(symbol: "magnifyingglass", help: L("Show in Finder", "Toon in Finder")) { revealAction(entry.path) }
        trash = IconButton(symbol: "trash", help: L("Move to Trash…", "Naar prullenmand…"), destructive: true) { trashAction(entry) }
        super.init(frame: .zero)
        toolTip = entry.path
        for view in [name, size, reveal, trash] as [NSView] { addSubview(view) }
        reveal.isHidden = true
        trash.isHidden = true
        update(entry.bytes)
    }

    required init?(coder: NSCoder) { fatalError() }

    func update(_ bytes: UInt64?) {
        entry.bytes = bytes
        size.stringValue = bytes.map(Scanner.formatBytes) ?? "…"
        size.textColor = bytes == nil ? Term.faint : Term.ink
    }

    override func resetCursorRects() {
        if entry.isFolder { super.resetCursorRects() }
    }

    override func refresh() {
        super.refresh()
        reveal.isHidden = !hovered
        trash.isHidden = !hovered
    }

    override func hitTest(_ point: NSPoint) -> NSView? {
        let local = convert(point, from: superview)
        guard bounds.contains(local) else { return nil }
        for button in [reveal, trash] where !button.isHidden && button.frame.contains(local) { return button }
        return self
    }

    override func layout() {
        super.layout()
        let right = bounds.width - Metrics.inset - 22
        size.frame = NSRect(x: right - 64, y: (bounds.height - 16) / 2, width: 64, height: 16)
        trash.frame = NSRect(x: size.frame.minX - 28, y: (bounds.height - 22) / 2, width: 24, height: 22)
        reveal.frame = NSRect(x: trash.frame.minX - 26, y: (bounds.height - 22) / 2, width: 24, height: 22)
        let left = Metrics.inset + 46
        name.frame = NSRect(x: left, y: bounds.height / 2 - 1, width: max(30, reveal.frame.minX - left - 6), height: 16)
    }

    override func draw(_ dirtyRect: NSRect) {
        if hovered || pressed {
            let path = NSBezierPath(roundedRect: bounds.insetBy(dx: Metrics.inset, dy: 1), xRadius: 10, yRadius: 10)
            Term.fill.setFill()
            path.fill()
        }
        icon.draw(in: NSRect(x: Metrics.inset + 12, y: bounds.midY - 13, width: 26, height: 26), from: .zero, operation: .sourceOver, fraction: 1)
        // Share of the largest item in this folder
        let left = Metrics.inset + 46
        let bar = NSRect(x: left, y: bounds.midY - 9, width: max(10, size.frame.minX - 60 - left), height: 4)
        Term.fill.setFill()
        NSBezierPath(roundedRect: bar, xRadius: 2, yRadius: 2).fill()
        if fraction > 0 {
            var filled = bar
            filled.size.width = max(bar.height, bar.width * CGFloat(min(1, fraction)))
            Term.accent.setFill()
            NSBezierPath(roundedRect: filled, xRadius: 2, yRadius: 2).fill()
        }
        if entry.isFolder {
            drawSymbol("chevron.right", in: NSRect(x: bounds.width - Metrics.inset - 20, y: 0, width: 12, height: bounds.height),
                       pointSize: 10, weight: .semibold, color: Term.dim)
        }
    }
}

final class ExplorerHeader: NSView {
    var onBack: () -> Void = {}
    private lazy var back = IconButton(symbol: "chevron.left", help: L("Back", "Terug")) { [weak self] in self?.onBack() }
    private let spinner = NSProgressIndicator()
    private var title = ""
    private var subtitle = ""

    override init(frame frameRect: NSRect) {
        super.init(frame: frameRect)
        spinner.style = .spinning
        spinner.controlSize = .small
        spinner.isDisplayedWhenStopped = false
        addSubview(back)
        addSubview(spinner)
    }

    required init?(coder: NSCoder) { fatalError() }

    func set(title: String, subtitle: String, canGoBack: Bool, busy: Bool) {
        self.title = title
        self.subtitle = subtitle
        back.isHidden = !canGoBack
        if busy { spinner.startAnimation(nil) } else { spinner.stopAnimation(nil) }
        needsDisplay = true
    }

    private var textX: CGFloat { back.isHidden ? Metrics.inset + 52 : Metrics.inset + 80 }

    override func layout() {
        super.layout()
        let card = bounds.insetBy(dx: Metrics.inset, dy: 4)
        back.frame = NSRect(x: card.minX + 10, y: card.midY - 13, width: 26, height: 26)
        spinner.frame = NSRect(x: card.maxX - 30, y: card.midY - 8, width: 16, height: 16)
    }

    override func draw(_ dirtyRect: NSRect) {
        let card = bounds.insetBy(dx: Metrics.inset, dy: 4)
        Draw.card(card, radius: 16)
        let tileX = back.isHidden ? card.minX + 12 : card.minX + 40
        Draw.tile("chart.pie.fill", in: NSRect(x: tileX, y: card.midY - 15, width: 30, height: 30), color: Term.accent)
        let x = tileX + 40
        let attrs: [NSAttributedString.Key: Any] = [.font: termFont(13, .semibold), .foregroundColor: Term.ink]
        (title as NSString).draw(with: NSRect(x: x, y: card.midY + 1, width: card.maxX - 40 - x, height: 17),
                                 options: [.usesLineFragmentOrigin, .truncatesLastVisibleLine], attributes: attrs)
        let subAttrs: [NSAttributedString.Key: Any] = [.font: digitFont(11, .regular), .foregroundColor: Term.dim]
        (subtitle as NSString).draw(with: NSRect(x: x, y: card.midY - 15, width: card.maxX - 40 - x, height: 15),
                                    options: [.usesLineFragmentOrigin, .truncatesLastVisibleLine], attributes: subAttrs)
    }
}

// Measures a folder's contents, biggest first; click a folder to go in. Starts in your home folder.
final class ExplorerView: NSView {
    override var isFlipped: Bool { true }
    var onReveal: (String) -> Void = { _ in }
    var onTrash: ([CleanItem], @escaping (Set<String>) -> Void) -> Void = { _, _ in }
    var onResize: () -> Void = {}
    private let home = NSHomeDirectory()
    private var path = NSHomeDirectory()
    private var rows: [ExplorerRow] = []
    private let header = ExplorerHeader()
    private let placeholder = makeLabel(L("Empty folder", "Lege map"), size: 12, weight: .medium, color: Term.dim)
    private var sizes: [String: UInt64] = [:]  // kept while iServer runs, so going back is instant
    private let queue: OperationQueue = {
        let queue = OperationQueue()
        queue.maxConcurrentOperationCount = 3
        queue.qualityOfService = .utility
        return queue
    }()
    private var generation = 0
    private var started = false
    private var pending = 0
    private var resortScheduled = false

    override init(frame frameRect: NSRect) {
        super.init(frame: frameRect)
        placeholder.alignment = .center
        header.onBack = { [weak self] in
            guard let self else { return }
            self.open((self.path as NSString).deletingLastPathComponent)
        }
        addSubview(header)
        addSubview(placeholder)
    }

    required init?(coder: NSCoder) { fatalError() }

    var contentHeight: CGFloat {
        Metrics.cleanHeader + CGFloat(max(rows.count, 1)) * Metrics.explorerRow + Metrics.listPad * 2
    }

    func start() {
        guard !started else { return }
        started = true
        open(home)
    }

    private func open(_ target: String) {
        generation += 1
        let current = generation
        queue.cancelAllOperations()
        path = target
        rows.forEach { $0.removeFromSuperview() }
        let keys: Set<URLResourceKey> = [.isDirectoryKey, .isSymbolicLinkKey, .isPackageKey]
        let entries = DevClean.children(of: target).compactMap { child -> ExplorerRow.Entry? in
            guard let values = try? URL(fileURLWithPath: child).resourceValues(forKeys: keys), values.isSymbolicLink != true else { return nil }
            let folder = values.isDirectory == true && values.isPackage != true
            return ExplorerRow.Entry(name: (child as NSString).lastPathComponent, path: child, isFolder: folder, bytes: sizes[child])
        }
        rows = entries.map { entry in
            let row = ExplorerRow(entry: entry, reveal: { [weak self] in self?.onReveal($0) }, trash: { [weak self] in self?.trash($0) })
            if entry.isFolder { row.onClick = { [weak self] in self?.open(entry.path) } }
            return row
        }
        rows.forEach(addSubview)
        resort()
        onResize()

        let missing = entries.filter { $0.bytes == nil }
        pending = missing.count
        updateHeader()
        for entry in missing {
            let operation = BlockOperation()
            operation.addExecutionBlock { [weak self, weak operation] in
                let bytes = DevClean.allocatedSize(entry.path, cancelled: { operation?.isCancelled ?? true })
                guard operation?.isCancelled == false else { return }
                DispatchQueue.main.async {
                    guard let self, self.generation == current else { return }
                    self.sizes[entry.path] = bytes
                    self.rows.first { $0.entry.path == entry.path }?.update(bytes)
                    self.pending -= 1
                    self.scheduleResort()
                }
            }
            queue.addOperation(operation)
        }
    }

    // Results arrive one by one; reorder at most a few times a second.
    private func scheduleResort() {
        updateHeader()
        guard !resortScheduled else { return }
        resortScheduled = true
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.3) { [weak self] in
            self?.resortScheduled = false
            self?.resort()
        }
    }

    private func resort() {
        rows.sort { lhs, rhs in
            switch (lhs.entry.bytes, rhs.entry.bytes) {
            case let (l?, r?): return l > r
            case (_?, nil): return true
            case (nil, _?): return false
            default: return lhs.entry.name.localizedCaseInsensitiveCompare(rhs.entry.name) == .orderedAscending
            }
        }
        let largest = Double(rows.compactMap(\.entry.bytes).max() ?? 0)
        for row in rows { row.fraction = largest > 0 ? Double(row.entry.bytes ?? 0) / largest : 0 }
        placeholder.isHidden = !rows.isEmpty
        needsLayout = true
    }

    private func updateHeader() {
        let total = rows.compactMap(\.entry.bytes).reduce(0, +)
        let name = path == home ? L("Home folder", "Thuismap") : (path as NSString).lastPathComponent
        var subtitle = DevClean.tilde(path) + "  ·  " + Scanner.formatBytes(total)
        if pending > 0 { subtitle += "  ·  " + L("measuring \(pending)…", "\(pending) meten…") }
        header.set(title: name, subtitle: subtitle, canGoBack: path != home && path.hasPrefix(home), busy: pending > 0)
    }

    private func trash(_ entry: ExplorerRow.Entry) {
        let item = CleanItem(id: "explore." + entry.path, title: entry.name, detail: DevClean.tilde(entry.path), paths: [entry.path],
                             bytes: entry.bytes ?? 0, preselect: false, action: .trash)
        onTrash([item]) { [weak self] cleaned in
            guard let self, !cleaned.isEmpty else { return }
            self.rows.first { $0.entry.path == entry.path }?.removeFromSuperview()
            self.rows.removeAll { $0.entry.path == entry.path }
            // Folders above it shrank; measure them again when visited.
            self.sizes = self.sizes.filter { !entry.path.hasPrefix($0.key + "/") && $0.key != entry.path }
            self.resort()
            self.updateHeader()
            self.onResize()
        }
    }

    override func layout() {
        super.layout()
        var y = Metrics.listPad
        header.frame = NSRect(x: 0, y: y, width: bounds.width, height: Metrics.cleanHeader)
        y += Metrics.cleanHeader
        placeholder.frame = NSRect(x: 16, y: y + (Metrics.explorerRow - 16) / 2, width: max(0, bounds.width - 32), height: 16)
        for row in rows {
            row.frame = NSRect(x: 0, y: y, width: bounds.width, height: Metrics.explorerRow)
            y += Metrics.explorerRow
        }
    }
}

// MARK: - Storage tab

// Switches between the storage tools.
final class ModeBar: NSView {
    var onSelect: (Int) -> Void = { _ in }
    private var chips: [SortChip] = []

    init(titles: [String]) {
        super.init(frame: .zero)
        for (index, title) in titles.enumerated() {
            let chip = SortChip(title)
            chip.on = index == 0
            chip.onClick = { [weak self] in self?.select(index) }
            chips.append(chip)
            addSubview(chip)
        }
    }

    required init?(coder: NSCoder) { fatalError() }

    func select(_ index: Int) {
        for (i, chip) in chips.enumerated() { chip.on = i == index }
        onSelect(index)
    }

    override func layout() {
        super.layout()
        let track = bounds.insetBy(dx: Metrics.inset + 2, dy: 6)
        let width = track.width / CGFloat(max(chips.count, 1))
        for (index, chip) in chips.enumerated() {
            chip.frame = NSRect(x: track.minX + CGFloat(index) * width, y: track.minY, width: width - 2, height: track.height)
        }
    }

    override func draw(_ dirtyRect: NSRect) {
        let track = bounds.insetBy(dx: Metrics.inset, dy: 4)
        let path = NSBezierPath(roundedRect: track, xRadius: track.height / 2, yRadius: track.height / 2)
        Term.fill.setFill()
        path.fill()
    }
}

final class StoragePane: NSView {
    override var isFlipped: Bool { true }
    var onClean: ([CleanItem], @escaping (Set<String>) -> Void) -> Void = { _, _ in }
    var onReveal: (String) -> Void = { _ in }
    var onResize: () -> Void = {}
    var runningFolders: () -> [String] = { [] }
    private var cards: [VolumeCard] = []
    private let modes = ModeBar(titles: [L("Cleanup", "Opschonen"), L("Explorer", "Verkenner"), L("Large", "Groot"),
                                         L("Apps", "Apps"), L("Duplicates", "Dubbel")])
    private let explorer = ExplorerView()
    private var lists: [CleanListView] = []
    private var mode = 0

    override init(frame frameRect: NSRect) {
        super.init(frame: frameRect)
        let cleanup = CleanListView(config: CleanListConfig(
            title: L("Developer cleanup", "Opschonen voor developers"), symbol: "sparkles",
            idle: L("Find caches and build folders you can remove", "Zoek caches en buildmappen die weg kunnen"),
            searchPlaceholder: L("Search projects", "Zoek projecten"), filterable: ["projects"], expanded: [],
            order: DevClean.order))
        cleanup.makeScan = { [weak self] in
            let running = self?.runningFolders() ?? []
            return { onGroup in DevClean.scan(running: running, onGroup: onGroup) }
        }
        let large = CleanListView(config: CleanListConfig(
            title: L("Large & old files", "Grote en oude bestanden"), symbol: "doc.fill",
            idle: L("Files over 100 MB, or untouched for a year, in your folders", "Bestanden boven 100 MB, of een jaar niet aangeraakt"),
            searchPlaceholder: L("Search files", "Zoek bestanden"), filterable: ["large"], expanded: ["large"], order: []))
        large.makeScan = { { _ in StorageTools.largeFiles() } }
        let apps = CleanListView(config: CleanListConfig(
            title: L("Apps and leftovers", "Apps en resten"), symbol: "app.badge.checkmark",
            idle: L("Remove apps with their files, and files of deleted apps", "Verwijder apps met hun bestanden, en resten van oude apps"),
            searchPlaceholder: L("Search leftovers", "Zoek resten"), filterable: ["orphans"], expanded: [], order: []))
        apps.makeScan = {
            let running = Set(NSWorkspace.shared.runningApplications.compactMap(\.bundleIdentifier))
            return { _ in StorageTools.apps(running: running) }
        }
        let duplicates = CleanListView(config: CleanListConfig(
            title: L("Duplicate files", "Dubbele bestanden"), symbol: "doc.on.doc.fill",
            idle: L("Identical files in your folders; one copy is always kept", "Identieke bestanden; er blijft altijd één over"),
            searchPlaceholder: "", filterable: [], expanded: [], order: []))
        duplicates.makeScan = { { onGroup in StorageTools.duplicates(onGroup: onGroup) } }
        lists = [cleanup, large, apps, duplicates]

        for list in lists {
            list.onClean = { [weak self] items, done in self?.onClean(items, done) }
            list.onReveal = { [weak self] in self?.onReveal($0) }
            list.onResize = { [weak self] in self?.contentChanged() }
        }
        explorer.onReveal = { [weak self] in self?.onReveal($0) }
        explorer.onTrash = { [weak self] items, done in self?.onClean(items, done) }
        explorer.onResize = { [weak self] in self?.contentChanged() }
        modes.onSelect = { [weak self] in self?.show($0) }
        addSubview(modes)
        show(0)
    }

    required init?(coder: NSCoder) { fatalError() }

    // Mode 0 cleanup, 1 explorer, 2 large files, 3 apps, 4 duplicates.
    private var current: NSView { mode == 1 ? explorer : lists[mode == 0 ? 0 : mode - 1] }

    private var currentHeight: CGFloat {
        if mode == 1 { return explorer.contentHeight }
        return lists[mode == 0 ? 0 : mode - 1].contentHeight
    }

    var contentHeight: CGFloat {
        Metrics.listPad + CGFloat(max(cards.count, 1)) * Metrics.volume + Metrics.modeBar + currentHeight + Metrics.listPad
    }

    private func show(_ index: Int) {
        mode = index
        if current.superview == nil { addSubview(current) }
        for view in [explorer] + lists as [NSView] where view !== current { view.removeFromSuperview() }
        if mode == 1 { explorer.start() }
        contentChanged()
    }

    private func contentChanged() {
        needsLayout = true
        onResize()
    }

    func showVolumes(_ volumes: [DiskVolume]) {
        if cards.count == volumes.count {
            zip(cards, volumes).forEach { $0.update($1) }
        } else {
            cards.forEach { $0.removeFromSuperview() }
            cards = volumes.map(VolumeCard.init)
            cards.forEach(addSubview)
            contentChanged()
        }
    }

    override func layout() {
        super.layout()
        var y = Metrics.listPad
        for card in cards {
            card.frame = NSRect(x: 0, y: y, width: bounds.width, height: Metrics.volume)
            y += Metrics.volume
        }
        if cards.isEmpty { y += Metrics.volume }
        modes.frame = NSRect(x: 0, y: y, width: bounds.width, height: Metrics.modeBar)
        y += Metrics.modeBar
        current.frame = NSRect(x: 0, y: y, width: bounds.width, height: currentHeight)
    }
}

// MARK: - Clipboard

final class ClipRow: HoverView {
    private let preview: NSTextField
    private let meta: NSTextField
    private let pin: IconButton
    private let pinned: Bool
    private let symbol: String
    private let color: NSColor

    init(clip: ClipItem, copy: @escaping () -> Void, toggle: @escaping () -> Void) {
        let oneLine = clip.text.replacingOccurrences(of: "\n", with: " ")
        preview = makeLabel(oneLine, size: 12, weight: .medium, color: Term.ink)
        let when = ClipRow.ago(clip.date)
        let what: String
        switch clip.kind {
        case "link":
            what = L("Link", "Link"); symbol = "link"; color = .systemBlue
        case "file":
            what = L("File", "Bestand"); symbol = "doc.fill"; color = .systemOrange
        default:
            what = L("Text", "Tekst"); symbol = "text.alignleft"; color = .systemGray
        }
        let who = clip.app.isEmpty ? what : "\(what)  ·  \(clip.app)"
        meta = makeLabel("\(who)  ·  \(when)", size: 10, weight: .regular, color: Term.dim)
        pinned = clip.pinned
        pin = IconButton(symbol: clip.pinned ? "pin.fill" : "pin", help: L("Pin", "Vastzetten"), action: toggle)
        super.init(frame: .zero)
        onClick = copy
        toolTip = clip.text
        pin.isHidden = !pinned
        addSubview(preview)
        addSubview(meta)
        addSubview(pin)
    }

    required init?(coder: NSCoder) { fatalError() }

    override func refresh() {
        super.refresh()
        pin.isHidden = !(pinned || hovered)
    }

    override func hitTest(_ point: NSPoint) -> NSView? {
        let local = convert(point, from: superview)
        guard bounds.contains(local) else { return nil }
        if !pin.isHidden, pin.frame.contains(local) { return pin }
        return self
    }

    override func layout() {
        super.layout()
        pin.frame = NSRect(x: bounds.width - Metrics.inset - 36, y: (bounds.height - 26) / 2, width: 28, height: 26)
        let left = Metrics.inset + 50
        preview.frame = NSRect(x: left, y: bounds.height / 2 + 1, width: max(40, pin.frame.minX - left - 6), height: 16)
        meta.frame = NSRect(x: left, y: bounds.height / 2 - 15, width: preview.frame.width, height: 13)
    }

    override func draw(_ dirtyRect: NSRect) {
        if hovered || pressed {
            Draw.card(bounds.insetBy(dx: Metrics.inset, dy: 2), hot: true, radius: 12)
        }
        Draw.tile(symbol, in: NSRect(x: Metrics.inset + 10, y: bounds.midY - 15, width: 30, height: 30), color: color)
    }

    private static func ago(_ date: Date) -> String {
        let minutes = Int(Date().timeIntervalSince(date) / 60)
        if minutes < 1 { return L("just now", "zojuist") }
        if minutes < 60 { return "\(minutes)m" }
        let hours = minutes / 60
        if hours < 48 { return "\(hours)\(L("h", "u"))" }
        return "\(hours / 24)d"
    }
}

final class ClipPane: NSView, NSTextFieldDelegate {
    override var isFlipped: Bool { true }
    var onCopy: (ClipItem) -> Void = { _ in }
    var onPin: (ClipItem) -> Void = { _ in }
    var onFilter: () -> Void = {}
    private let field = NSTextField()
    private let empty = makeLabel(L("Clipboard is empty", "Klembord is leeg"), size: 13, weight: .semibold, color: Term.dim)
    private var all: [ClipItem] = []
    private var rows: [ClipRow] = []
    private(set) var shown = 0

    override init(frame frameRect: NSRect) {
        super.init(frame: frameRect)
        field.isBezeled = false
        field.drawsBackground = false
        field.focusRingType = .none
        field.font = termFont(12, .medium)
        field.textColor = Term.ink
        field.placeholderString = L("Search clipboard", "Zoek in klembord")
        field.delegate = self
        empty.alignment = .center
        empty.isHidden = true
        addSubview(field)
        addSubview(empty)
    }

    required init?(coder: NSCoder) { fatalError() }

    func show(_ clips: [ClipItem]) {
        all = clips
        rebuild()
    }

    @objc func controlTextDidChange(_ obj: Notification) {
        rebuild()
        onFilter()
    }

    func takeQuery(_ extra: String) -> Bool {
        window?.makeFirstResponder(field)
        field.stringValue += extra
        rebuild()
        onFilter()
        return true
    }

    func clearQuery() -> Bool {
        guard !field.stringValue.isEmpty else { return false }
        field.stringValue = ""
        rebuild()
        onFilter()
        return true
    }

    var isEditing: Bool { window?.firstResponder === field.currentEditor() }

    private func rebuild() {
        rows.forEach { $0.removeFromSuperview() }
        let query = field.stringValue.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        let shownItems = query.isEmpty ? all : all.filter {
            $0.text.lowercased().contains(query) || $0.app.lowercased().contains(query) || $0.kind.contains(query)
        }
        rows = shownItems.map { clip in
            ClipRow(clip: clip, copy: { [weak self] in self?.onCopy(clip) }, toggle: { [weak self] in self?.onPin(clip) })
        }
        rows.forEach(addSubview)
        shown = shownItems.count
        empty.isHidden = shown != 0
        needsLayout = true
    }

    private var searchRect: NSRect { NSRect(x: Metrics.inset, y: 6, width: bounds.width - Metrics.inset * 2, height: 30) }

    override func layout() {
        super.layout()
        let search = searchRect
        field.frame = NSRect(x: search.minX + 32, y: search.minY + 7, width: search.width - 44, height: 17)
        empty.frame = NSRect(x: 16, y: 64, width: max(0, bounds.width - 32), height: 16)
        var y: CGFloat = 46
        for row in rows {
            row.frame = NSRect(x: 0, y: y, width: bounds.width, height: Metrics.clip)
            y += Metrics.clip
        }
    }

    override func draw(_ dirtyRect: NSRect) {
        let search = searchRect
        let path = NSBezierPath(roundedRect: search, xRadius: search.height / 2, yRadius: search.height / 2)
        Term.fill.setFill()
        path.fill()
        drawSymbol("magnifyingglass", in: NSRect(x: search.minX + 10, y: search.minY, width: 16, height: search.height),
                   pointSize: 12, weight: .semibold, color: Term.dim)
    }
}

// MARK: - Board

final class BoardView: NSView {
    var openURL: (String) -> Void = { _ in }
    var copyText: (String) -> Void = { _ in }
    var reveal: (String) -> Void = { _ in }
    var terminal: (String) -> Void = { _ in }
    var stop: (Int32) -> Void = { _ in }
    var setApps: (Bool) -> Void = { _ in }
    var setLogin: (Bool) -> Void = { _ in }
    var setAwake: (Bool) -> Void = { _ in }
    var quit: () -> Void = {}
    var onPage: () -> Void = {}
    var relayout: () -> Void = {}
    var cleanItems: ([CleanItem], @escaping (Set<String>) -> Void) -> Void = { _, _ in }
    var runningFolders: () -> [String] = { [] }
    var quitProcess: (AppUsage) -> Void = { _ in }
    var copyClip: (ClipItem) -> Void = { _ in }
    var pinClip: (ClipItem) -> Void = { _ in }
    private(set) var page = 0
    private var trace = Trace()

    private let hero = HeroView()
    private let tabs = TabBar()
    private let well = NSView()
    private let scroll = NSScrollView()
    private let column = ListColumn()
    private let empty = EmptyState()
    private let activityScroll = NSScrollView()
    private let activity = ActivityPane()
    private let storageScroll = NSScrollView()
    private let storage = StoragePane()
    private let clipScroll = NSScrollView()
    private let clips = ClipPane()
    private let footer = NSView()
    private let hairline = NSView()
    private let appsToggle = TogglePill(L("Apps", "Apps"), symbol: "square.grid.2x2.fill",
                                        help: L("Also show regular apps that listen on a port", "Toon ook gewone apps die op een poort luisteren"))
    private let awakeToggle = TogglePill(L("Awake", "Wakker"), symbol: "cup.and.saucer.fill",
                                         help: L("Keep your Mac and display awake", "Houd je Mac en scherm wakker"))
    private let loginToggle = TogglePill(L("Login", "Login"), symbol: "power",
                                         help: L("Launch iServer at login", "Open iServer bij inloggen"))
    private var quitButton: IconButton!
    private var rows: [ServerCard] = []
    private var expanded: Int32?  // server whose details are open
    private lazy var detail = ServerDetail { [weak self] in self?.copyText($0) }
    private var serverGroups: [ServerGroup] = []
    private var cpuHistory: [Int32: [Double]] = [:]
    var memHistory: [Int32: [Double]] = [:]
    private var pendingScroll: NSPoint?

    override init(frame frameRect: NSRect) {
        super.init(frame: frameRect)
        appsToggle.onChange = { [weak self] on in self?.setApps(on) }
        loginToggle.onChange = { [weak self] on in self?.setLogin(on) }
        awakeToggle.onChange = { [weak self] on in self?.setAwake(on) }
        quitButton = IconButton(symbol: "xmark.circle", help: L("Quit iServer", "Stop iServer")) { [weak self] in self?.quit() }

        tabs.onSelect = { [weak self] index in
            guard let self else { return }
            self.page = index
            self.applyPage()
            self.fadeInPage()
            self.onPage()
        }
        hairline.wantsLayer = true
        hairline.layer?.backgroundColor = Term.line.cgColor
        footer.addSubview(hairline)
        footer.addSubview(appsToggle)
        footer.addSubview(loginToggle)
        footer.addSubview(awakeToggle)
        footer.addSubview(quitButton)

        configure(scroll)
        scroll.documentView = column
        configure(activityScroll)
        activityScroll.documentView = activity
        configure(storageScroll)
        storageScroll.documentView = storage
        configure(clipScroll)
        clipScroll.documentView = clips
        storage.onClean = { [weak self] items, done in self?.cleanItems(items, done) }
        storage.runningFolders = { [weak self] in self?.runningFolders() ?? [] }
        activity.onQuit = { [weak self] in self?.quitProcess($0) }
        activity.onResize = { [weak self] in
            self?.needsLayout = true
            self?.relayout()
        }
        storage.onReveal = { [weak self] in self?.reveal($0) }
        storage.onResize = { [weak self] in
            self?.needsLayout = true
            self?.relayout()
        }
        clips.onCopy = { [weak self] in self?.copyClip($0) }
        clips.onPin = { [weak self] in self?.pinClip($0) }
        clips.onFilter = { [weak self] in self?.relayout() }
        for view in [scroll, empty, activityScroll, storageScroll, clipScroll] as [NSView] { well.addSubview(view) }

        addSubview(hero)
        addSubview(tabs)
        addSubview(well)
        addSubview(footer)

        for view in [hero, tabs, well, scroll, empty, activityScroll, storageScroll, clipScroll, footer] as [NSView] {
            view.translatesAutoresizingMaskIntoConstraints = false
        }
        var constraints: [NSLayoutConstraint] = [
            hero.topAnchor.constraint(equalTo: topAnchor, constant: 4),
            hero.leadingAnchor.constraint(equalTo: leadingAnchor),
            hero.trailingAnchor.constraint(equalTo: trailingAnchor),
            hero.heightAnchor.constraint(equalToConstant: Metrics.hero - 4),

            tabs.topAnchor.constraint(equalTo: hero.bottomAnchor),
            tabs.leadingAnchor.constraint(equalTo: leadingAnchor),
            tabs.trailingAnchor.constraint(equalTo: trailingAnchor),
            tabs.heightAnchor.constraint(equalToConstant: Metrics.tabs),

            footer.leadingAnchor.constraint(equalTo: leadingAnchor),
            footer.trailingAnchor.constraint(equalTo: trailingAnchor),
            footer.bottomAnchor.constraint(equalTo: bottomAnchor),
            footer.heightAnchor.constraint(equalToConstant: Metrics.footer),

            well.topAnchor.constraint(equalTo: tabs.bottomAnchor),
            well.leadingAnchor.constraint(equalTo: leadingAnchor),
            well.trailingAnchor.constraint(equalTo: trailingAnchor),
            well.bottomAnchor.constraint(equalTo: footer.topAnchor),
        ]
        for view in [scroll, empty, activityScroll, storageScroll, clipScroll] as [NSView] {
            constraints += [
                view.topAnchor.constraint(equalTo: well.topAnchor),
                view.leadingAnchor.constraint(equalTo: well.leadingAnchor),
                view.trailingAnchor.constraint(equalTo: well.trailingAnchor),
                view.bottomAnchor.constraint(equalTo: well.bottomAnchor),
            ]
        }
        NSLayoutConstraint.activate(constraints)

        let names = ["server": 0, "servers": 0, "activity": 1, "activiteit": 1, "storage": 2, "opslag": 2, "clipboard": 3, "klembord": 3]
        if let index = CommandLine.arguments.firstIndex(of: "--tab"),
           index + 1 < CommandLine.arguments.count,
           let found = names[CommandLine.arguments[index + 1]] {
            page = found
            tabs.selected = found
        }
        applyPage()
    }

    private func configure(_ scroll: NSScrollView) {
        scroll.drawsBackground = false
        scroll.borderType = .noBorder
        scroll.hasVerticalScroller = true
        scroll.autohidesScrollers = true
        scroll.scrollerStyle = .overlay
        scroll.automaticallyAdjustsContentInsets = false
    }

    required init?(coder: NSCoder) { fatalError() }

    func setToggles(apps: Bool, login: Bool) {
        appsToggle.checked = apps
        loginToggle.checked = login
        awakeToggle.checked = Awake.isOn
    }

    func setHero(groups: [ServerGroup], vitals: Vitals, disk: DiskVolume?) {
        hero.set(groups: groups, vitals: vitals, disk: disk)
    }

    func update(groups: [ServerGroup], history: [Int32: [Double]], vitals: Vitals, volumes: [DiskVolume],
                includeApps: Bool, login: Bool, lan: String?) {
        pendingScroll = scroll.contentView.bounds.origin
        let known = Set(rows.map(\.groupID))
        rows.forEach { $0.removeFromSuperview() }
        rows = groups.map { group in
            ServerCard(group: group, history: history[group.id] ?? [], lan: lan, openURL: openURL, copyText: copyText,
                       reveal: reveal, terminal: terminal, toggle: { [weak self] in self?.toggleDetails(group.id) }) { [weak self] in
                self?.stop(group.id)
            }
        }
        rows.forEach(column.addSubview)
        serverGroups = groups
        cpuHistory = history
        if let id = expanded, !groups.contains(where: { $0.id == id }) { expanded = nil }
        showDetails()
        // Servers that just appeared fade in; the rest stay put.
        if !known.isEmpty {
            for row in rows where !known.contains(row.groupID) {
                row.alphaValue = 0
                NSAnimationContext.runAnimationGroup { context in
                    context.duration = 0.35
                    row.animator().alphaValue = 1
                }
            }
        }
        setHero(groups: groups, vitals: vitals, disk: volumes.first)
        if page == 1 { activity.setCharts(vitals, trace) }
        storage.showVolumes(volumes)
        setToggles(apps: includeApps, login: login)
        applyPage()
        needsLayout = true
    }

    func refreshStats(groups: [ServerGroup], history: [Int32: [Double]], vitals: Vitals, volumes: [DiskVolume]) {
        setHero(groups: groups, vitals: vitals, disk: volumes.first)
        switch page {
        case 1:
            activity.setCharts(vitals, trace)
        case 2:
            storage.showVolumes(volumes)
        default:
            for group in groups {
                rows.first { $0.groupID == group.id }?.applyStats(group, history: history[group.id] ?? [])
            }
            serverGroups = groups
            cpuHistory = history
            showDetails()
        }
        needsLayout = true
    }

    func bodyHeight(maxHeight: CGFloat) -> CGFloat {
        switch page {
        case 1: return Metrics.capped(activity.contentHeight, maxHeight: maxHeight)
        case 2: return Metrics.capped(storage.contentHeight, maxHeight: maxHeight)
        case 3: return Metrics.capped(Metrics.clipHeight(count: clips.shown), maxHeight: maxHeight)
        default:
            guard !rows.isEmpty else { return Metrics.listHeight(count: 0, maxHeight: maxHeight) }
            return Metrics.capped(serverListHeight, maxHeight: maxHeight)
        }
    }

    private var serverListHeight: CGFloat {
        Metrics.listPad * 2 + CGFloat(rows.count) * Metrics.row + (expanded == nil ? 0 : detail.contentHeight)
    }

    // One server's details at a time; clicking the open one closes it.
    private func toggleDetails(_ id: Int32) {
        expanded = expanded == id ? nil : id
        showDetails()
        if expanded != nil {
            detail.alphaValue = 0
            NSAnimationContext.runAnimationGroup { context in
                context.duration = 0.2
                detail.animator().alphaValue = 1
            }
        }
        needsLayout = true
        relayout()
    }

    private func showDetails() {
        for row in rows { row.expanded = row.groupID == expanded }
        guard let id = expanded, let group = serverGroups.first(where: { $0.id == id }) else {
            detail.removeFromSuperview()
            return
        }
        if detail.superview == nil { column.addSubview(detail) }
        detail.show(group, cpu: cpuHistory[id] ?? [], mem: memHistory[id] ?? [])
    }

    func noteCharts(_ vitals: Vitals, _ trace: Trace) {
        self.trace = trace
        guard page == 1 else { return }
        activity.setCharts(vitals, trace)
    }

    func showClips(_ items: [ClipItem]) {
        clips.show(items)
        needsLayout = true
    }

    func showActivity(processes: [AppUsage], power: PowerInfo) {
        activity.showProcesses(processes)
        activity.showPower(power)
    }

    func clearClipFilter() -> Bool { clips.clearQuery() }
    func clipIsEditing() -> Bool { clips.isEditing }
    func typeClip(_ text: String) { _ = clips.takeQuery(text) }

    private var pageView: NSView {
        switch page {
        case 1: return activityScroll
        case 2: return storageScroll
        case 3: return clipScroll
        default: return rows.isEmpty ? empty : scroll
        }
    }

    private func fadeInPage() {
        let view = pageView
        view.alphaValue = 0
        NSAnimationContext.runAnimationGroup { context in
            context.duration = 0.22
            context.timingFunction = CAMediaTimingFunction(name: .easeOut)
            view.animator().alphaValue = 1
        }
    }

    // Cards cascade in when the panel opens.
    func animateIn() {
        fadeInPage()
        guard page == 0 else { return }
        for (index, row) in rows.enumerated() {
            row.alphaValue = 0
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.03 * Double(index)) {
                NSAnimationContext.runAnimationGroup { context in
                    context.duration = 0.25
                    context.timingFunction = CAMediaTimingFunction(name: .easeOut)
                    row.animator().alphaValue = 1
                }
            }
        }
    }

    private func applyPage() {
        let servers = page == 0
        let hasRows = !rows.isEmpty
        scroll.isHidden = !servers || !hasRows
        empty.isHidden = !servers || hasRows
        activityScroll.isHidden = page != 1
        storageScroll.isHidden = page != 2
        clipScroll.isHidden = page != 3
    }

    override func layout() {
        super.layout()
        let width = max(scroll.contentView.bounds.width, well.bounds.width)
        guard width > 1 else { return }
        var y = Metrics.listPad
        for row in rows {
            row.frame = NSRect(x: 0, y: y, width: width, height: Metrics.row)
            y += Metrics.row
            if row.groupID == expanded {
                detail.frame = NSRect(x: 0, y: y - 2, width: width, height: detail.contentHeight)
                y += detail.contentHeight
            }
        }
        if !rows.isEmpty { y += Metrics.listPad }
        let next = NSRect(x: 0, y: 0, width: width, height: max(y, 1))
        if column.frame.integral != next.integral { column.frame = next }
        if let point = pendingScroll {
            pendingScroll = nil
            scroll.contentView.scroll(to: point)
        }

        let activityFrame = NSRect(x: 0, y: 0, width: width, height: activity.contentHeight)
        if activity.frame.integral != activityFrame.integral { activity.frame = activityFrame }
        let storageFrame = NSRect(x: 0, y: 0, width: width, height: storage.contentHeight)
        if storage.frame.integral != storageFrame.integral { storage.frame = storageFrame }
        let clipFrame = NSRect(x: 0, y: 0, width: width, height: Metrics.clipHeight(count: clips.shown))
        if clips.frame.integral != clipFrame.integral { clips.frame = clipFrame }

        let w = footer.bounds.width
        let h = footer.bounds.height
        hairline.frame = NSRect(x: Metrics.inset + 6, y: h - 1, width: w - Metrics.inset * 2 - 12, height: 1)
        let pill: CGFloat = 26
        appsToggle.frame = NSRect(x: Metrics.inset, y: (h - pill) / 2, width: appsToggle.preferredWidth, height: pill)
        loginToggle.frame = NSRect(x: appsToggle.frame.maxX + 6, y: (h - pill) / 2, width: loginToggle.preferredWidth, height: pill)
        awakeToggle.frame = NSRect(x: loginToggle.frame.maxX + 6, y: (h - pill) / 2, width: awakeToggle.preferredWidth, height: pill)
        quitButton.frame = NSRect(x: w - Metrics.inset - 30, y: (h - pill) / 2, width: 30, height: pill)
    }
}

// MARK: - App

final class AppDelegate: NSObject, NSApplicationDelegate, NSWindowDelegate {
    private let statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
    private let panel = MenuPanel()
    private let board = BoardView()
    private let demo = CommandLine.arguments.contains("--demo")
    private let keepOpen = CommandLine.arguments.contains("--keep-open")  // for screenshots: ignore clicks elsewhere
    private var groups: [ServerGroup] = []
    private var vitals = Vitals.empty
    private var volumes: [DiskVolume] = []
    private let clips = ClipBook()
    private var lastSignature = ""
    private var scanning = false
    private var trace = Trace()
    private var cpuHistory: [Int32: [Double]] = [:]  // per server group, newest last
    private var menuCPU: [Double] = []  // system CPU 0...1 for the menu bar graph, newest last
    private var chartTimer: Timer?
    private var charting = false
    private var activityTicks = 0
    private var timer: Timer?
    private var monitors: [Any] = []
    private var openedAt: TimeInterval = 0
    private var suppressOpenUntil: TimeInterval = 0

    private var includeApps: Bool {
        get { UserDefaults.standard.bool(forKey: "includeApps") }
        set { UserDefaults.standard.set(newValue, forKey: "includeApps") }
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        let chrome = ChromeView()
        panel.contentView = chrome
        panel.delegate = self
        chrome.host(board)
        board.openURL = { [weak self] in self?.openURL($0) }
        board.copyText = { [weak self] in self?.copyText($0) }
        board.reveal = { [weak self] in self?.revealFolder($0) }
        board.terminal = { [weak self] in self?.openTerminal($0) }
        board.stop = { [weak self] in self?.stopGroup($0) }
        board.setApps = { [weak self] in self?.setIncludeApps($0) }
        board.setLogin = { [weak self] in self?.setLogin($0) }
        board.setAwake = { [weak self] on in
            guard let self else { return }
            Awake.set(on)
            self.board.setToggles(apps: self.includeApps, login: SMAppService.mainApp.status == .enabled)
        }
        board.quit = { NSApp.terminate(nil) }
        board.relayout = { [weak self] in self?.placePanel(animated: true) }
        board.onPage = { [weak self] in
            guard let self else { return }
            self.placePanel(animated: true)
            self.board.refreshStats(groups: self.groups, history: self.cpuHistory, vitals: self.vitals, volumes: self.volumes)
            self.setChartsRunning(self.board.page == 1)
            if self.board.page == 1 { self.refresh() }
            if self.board.page == 2 { self.refresh() }
        }
        board.cleanItems = { [weak self] items, done in self?.clean(items, done: done) }
        board.runningFolders = { [weak self] in self?.groups.compactMap(\.folder) ?? [] }
        board.quitProcess = { [weak self] in self?.quitProcess($0) }
        board.copyClip = { [weak self] item in
            self?.clips.copy(item)
            self?.closePanel()
        }
        board.pinClip = { [weak self] in self?.clips.togglePin($0.id) }
        clips.onChange = { [weak self] in
            guard let self else { return }
            self.board.showClips(self.clips.items)
            if self.panel.isVisible, self.board.page == 3 { self.placePanel(animated: true) }
        }
        board.showClips(clips.items)

        if let button = statusItem.button {
            button.imagePosition = .imageLeading
            button.target = self
            button.action = #selector(togglePanel)
            button.sendAction(on: [.leftMouseDown, .rightMouseDown])
        }
        if let local = NSEvent.addLocalMonitorForEvents(matching: .keyDown, handler: { [weak self] event in
            guard let self, self.panel.isVisible else { return event }
            if event.keyCode == 53 {
                if self.board.clearClipFilter() { return nil }
                self.closePanel()
                return nil
            }
            guard self.board.page == 3, !self.board.clipIsEditing(),
                  event.modifierFlags.intersection([.command, .control, .option]).isEmpty,
                  let chars = event.characters, chars.count == 1,
                  let scalar = chars.unicodeScalars.first, scalar.value >= 32, scalar.value < 0xF700
            else { return event }
            self.board.typeClip(chars)
            return nil
        }) { monitors.append(local) }
        if let global = NSEvent.addGlobalMonitorForEvents(matching: [.leftMouseDown, .rightMouseDown], handler: { [weak self] _ in
            guard self?.keepOpen == false else { return }
            self?.closePanel()
        }) { monitors.append(global) }

        updateButton()
        refresh()
        scheduleRefresh()
        let clipTimer = Timer.scheduledTimer(withTimeInterval: 2, repeats: true) { [weak self] _ in self?.clips.poll() }
        clipTimer.tolerance = 1
        let cpuTimer = Timer.scheduledTimer(withTimeInterval: 3, repeats: true) { [weak self] _ in self?.sampleMenuCPU() }
        cpuTimer.tolerance = 0.5
        sampleMenuCPU()
        if CommandLine.arguments.contains("--open-menu") {
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.4) { [weak self] in
                self?.openPanel()
            }
        }
    }

    func windowDidResignKey(_ notification: Notification) {
        guard !keepOpen, ProcessInfo.processInfo.systemUptime - openedAt > 0.25 else { return }
        closePanel()
    }

    @objc private func togglePanel() {
        if panel.isVisible {
            closePanel()
            return
        }
        if ProcessInfo.processInfo.systemUptime < suppressOpenUntil { return }
        openPanel()
    }

    private func openPanel() {
        openedAt = ProcessInfo.processInfo.systemUptime
        render()
        placePanel(animated: false)
        board.animateIn()
        panel.orderFrontRegardless()
        panel.makeKey()
        statusItem.button?.highlight(true)
        scheduleRefresh()
        setChartsRunning(board.page == 1)
        refresh()
    }

    private func closePanel() {
        guard panel.isVisible else { return }
        suppressOpenUntil = ProcessInfo.processInfo.systemUptime + 0.25
        panel.orderOut(nil)
        statusItem.button?.highlight(false)
        setChartsRunning(false)
        scheduleRefresh()
    }

    private func setChartsRunning(_ on: Bool) {
        guard on else {
            chartTimer?.invalidate()
            chartTimer = nil
            return
        }
        activityTicks = 0
        guard chartTimer == nil else { return }
        tickChart()
        chartTimer = Timer.scheduledTimer(withTimeInterval: 1.2, repeats: true) { [weak self] _ in self?.tickChart() }
        chartTimer?.tolerance = 0.4
    }

    // Charts every tick; the process list and battery every third tick (about every 3.6 s).
    private func tickChart() {
        guard panel.isVisible, board.page == 1, !charting else { return }
        charting = true
        let withList = activityTicks % 3 == 0
        activityTicks += 1
        DispatchQueue.global(qos: .utility).async {
            let vitals = Vitals.sample()
            let processes = withList ? ProcessMonitor.sample() : nil
            let power = withList ? PowerInfo.sample() : nil
            DispatchQueue.main.async {
                if let processes, let power, self.panel.isVisible, self.board.page == 1 {
                    self.board.showActivity(processes: processes, power: power)
                }
                self.charting = false
                guard self.panel.isVisible, self.board.page == 1 else { return }
                self.vitals = vitals
                self.trace.push(Vitals.fraction(of: vitals))
                self.board.noteCharts(vitals, self.trace)
            }
        }
    }

    private func scheduleRefresh() {
        timer?.invalidate()
        let open = panel.isVisible
        timer = Timer.scheduledTimer(withTimeInterval: open ? 8 : 30, repeats: true) { [weak self] _ in
            self?.refresh()
        }
        timer?.tolerance = open ? 2 : 15
    }

    private func placePanel(animated: Bool) {
        guard let button = statusItem.button, let window = button.window else { return }
        let rect = window.convertToScreen(button.convert(button.bounds, to: nil))
        let screen = window.screen ?? NSScreen.main
        let visible = screen?.visibleFrame ?? NSRect(x: 0, y: 0, width: 1440, height: 900)
        let height = Metrics.chrome + board.bodyHeight(maxHeight: visible.height - 12)
        var x = round(rect.midX - Metrics.width / 2)
        x = min(max(x, visible.minX + 8), visible.maxX - Metrics.width - 8)
        let y = round(rect.minY - 4 - height)
        let frame = NSRect(x: x, y: max(y, visible.minY + 8), width: Metrics.width, height: height)
        guard frame.integral != panel.frame.integral else { return }
        if animated && panel.isVisible {
            NSAnimationContext.runAnimationGroup { context in
                context.duration = 0.2
                context.timingFunction = CAMediaTimingFunction(name: .easeInEaseOut)
                panel.animator().setFrame(frame, display: true)
            }
        } else {
            panel.setFrame(frame, display: true, animate: false)
        }
    }

    @objc private func refresh() {
        guard !scanning else { return }
        scanning = true
        let includeApps = self.includeApps
        let demo = self.demo
        let visible = panel.isVisible
        let qos: DispatchQoS.QoSClass = visible ? .utility : .background
        DispatchQueue.global(qos: qos).async {
            let result = demo ? Demo.groups() : Scanner.scan(includeApps: includeApps)
            // The hero strip shows CPU, RAM and disk on every tab, so sample them whenever the panel is open.
            let vitals = visible ? Vitals.sample() : nil
            let volumes = visible ? Disks.mounted() : nil
            DispatchQueue.main.async {
                self.scanning = false
                self.groups = result
                self.recordHistory(result)
                if let vitals {
                    self.vitals = vitals
                    self.trace.push(Vitals.fraction(of: vitals))
                    self.board.noteCharts(vitals, self.trace)
                }
                if let volumes { self.volumes = volumes }
                // Uptime and load are not part of the signature: refreshStats updates those in place.
                let signature = result.map(\.signature).joined(separator: ";")
                let changed = signature != self.lastSignature
                if changed {
                    self.lastSignature = signature
                    self.updateButton()
                }
                guard self.panel.isVisible else { return }
                if changed {
                    self.render()
                } else {
                    self.board.refreshStats(groups: result, history: self.cpuHistory, vitals: self.vitals, volumes: self.volumes)
                }
                // This scan started while the panel was closed, so it has no system stats yet.
                if vitals == nil {
                    self.refresh()
                }
            }
        }
    }

    private func sampleMenuCPU() {
        DispatchQueue.global(qos: .utility).async {
            let load = Vitals.cpuLoad() / 100
            DispatchQueue.main.async {
                self.menuCPU = Array((self.menuCPU + [load]).suffix(StatusIcon.bars))
                self.updateButton()
            }
        }
    }

    private func recordHistory(_ groups: [ServerGroup]) {
        var next: [Int32: [Double]] = [:]
        var memory: [Int32: [Double]] = [:]
        for group in groups {
            next[group.id] = Array(((cpuHistory[group.id] ?? []) + [group.cpu]).suffix(20))
            memory[group.id] = Array(((board.memHistory[group.id] ?? []) + [Double(group.rss)]).suffix(20))
        }
        cpuHistory = next
        board.memHistory = memory
    }

    private func updateButton() {
        guard let button = statusItem.button else { return }
        button.title = ""
        button.image = StatusIcon.image(cpu: menuCPU)
        button.toolTip = groups.isEmpty
            ? L("No dev servers running", "Geen dev servers actief")
            : groups.map { "\($0.title)  " + $0.listeners.map { ":\($0.port)" }.joined(separator: " ") }.joined(separator: "\n")
    }

    private func render() {
        let lan = demo ? "192.168.1.20" : Scanner.lanAddress()
        board.update(
            groups: groups,
            history: cpuHistory,
            vitals: vitals,
            volumes: volumes,
            includeApps: includeApps,
            login: SMAppService.mainApp.status == .enabled,
            lan: lan)
        if panel.isVisible { placePanel(animated: true) }
    }

    private func openURL(_ string: String) {
        guard let url = URL(string: string) else { return }
        closePanel()
        NSWorkspace.shared.open(url)
    }

    private func copyText(_ string: String) {
        clips.copyString(string)
    }

    // Confirms, moves the items to the Trash (or runs their command), reports, then tells the caller what is gone.
    private func clean(_ items: [CleanItem], done finished: @escaping (Set<String>) -> Void) {
        closePanel()
        let total = items.reduce(UInt64(0)) { $0 + $1.bytes }
        let permanent = items.filter(\.permanent)
        var lines = items.prefix(8).map { "• \($0.title)  \(Scanner.formatBytes($0.bytes))" }
        if items.count > 8 { lines.append(L("… and \(items.count - 8) more", "… en nog \(items.count - 8)")) }
        lines.append("")
        lines.append(L("Everything goes to the Trash, so you can still put it back. Empty the Trash to free the space.",
                       "Alles gaat naar de prullenmand, dus je kunt het nog terugzetten. Leeg de prullenmand om de ruimte vrij te maken."))
        if !permanent.isEmpty {
            lines.append(L("Except: \(permanent.map(\.title).joined(separator: ", ")). Those are removed permanently.",
                           "Behalve: \(permanent.map(\.title).joined(separator: ", ")). Die worden definitief verwijderd."))
        }
        let alert = NSAlert()
        alert.messageText = L("Clean up \(Scanner.formatBytes(total))?", "\(Scanner.formatBytes(total)) opschonen?")
        alert.informativeText = lines.joined(separator: "\n")
        alert.addButton(withTitle: L("Clean", "Opschonen"))
        alert.addButton(withTitle: L("Cancel", "Annuleer"))
        NSApp.activate(ignoringOtherApps: true)
        guard alert.runModal() == .alertFirstButtonReturn else { return }

        DispatchQueue.global(qos: .utility).async {
            let outcome = DevClean.clean(items)
            DispatchQueue.main.async {
                let done = NSAlert()
                var text: [String] = []
                if outcome.trashed > 0 {
                    text.append(L("Moved \(Scanner.formatBytes(outcome.trashed)) to the Trash. Empty the Trash to free the space.",
                                  "\(Scanner.formatBytes(outcome.trashed)) naar de prullenmand verplaatst. Leeg de prullenmand om de ruimte vrij te maken."))
                }
                if outcome.deleted > 0 {
                    text.append(L("Removed \(Scanner.formatBytes(outcome.deleted)) permanently.",
                                  "\(Scanner.formatBytes(outcome.deleted)) definitief verwijderd."))
                }
                if !outcome.failed.isEmpty {
                    text.append(L("Could not clean: \(outcome.failed.joined(separator: ", ")). Something may still be using it, or macOS needs Full Disk Access.",
                                  "Niet gelukt: \(outcome.failed.joined(separator: ", ")). Misschien is het nog in gebruik, of heeft macOS volledige schijftoegang nodig."))
                }
                done.messageText = outcome.failed.isEmpty ? L("Cleaned up", "Opgeschoond") : L("Partly cleaned up", "Deels opgeschoond")
                done.informativeText = text.joined(separator: "\n\n")
                done.addButton(withTitle: L("Done", "Klaar"))
                if outcome.trashed > 0 { done.addButton(withTitle: L("Show Trash", "Toon prullenmand")) }
                NSApp.activate(ignoringOtherApps: true)
                if done.runModal() == .alertSecondButtonReturn {
                    NSWorkspace.shared.open(URL(fileURLWithPath: NSHomeDirectory() + "/.Trash"))
                }
                finished(outcome.cleaned)
            }
        }
    }

    private func quitProcess(_ usage: AppUsage) {
        closePanel()
        let alert = NSAlert()
        alert.messageText = L("Quit \(usage.name)?", "\(usage.name) stoppen?")
        let count = usage.pids.count
        alert.informativeText = (count == 1 ? "pid \(usage.pids[0])" : "\(count) " + L("processes", "processen"))
            + "\n\n" + L("Force Quit stops it right away; unsaved work is lost.",
                           "Geforceerd stoppen stopt hem meteen; niet-bewaard werk gaat verloren.")
        alert.addButton(withTitle: L("Quit", "Stop"))
        alert.addButton(withTitle: L("Force Quit", "Geforceerd stoppen"))
        alert.addButton(withTitle: L("Cancel", "Annuleer"))
        NSApp.activate(ignoringOtherApps: true)
        let answer = alert.runModal()
        guard answer != .alertThirdButtonReturn else { return }
        ProcessMonitor.quit(usage, force: answer == .alertSecondButtonReturn)
        activityTicks = 0
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.2) { [weak self] in self?.tickChart() }
    }

    private func revealFolder(_ path: String) {
        closePanel()
        NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: path)])
    }

    private func openTerminal(_ path: String) {
        guard let terminal = NSWorkspace.shared.urlForApplication(withBundleIdentifier: "com.apple.Terminal") else { return }
        closePanel()
        NSWorkspace.shared.open([URL(fileURLWithPath: path)], withApplicationAt: terminal,
                                configuration: NSWorkspace.OpenConfiguration())
    }

    private func stopGroup(_ id: Int32) {
        guard let group = groups.first(where: { $0.id == id }) else { return }
        closePanel()
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
        // The scan can be up to 30s old; only signal PIDs still running the same executable,
        // so a reused PID never hits an unrelated process.
        for proc in group.processes where !proc.execPath.isEmpty && Scanner.execPath(proc.pid) == proc.execPath {
            kill(proc.pid, SIGTERM)
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) { self.refresh() }
    }

    private func setIncludeApps(_ on: Bool) {
        includeApps = on
        lastSignature = ""
        refresh()
    }

    private func setLogin(_ on: Bool) {
        do {
            if on {
                if SMAppService.mainApp.status != .enabled { try SMAppService.mainApp.register() }
            } else if SMAppService.mainApp.status == .enabled {
                try SMAppService.mainApp.unregister()
            }
        } catch {
            let alert = NSAlert(error: error)
            NSApp.activate(ignoringOtherApps: true)
            alert.runModal()
        }
        board.setToggles(apps: includeApps, login: SMAppService.mainApp.status == .enabled)
    }
}

// `iServer --list [--all]` prints the detected servers without showing a menu bar icon.
if CommandLine.arguments.contains("--list") {
    let groups = CommandLine.arguments.contains("--demo")
        ? Demo.groups() : Scanner.scan(includeApps: CommandLine.arguments.contains("--all"))
    for g in groups {
        print("\(g.exposed ? "🟠" : "🟢") \(g.title)  " + g.listeners.map { ":\($0.port)\($0.exposed ? "*" : "")" }.joined(separator: " "))
        print("   \(g.detail)")
        print("   \(Scanner.formatCPU(g.cpu))  \(Scanner.formatBytes(g.rss))")
        for p in g.processes { print("   - \(p.execName) pid \(p.pid) · \(Scanner.formatCPU(p.cpu)) · \(Scanner.formatBytes(p.rss)) · \(Scanner.formatElapsed(p.elapsed))") }
    }
    exit(0)
}

let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
app.setActivationPolicy(.accessory)
app.run()
