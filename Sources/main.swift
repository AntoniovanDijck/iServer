// iServer — a menu bar app that shows which development servers are running on your Mac.
import AppKit
import CryptoKit
import Darwin
import IOKit
import IOKit.ps
import IOKit.pwr_mgt
import Network
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

// MARK: - iNotch data: AI usage limits and agent sessions

struct QuotaWindow {
    var used: Double        // 0...1
    var resetsAt: Date?
}

struct ProviderUsage {
    let name: String
    var plan: String?
    var fiveHour: QuotaWindow?
    var weekly: QuotaWindow?
    var note: String?       // why there is no reading, or how old it is
    var asOf: Date?
}

enum AIUsage {
    static let home = NSHomeDirectory()

    // Codex writes its current limits into every session log, so they are read locally: no network, no login.
    static func codex() -> ProviderUsage {
        var usage = ProviderUsage(name: "Codex")
        let files = AgentWatcher.codexFiles(days: 8).sorted { $0.modified > $1.modified }
        guard !files.isEmpty else {
            usage.note = L("No Codex sessions yet", "Nog geen Codex-sessies")
            return usage
        }
        for file in files.prefix(6) {
            for line in AgentWatcher.tail(file.path, bytes: 400_000).reversed() {
                guard line.contains("\"rate_limits\""), let entry = AgentWatcher.json(line),
                      let payload = entry["payload"] as? [String: Any], payload["type"] as? String == "token_count",
                      let limits = payload["rate_limits"] as? [String: Any] else { continue }
                for key in ["primary", "secondary"] {
                    guard let window = limits[key] as? [String: Any],
                          let percent = (window["used_percent"] as? NSNumber)?.doubleValue else { continue }
                    let minutes = (window["window_minutes"] as? NSNumber)?.intValue ?? (key == "primary" ? 300 : 10_080)
                    let reset = (window["resets_at"] as? NSNumber).map { Date(timeIntervalSince1970: $0.doubleValue) }
                    // A window that has reset since the reading was taken is empty again, with no reset time to show.
                    let passed = reset.map { $0 < Date() } ?? false
                    let quota = QuotaWindow(used: passed ? 0 : percent / 100, resetsAt: passed ? nil : reset)
                    if minutes >= 1440 { usage.weekly = quota } else { usage.fiveHour = quota }
                }
                usage.plan = (limits["plan_type"] as? String)?.capitalized
                usage.asOf = file.modified
                return usage
            }
        }
        usage.note = L("No limits in recent sessions", "Geen limieten in recente sessies")
        return usage
    }

    // Claude Code keeps its sign-in in the Keychain; its usage endpoint needs that token. The token is only
    // read, never refreshed or stored: when it has expired, running Claude Code renews it.
    static func claude() -> ProviderUsage {
        var usage = ProviderUsage(name: "Claude")
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "Claude Code-credentials",
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var item: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess, let data = item as? Data,
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let oauth = json["claudeAiOauth"] as? [String: Any],
              let token = oauth["accessToken"] as? String else {
            usage.note = L("Sign in to Claude Code first", "Log eerst in bij Claude Code")
            return usage
        }
        usage.plan = (oauth["subscriptionType"] as? String)?.capitalized
        if let expires = (oauth["expiresAt"] as? NSNumber)?.doubleValue, expires / 1000 < Date().timeIntervalSince1970 {
            usage.note = L("Sign-in expired; open Claude Code once", "Inlog verlopen; open Claude Code even")
            return usage
        }
        var request = URLRequest(url: URL(string: "https://api.anthropic.com/api/oauth/usage")!, timeoutInterval: 15)
        request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        request.setValue("oauth-2025-04-20", forHTTPHeaderField: "anthropic-beta")
        request.setValue("claude-code/2.1.121", forHTTPHeaderField: "User-Agent")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        let done = DispatchSemaphore(value: 0)
        var body: Data?
        var status = 0
        URLSession.shared.dataTask(with: request) { data, response, _ in
            body = data
            status = (response as? HTTPURLResponse)?.statusCode ?? 0
            done.signal()
        }.resume()
        _ = done.wait(timeout: .now() + 20)
        guard status == 200, let body, let object = try? JSONSerialization.jsonObject(with: body) as? [String: Any] else {
            usage.note = status == 429 ? L("Rate limited, try later", "Te vaak gevraagd, later opnieuw")
                : (status == 401 ? L("Sign-in expired; open Claude Code once", "Inlog verlopen; open Claude Code even")
                   : L("Couldn't reach Claude", "Claude niet bereikbaar"))
            return usage
        }
        func window(_ key: String) -> QuotaWindow? {
            guard let entry = object[key] as? [String: Any],
                  let percent = (entry["utilization"] as? NSNumber)?.doubleValue else { return nil }
            var reset: Date?
            if let text = entry["resets_at"] as? String {
                let formatter = ISO8601DateFormatter()
                formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
                reset = formatter.date(from: text) ?? ISO8601DateFormatter().date(from: text)
            }
            return QuotaWindow(used: percent / 100, resetsAt: reset)
        }
        usage.fiveHour = window("five_hour")
        usage.weekly = window("seven_day")
        usage.asOf = Date()
        return usage
    }

    static func demo() -> [ProviderUsage] {
        let now = Date()
        return [
            ProviderUsage(name: "Claude", plan: "Max", fiveHour: QuotaWindow(used: 0.42, resetsAt: now.addingTimeInterval(7_800)),
                          weekly: QuotaWindow(used: 0.61, resetsAt: now.addingTimeInterval(260_000)), asOf: now),
            ProviderUsage(name: "Codex", plan: "Plus", fiveHour: QuotaWindow(used: 0.18, resetsAt: now.addingTimeInterval(12_000)),
                          weekly: QuotaWindow(used: 0.33, resetsAt: now.addingTimeInterval(400_000)), asOf: now),
        ]
    }
}

enum AgentState { case working, waiting, done }

struct AgentSession {
    let id: String
    let agent: String       // "Claude Code" or "Codex"
    var project: String
    var action: String
    var state: AgentState
    var updated: Date
}

// Follows Claude Code and Codex sessions by reading the logs they already write; nothing is installed or changed.
enum AgentWatcher {
    static let home = NSHomeDirectory()

    struct LogFile {
        let path: String
        let modified: Date
    }

    static func modified(_ path: String) -> Date? {
        (try? URL(fileURLWithPath: path).resourceValues(forKeys: [.contentModificationDateKey]))?.contentModificationDate
    }

    static func json(_ line: String) -> [String: Any]? {
        guard let data = line.data(using: .utf8) else { return nil }
        return (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
    }

    // The last lines of a file, without reading all of it.
    static func tail(_ path: String, bytes: Int = 160_000) -> [String] {
        guard let handle = FileHandle(forReadingAtPath: path) else { return [] }
        defer { try? handle.close() }
        let size = (try? handle.seekToEnd()) ?? 0
        let start = size > UInt64(bytes) ? size - UInt64(bytes) : 0
        guard (try? handle.seek(toOffset: start)) != nil, let data = try? handle.readToEnd() else { return [] }
        var lines = String(decoding: data, as: UTF8.self).split(separator: "\n").map(String.init)
        if start > 0, !lines.isEmpty { lines.removeFirst() }  // likely cut in half
        return lines
    }

    static func codexFiles(days: Int) -> [LogFile] {
        let calendar = Calendar.current
        var out: [LogFile] = []
        for offset in 0..<days {
            guard let day = calendar.date(byAdding: .day, value: -offset, to: Date()) else { continue }
            let parts = calendar.dateComponents([.year, .month, .day], from: day)
            let dir = String(format: "%@/.codex/sessions/%04d/%02d/%02d", home, parts.year ?? 0, parts.month ?? 0, parts.day ?? 0)
            for path in DevClean.children(of: dir) where path.hasSuffix(".jsonl") {
                if let date = modified(path) { out.append(LogFile(path: path, modified: date)) }
            }
        }
        return out
    }

    // Sessions active in the last half hour; finished ones stay for ten minutes.
    static func scan() -> [AgentSession] {
        let now = Date()
        var sessions: [AgentSession] = []
        for dir in DevClean.children(of: home + "/.claude/projects") {
            for path in DevClean.children(of: dir) where path.hasSuffix(".jsonl") {
                guard let date = modified(path), now.timeIntervalSince(date) < 1800 else { continue }
                if let session = claudeSession(path, modified: date) { sessions.append(session) }
            }
        }
        for file in codexFiles(days: 1) where now.timeIntervalSince(file.modified) < 1800 {
            if let session = codexSession(file.path, modified: file.modified) { sessions.append(session) }
        }
        return sessions.filter { $0.state != .done || now.timeIntervalSince($0.updated) < 600 }
            .sorted { $0.updated > $1.updated }
    }

    static func state(finished: Bool, waitingOnTool: Bool, age: TimeInterval) -> AgentState? {
        if finished { return .done }
        if age < 25 { return .working }
        if waitingOnTool { return age < 1800 ? .waiting : nil }
        return age < 300 ? .working : nil  // quiet for long without finishing: stopped or interrupted
    }

    static func claudeSession(_ path: String, modified: Date) -> AgentSession? {
        var cwd: String?
        var title: String?
        for line in tail(path).reversed() {
            guard let entry = json(line), let type = entry["type"] as? String else { continue }
            if type == "custom-title", title == nil { title = entry["customTitle"] as? String }
            guard type == "assistant" || type == "user", entry["isSidechain"] as? Bool != true,
                  let message = entry["message"] as? [String: Any] else { continue }
            cwd = entry["cwd"] as? String
            let content = message["content"] as? [[String: Any]] ?? []
            var finished = false
            var waiting = false
            var action = L("Thinking…", "Denkt na…")
            if type == "assistant" {
                if let tool = content.last(where: { $0["type"] as? String == "tool_use" }) {
                    action = describe(tool["name"] as? String ?? "", tool["input"] as? [String: Any] ?? [:])
                    waiting = true
                } else {
                    finished = message["stop_reason"] as? String == "end_turn"
                    action = L("Finished", "Klaar")
                }
            } else if content.contains(where: { $0["type"] as? String == "tool_result" }) {
                action = L("Thinking…", "Denkt na…")
            } else {
                action = L("Got a new prompt", "Kreeg een nieuwe opdracht")
            }
            guard let state = state(finished: finished, waitingOnTool: waiting, age: Date().timeIntervalSince(modified)) else { return nil }
            if state == .waiting { action = L("Waiting · may need you", "Wacht · heeft je misschien nodig") }
            let project = cwd.map { ($0 as NSString).lastPathComponent } ?? title ?? "Claude Code"
            return AgentSession(id: path, agent: "Claude Code", project: project, action: action, state: state, updated: modified)
        }
        return nil
    }

    static func codexSession(_ path: String, modified: Date) -> AgentSession? {
        var cwd: String?
        var state: AgentState?
        var action: String?
        for line in tail(path).reversed() {
            guard let entry = json(line), let payload = entry["payload"] as? [String: Any] else { continue }
            if cwd == nil, let dir = payload["cwd"] as? String { cwd = dir }
            let kind = payload["type"] as? String ?? ""
            if state == nil, action == nil {
                switch (entry["type"] as? String ?? "", kind) {
                case ("event_msg", "task_complete"):
                    state = .done
                    action = L("Finished", "Klaar")
                case ("response_item", "function_call"), ("response_item", "custom_tool_call"):
                    let name = payload["name"] as? String ?? ""
                    action = name == "apply_patch" ? L("Editing files", "Bewerkt bestanden")
                        : L("Running", "Voert uit") + " " + codexCommand(payload["arguments"] as? String ?? "")
                case ("event_msg", "task_started"), ("response_item", "reasoning"), ("response_item", "message"):
                    action = L("Thinking…", "Denkt na…")
                default:
                    break
                }
            }
            if cwd != nil, action != nil { break }
        }
        let age = Date().timeIntervalSince(modified)
        guard let resolved = state ?? AgentWatcher.state(finished: false, waitingOnTool: false, age: age) else { return nil }
        let project = cwd.map { ($0 as NSString).lastPathComponent } ?? "Codex"
        return AgentSession(id: path, agent: "Codex", project: project, action: action ?? L("Working", "Bezig"),
                            state: resolved, updated: modified)
    }

    static func codexCommand(_ arguments: String) -> String {
        guard let args = json(arguments) else { return "" }
        let command = (args["command"] as? [String])?.joined(separator: " ") ?? (args["cmd"] as? String) ?? ""
        return String(command.replacingOccurrences(of: "bash -lc ", with: "").prefix(48))
    }

    static func describe(_ tool: String, _ input: [String: Any]) -> String {
        let file = (input["file_path"] as? String).map { ($0 as NSString).lastPathComponent } ?? ""
        switch tool {
        case "Edit", "MultiEdit", "Write", "NotebookEdit": return L("Editing", "Bewerkt") + " " + file
        case "Read": return L("Reading", "Leest") + " " + file
        case "Bash":
            let command = (input["command"] as? String ?? "").split(separator: "\n").first.map(String.init) ?? ""
            return L("Running", "Voert uit") + " " + String(command.prefix(48))
        case "Grep", "Glob": return L("Searching the code", "Zoekt in de code")
        case "WebFetch", "WebSearch": return L("Looking on the web", "Zoekt op het web")
        case "Task", "Agent": return L("Running a helper agent", "Laat een hulpagent werken")
        default: return L("Using", "Gebruikt") + " " + tool
        }
    }

    static func demo() -> [AgentSession] {
        let now = Date()
        return [
            AgentSession(id: "1", agent: "Claude Code", project: "acme-web", action: L("Editing", "Bewerkt") + " Checkout.tsx",
                         state: .working, updated: now),
            AgentSession(id: "2", agent: "Codex", project: "acme-api", action: L("Waiting · may need you", "Wacht · heeft je misschien nodig"),
                         state: .waiting, updated: now.addingTimeInterval(-40)),
            AgentSession(id: "3", agent: "Claude Code", project: "docs", action: L("Finished", "Klaar"),
                         state: .done, updated: now.addingTimeInterval(-180)),
        ]
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
    var text: String        // the text, link, file path, colour, or "1200 × 800" for an image
    var kind: String        // text, code, link, color, file, image
    var app: String
    var date: Date
    var pinned: Bool
    var digest: String? = nil  // images: SHA-256 of the PNG, to spot the same image copied twice
}

// Parses "#abc", "#aabbcc", "#aabbccdd", "rgb(1, 2, 3)" and "rgba(1, 2, 3, 0.5)".
func parseColor(_ text: String) -> NSColor? {
    let value = text.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
    if value.hasPrefix("#") {
        var hex = String(value.dropFirst())
        guard [3, 6, 8].contains(hex.count), hex.allSatisfy(\.isHexDigit) else { return nil }
        if hex.count == 3 { hex = hex.map { "\($0)\($0)" }.joined() }
        guard let number = UInt64(hex, radix: 16) else { return nil }
        let hasAlpha = hex.count == 8
        let r = Double((number >> (hasAlpha ? 24 : 16)) & 0xff) / 255
        let g = Double((number >> (hasAlpha ? 16 : 8)) & 0xff) / 255
        let b = Double((number >> (hasAlpha ? 8 : 0)) & 0xff) / 255
        let a = hasAlpha ? Double(number & 0xff) / 255 : 1
        return NSColor(srgbRed: r, green: g, blue: b, alpha: a)
    }
    for prefix in ["rgba(", "rgb("] where value.hasPrefix(prefix) && value.hasSuffix(")") {
        let parts = value.dropFirst(prefix.count).dropLast().split(separator: ",").map {
            Double($0.trimmingCharacters(in: .whitespaces)) ?? -1
        }
        guard (3...4).contains(parts.count), parts.prefix(3).allSatisfy({ (0...255).contains($0) }) else { return nil }
        return NSColor(srgbRed: parts[0] / 255, green: parts[1] / 255, blue: parts[2] / 255,
                       alpha: parts.count == 4 ? min(1, max(0, parts[3])) : 1)
    }
    return nil
}

final class ClipBook {
    private(set) var items: [ClipItem] = []
    var onChange: () -> Void = {}
    private var suppressChange = -1
    private var seenChange = NSPasteboard.general.changeCount
    private var sourceApp = ""
    private let file: URL
    private let imageDir: URL
    private var images: [UUID: Data] = [:]  // PNG; only pinned images are written to disk
    private var thumbnails: [UUID: NSImage] = [:]
    private static let maxLoose = 40
    private static let maxImages = 15
    private static let maxImageBytes = 25_000_000

    init() {
        let dir = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("iServer", isDirectory: true)
        imageDir = dir.appendingPathComponent("images", isDirectory: true)
        try? FileManager.default.createDirectory(at: imageDir, withIntermediateDirectories: true)
        file = dir.appendingPathComponent("clips.json")
        if let data = try? Data(contentsOf: file),
           let saved = try? JSONDecoder().decode([ClipItem].self, from: data) {
            items = saved.filter(\.pinned)
            for item in items where item.kind == "image" {
                images[item.id] = try? Data(contentsOf: imageFile(item.id))
            }
            items.removeAll { $0.kind == "image" && images[$0.id] == nil }
            if items.count != saved.count { store() }  // scrub unpinned history written by older versions
        }
        noteFrontmost()
        NSWorkspace.shared.notificationCenter.addObserver(
            self, selector: #selector(appActivated), name: NSWorkspace.didActivateApplicationNotification, object: nil)
    }

    private func imageFile(_ id: UUID) -> URL { imageDir.appendingPathComponent(id.uuidString + ".png") }

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
        if let text = board.string(forType: .string) {
            let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !trimmed.isEmpty, trimmed.count <= 50_000 else { return }
            remember(trimmed, kind: ClipBook.classify(trimmed))
            return
        }
        if let data = board.data(forType: .png) ?? board.data(forType: .tiff), data.count <= ClipBook.maxImageBytes,
           let png = NSBitmapImageRep(data: data)?.representation(using: .png, properties: [:]) {
            rememberImage(png)
        }
    }

    static func classify(_ text: String) -> String {
        if !text.contains(where: \.isWhitespace), text.hasPrefix("http://") || text.hasPrefix("https://") { return "link" }
        if parseColor(text) != nil { return "color" }
        return looksLikeCode(text) ? "code" : "text"
    }

    // Several lines with the punctuation and keywords code is full of.
    static func looksLikeCode(_ text: String) -> Bool {
        let lines = text.split(separator: "\n", omittingEmptySubsequences: true)
        guard lines.count >= 2 else { return false }
        let markers = ["{", "}", ";", "=>", "->", "func ", "def ", "const ", "let ", "var ", "import ", "return ",
                       "</", "#include", "class ", "if (", "if ", "fn ", "$ ", "npm ", "git "]
        let hits = markers.filter { text.contains($0) }.count
        let indented = lines.filter { $0.hasPrefix("  ") || $0.hasPrefix("\t") }.count
        return hits >= 3 || (hits >= 2 && indented >= 1)
    }

    func image(_ item: ClipItem) -> NSImage? {
        if let cached = thumbnails[item.id] { return cached }
        guard let data = images[item.id], let image = NSImage(data: data) else { return nil }
        thumbnails[item.id] = image
        return image
    }

    func imageBytes(_ item: ClipItem) -> Int { images[item.id]?.count ?? 0 }

    func copy(_ item: ClipItem) {
        let board = NSPasteboard.general
        board.clearContents()
        switch item.kind {
        case "file":
            board.writeObjects([URL(fileURLWithPath: item.text) as NSURL])
        case "image":
            guard let png = images[item.id] else { return }
            board.setData(png, forType: .png)
            if let tiff = NSImage(data: png)?.tiffRepresentation { board.setData(tiff, forType: .tiff) }
        default:
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
        if items[index].kind == "image" {
            if items[index].pinned {
                try? images[id]?.write(to: imageFile(id), options: .atomic)
            } else {
                try? FileManager.default.removeItem(at: imageFile(id))
            }
        }
        sortPinnedFirst()
        store()
        onChange()
    }

    func remove(_ id: UUID) {
        if items.first(where: { $0.id == id })?.pinned == true { try? FileManager.default.removeItem(at: imageFile(id)) }
        items.removeAll { $0.id == id }
        forget([id])
        store()
        onChange()
    }

    // Removes everything that isn't pinned.
    func clearHistory() {
        let loose = items.filter { !$0.pinned }.map(\.id)
        items.removeAll { !$0.pinned }
        forget(loose)
        onChange()
    }

    private func forget(_ ids: [UUID]) {
        for id in ids {
            images[id] = nil
            thumbnails[id] = nil
        }
    }

    private func sortPinnedFirst() {
        items.sort { lhs, rhs in
            if lhs.pinned != rhs.pinned { return lhs.pinned && !rhs.pinned }
            return lhs.date > rhs.date
        }
    }

    private func remember(_ text: String, kind: String) {
        if items.contains(where: { $0.text == text && $0.pinned && $0.kind != "image" }) { return }
        let duplicates = items.filter { $0.text == text && !$0.pinned && $0.kind != "image" }.map(\.id)
        items.removeAll { duplicates.contains($0.id) }
        insert(ClipItem(id: UUID(), text: text, kind: kind, app: sourceApp, date: Date(), pinned: false))
    }

    private func rememberImage(_ png: Data) {
        let digest = SHA256.hash(data: png).map { String(format: "%02x", $0) }.joined()
        if items.contains(where: { $0.digest == digest && $0.pinned }) { return }
        let duplicates = items.filter { $0.digest == digest }.map(\.id)
        items.removeAll { duplicates.contains($0.id) }
        forget(duplicates)
        let rep = NSBitmapImageRep(data: png)
        let size = "\(rep?.pixelsWide ?? 0) × \(rep?.pixelsHigh ?? 0)"
        let clip = ClipItem(id: UUID(), text: size, kind: "image", app: sourceApp, date: Date(), pinned: false, digest: digest)
        images[clip.id] = png
        insert(clip)
    }

    // Newest unpinned item goes right after the pinned ones; old history and extra images fall off.
    private func insert(_ clip: ClipItem) {
        let pinCount = items.filter(\.pinned).count
        items.insert(clip, at: min(pinCount, items.count))
        var loose = items.filter { !$0.pinned }
        var dropped: [UUID] = []
        if loose.count > ClipBook.maxLoose {
            dropped += loose.dropFirst(ClipBook.maxLoose).map(\.id)
            loose = Array(loose.prefix(ClipBook.maxLoose))
        }
        let looseImages = loose.filter { $0.kind == "image" }
        if looseImages.count > ClipBook.maxImages {
            let extra = Set(looseImages.dropFirst(ClipBook.maxImages).map(\.id))
            dropped += extra
            loose.removeAll { extra.contains($0.id) }
        }
        items = items.filter(\.pinned) + loose
        forget(dropped)
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

    var symbol: String {
        get { symbolName }
        set {
            symbolName = newValue
            needsDisplay = true
        }
    }

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
    var onScan: () -> Void = {}
    private lazy var back = IconButton(symbol: "chevron.left", help: L("Back", "Terug")) { [weak self] in self?.onBack() }
    private lazy var scan = AccentButton { [weak self] in self?.onScan() }
    private lazy var rescan = IconButton(symbol: "arrow.clockwise", help: L("Measure this folder again", "Meet deze map opnieuw")) {
        [weak self] in self?.onScan()
    }
    private let spinner = NSProgressIndicator()
    private var title = ""
    private var subtitle = ""

    override init(frame frameRect: NSRect) {
        super.init(frame: frameRect)
        spinner.style = .spinning
        spinner.controlSize = .small
        spinner.isDisplayedWhenStopped = false
        scan.title = L("Scan", "Scannen")
        addSubview(back)
        addSubview(scan)
        addSubview(rescan)
        addSubview(spinner)
    }

    required init?(coder: NSCoder) { fatalError() }

    func set(title: String, subtitle: String, canGoBack: Bool, busy: Bool, started: Bool) {
        self.title = title
        self.subtitle = subtitle
        back.isHidden = !canGoBack
        scan.isHidden = started
        rescan.isHidden = !started || busy
        if busy { spinner.startAnimation(nil) } else { spinner.stopAnimation(nil) }
        needsDisplay = true
    }

    private var textX: CGFloat { back.isHidden ? Metrics.inset + 52 : Metrics.inset + 80 }

    override func layout() {
        super.layout()
        let card = bounds.insetBy(dx: Metrics.inset, dy: 4)
        back.frame = NSRect(x: card.minX + 10, y: card.midY - 13, width: 26, height: 26)
        spinner.frame = NSRect(x: card.maxX - 30, y: card.midY - 8, width: 16, height: 16)
        rescan.frame = NSRect(x: card.maxX - 38, y: card.midY - 12, width: 26, height: 24)
        let width = scan.preferredWidth
        scan.frame = NSRect(x: card.maxX - 12 - width, y: card.midY - 14, width: width, height: 28)
    }

    override func draw(_ dirtyRect: NSRect) {
        let card = bounds.insetBy(dx: Metrics.inset, dy: 4)
        Draw.card(card, radius: 16)
        let tileX = back.isHidden ? card.minX + 12 : card.minX + 40
        Draw.tile("chart.pie.fill", in: NSRect(x: tileX, y: card.midY - 15, width: 30, height: 30), color: Term.accent)
        let x = tileX + 40
        let attrs: [NSAttributedString.Key: Any] = [.font: termFont(13, .semibold), .foregroundColor: Term.ink]
        let textWidth = (scan.isHidden ? card.maxX - 40 : scan.frame.minX - 8) - x
        (title as NSString).draw(with: NSRect(x: x, y: card.midY + 1, width: textWidth, height: 17),
                                 options: [.usesLineFragmentOrigin, .truncatesLastVisibleLine], attributes: attrs)
        let subAttrs: [NSAttributedString.Key: Any] = [.font: digitFont(11, .regular), .foregroundColor: Term.dim]
        (subtitle as NSString).draw(with: NSRect(x: x, y: card.midY - 15, width: textWidth, height: 15),
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
        header.onScan = { [weak self] in self?.scan() }
        addSubview(header)
        addSubview(placeholder)
        placeholder.stringValue = L("Press Scan to measure your home folder", "Druk op Scannen om je thuismap te meten")
        header.set(title: L("Space explorer", "Ruimteverkenner"),
                   subtitle: L("See what takes up space in your home folder", "Zie wat ruimte inneemt in je thuismap"),
                   canGoBack: false, busy: false, started: false)
    }

    required init?(coder: NSCoder) { fatalError() }

    var contentHeight: CGFloat {
        Metrics.cleanHeader + CGFloat(max(rows.count, 1)) * Metrics.explorerRow + Metrics.listPad * 2
    }

    // The first press measures the home folder; after that it measures the current folder again.
    private func scan() {
        if started {
            sizes = sizes.filter { !$0.key.hasPrefix(path + "/") }
        }
        started = true
        placeholder.stringValue = L("Empty folder", "Lege map")
        open(started ? path : home)
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
        header.set(title: name, subtitle: subtitle, canGoBack: path != home && path.hasPrefix(home), busy: pending > 0, started: true)
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
    private let clip: ClipItem
    private let image: NSImage?
    private let color: NSColor?
    private let preview: NSTextField
    private let meta: NSTextField
    private let pin: IconButton
    private let delete: IconButton

    init(clip: ClipItem, image: NSImage?, bytes: Int, copy: @escaping () -> Void, toggle: @escaping () -> Void,
         delete deleteAction: @escaping () -> Void) {
        self.clip = clip
        self.image = image
        color = clip.kind == "color" ? parseColor(clip.text) : nil
        let what: String
        var text = clip.text.replacingOccurrences(of: "\n", with: " ")
        switch clip.kind {
        case "link": what = L("Link", "Link")
        case "file": what = L("File", "Bestand")
        case "image":
            what = L("Image", "Afbeelding")
            text = L("Image", "Afbeelding") + "  ·  " + clip.text + (bytes > 0 ? "  ·  " + Scanner.formatBytes(UInt64(bytes)) : "")
        case "color": what = L("Colour", "Kleur")
        case "code":
            what = L("Code", "Code")
            text = clip.text.split(separator: "\n").map { $0.trimmingCharacters(in: .whitespaces) }.joined(separator: "  ")
        default: what = L("Text", "Tekst")
        }
        preview = makeLabel(text, size: 12, weight: .medium, color: Term.ink)
        if clip.kind == "code" || clip.kind == "color" { preview.font = NSFont.monospacedSystemFont(ofSize: 11.5, weight: .medium) }
        let who = clip.app.isEmpty ? what : "\(what)  ·  \(clip.app)"
        meta = makeLabel("\(who)  ·  \(ClipRow.ago(clip.date))", size: 10, weight: .regular, color: Term.dim)
        pin = IconButton(symbol: clip.pinned ? "pin.fill" : "pin", help: clip.pinned ? L("Unpin", "Losmaken") : L("Pin", "Vastzetten"),
                         action: toggle)
        delete = IconButton(symbol: "trash", help: L("Remove", "Verwijder"), destructive: true, action: deleteAction)
        super.init(frame: .zero)
        onClick = copy
        toolTip = clip.kind == "image" ? nil : String(clip.text.prefix(2000))
        for view in [preview, meta, pin, delete] as [NSView] { addSubview(view) }
        pin.isHidden = !clip.pinned
        delete.isHidden = true
    }

    required init?(coder: NSCoder) { fatalError() }

    override func refresh() {
        super.refresh()
        pin.isHidden = !(clip.pinned || hovered)
        delete.isHidden = !hovered
    }

    override func hitTest(_ point: NSPoint) -> NSView? {
        let local = convert(point, from: superview)
        guard bounds.contains(local) else { return nil }
        for button in [pin, delete] where !button.isHidden && button.frame.contains(local) { return button }
        return self
    }

    override func layout() {
        super.layout()
        delete.frame = NSRect(x: bounds.width - Metrics.inset - 32, y: (bounds.height - 24) / 2, width: 26, height: 24)
        pin.frame = NSRect(x: delete.frame.minX - 28, y: (bounds.height - 24) / 2, width: 26, height: 24)
        let left = Metrics.inset + 52
        preview.frame = NSRect(x: left, y: bounds.height / 2 + 1, width: max(40, pin.frame.minX - left - 6), height: 16)
        meta.frame = NSRect(x: left, y: bounds.height / 2 - 15, width: preview.frame.width, height: 13)
    }

    override func draw(_ dirtyRect: NSRect) {
        if hovered || pressed {
            Draw.card(bounds.insetBy(dx: Metrics.inset, dy: 2), hot: true, radius: 12)
        }
        let tile = NSRect(x: Metrics.inset + 10, y: bounds.midY - 16, width: 32, height: 32)
        if let image {
            // Thumbnail, filled into a rounded square
            NSGraphicsContext.saveGraphicsState()
            NSBezierPath(roundedRect: tile, xRadius: 8, yRadius: 8).addClip()
            let size = image.size
            let scale = max(tile.width / max(size.width, 1), tile.height / max(size.height, 1))
            let drawn = NSSize(width: size.width * scale, height: size.height * scale)
            image.draw(in: NSRect(x: tile.midX - drawn.width / 2, y: tile.midY - drawn.height / 2, width: drawn.width, height: drawn.height))
            NSGraphicsContext.restoreGraphicsState()
            Term.stroke.setStroke()
            NSBezierPath(roundedRect: tile.insetBy(dx: 0.5, dy: 0.5), xRadius: 8, yRadius: 8).stroke()
        } else if let color {
            color.setFill()
            NSBezierPath(roundedRect: tile.insetBy(dx: 2, dy: 2), xRadius: 14, yRadius: 14).fill()
            Term.stroke.setStroke()
            NSBezierPath(roundedRect: tile.insetBy(dx: 2.5, dy: 2.5), xRadius: 14, yRadius: 14).stroke()
        } else {
            let (symbol, tint): (String, NSColor) = {
                switch clip.kind {
                case "link": return ("link", .systemBlue)
                case "file": return ("doc.fill", .systemOrange)
                case "code": return ("chevron.left.forwardslash.chevron.right", .systemGreen)
                default: return ("text.alignleft", .systemGray)
                }
            }()
            Draw.tile(symbol, in: tile.insetBy(dx: 1, dy: 1), color: tint)
        }
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
    var onDelete: (ClipItem) -> Void = { _ in }
    var onClear: () -> Void = {}
    var onFilter: () -> Void = {}
    var imageFor: (ClipItem) -> NSImage? = { _ in nil }
    var bytesFor: (ClipItem) -> Int = { _ in 0 }
    private let field = NSTextField()
    private let filters = ModeBar(titles: [L("All", "Alles"), L("Text", "Tekst"), L("Links", "Links"),
                                           L("Images", "Beeld"), L("Files", "Bestand"), L("Pinned", "Vast")])
    private let empty = makeLabel(L("Clipboard is empty", "Klembord is leeg"), size: 13, weight: .semibold, color: Term.dim)
    private let pinnedLabel = makeLabel(L("Pinned", "Vastgezet"), size: 11, weight: .semibold, color: Term.dim)
    private let recentLabel = makeLabel(L("Recent", "Recent"), size: 11, weight: .semibold, color: Term.dim)
    private lazy var clear = QuietButton(L("Clear history", "Geschiedenis wissen")) { [weak self] in self?.onClear() }
    private var all: [ClipItem] = []
    private var rows: [ClipRow] = []
    private var pinnedCount = 0
    private var filter = 0
    private static let sectionHeight: CGFloat = 26

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
        filters.onSelect = { [weak self] index in
            guard let self else { return }
            self.filter = index
            self.rebuild()
            self.onFilter()
        }
        for view in [field, filters, empty, pinnedLabel, recentLabel, clear] as [NSView] { addSubview(view) }
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

    private var showsSections: Bool { filter != 5 && pinnedCount > 0 && rows.count > pinnedCount }
    private var hasLoose: Bool { all.contains { !$0.pinned } }

    var contentHeight: CGFloat {
        var height: CGFloat = 46 + 40
        height += rows.isEmpty ? 60 : CGFloat(rows.count) * Metrics.clip
        if showsSections { height += ClipPane.sectionHeight * 2 }
        if hasLoose && filter != 5 { height += 44 }
        return height + Metrics.listPad * 2
    }

    private func matches(_ clip: ClipItem) -> Bool {
        switch filter {
        case 1: return ["text", "code", "color"].contains(clip.kind)
        case 2: return clip.kind == "link"
        case 3: return clip.kind == "image"
        case 4: return clip.kind == "file"
        case 5: return clip.pinned
        default: return true
        }
    }

    private func rebuild() {
        rows.forEach { $0.removeFromSuperview() }
        let query = field.stringValue.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        let shown = all.filter(matches).filter {
            query.isEmpty || $0.text.lowercased().contains(query) || $0.app.lowercased().contains(query) || $0.kind.contains(query)
        }
        // Pinned first, then the rest by time (the store keeps that order already).
        rows = shown.map { clip in
            ClipRow(clip: clip, image: imageFor(clip), bytes: bytesFor(clip),
                    copy: { [weak self] in self?.onCopy(clip) },
                    toggle: { [weak self] in self?.onPin(clip) },
                    delete: { [weak self] in self?.onDelete(clip) })
        }
        pinnedCount = shown.filter(\.pinned).count
        rows.forEach(addSubview)
        empty.stringValue = all.isEmpty ? L("Clipboard is empty", "Klembord is leeg") : L("Nothing matches", "Niets gevonden")
        empty.isHidden = !rows.isEmpty
        pinnedLabel.isHidden = !showsSections
        recentLabel.isHidden = !showsSections
        clear.isHidden = !(hasLoose && filter != 5)
        needsLayout = true
        needsDisplay = true
    }

    private var searchRect: NSRect { NSRect(x: Metrics.inset, y: 6, width: bounds.width - Metrics.inset * 2, height: 30) }

    override func layout() {
        super.layout()
        let search = searchRect
        field.frame = NSRect(x: search.minX + 32, y: search.minY + 7, width: search.width - 44, height: 17)
        filters.frame = NSRect(x: 0, y: 44, width: bounds.width, height: 36)
        var y: CGFloat = 86
        empty.frame = NSRect(x: 16, y: y + 20, width: max(0, bounds.width - 32), height: 16)
        for (index, row) in rows.enumerated() {
            if showsSections && index == 0 {
                pinnedLabel.frame = NSRect(x: Metrics.inset + 6, y: y + 8, width: 200, height: 14)
                y += ClipPane.sectionHeight
            }
            if showsSections && index == pinnedCount {
                recentLabel.frame = NSRect(x: Metrics.inset + 6, y: y + 8, width: 200, height: 14)
                y += ClipPane.sectionHeight
            }
            row.frame = NSRect(x: 0, y: y, width: bounds.width, height: Metrics.clip)
            y += Metrics.clip
        }
        if rows.isEmpty { y += 60 }
        clear.frame = NSRect(x: (bounds.width - 150) / 2, y: y + 10, width: 150, height: 26)
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
    var setNotch: (Bool) -> Void = { _ in }
    var notchOn = false { didSet { notchToggle.checked = notchOn } }
    var quit: () -> Void = {}
    var onPage: () -> Void = {}
    var relayout: () -> Void = {}
    var cleanItems: ([CleanItem], @escaping (Set<String>) -> Void) -> Void = { _, _ in }
    var runningFolders: () -> [String] = { [] }
    var quitProcess: (AppUsage) -> Void = { _ in }
    var copyClip: (ClipItem) -> Void = { _ in }
    var pinClip: (ClipItem) -> Void = { _ in }
    var deleteClip: (ClipItem) -> Void = { _ in }
    var clearClips: () -> Void = {}
    var clipImage: (ClipItem) -> NSImage? = { _ in nil }
    var clipBytes: (ClipItem) -> Int = { _ in 0 }
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
    private let notchToggle = TogglePill(L("Notch", "Notch"), symbol: "capsule.portrait.fill",
                                         help: L("iNotch: alerts, AI limits, agents, Pip and a prompter in the notch",
                                                 "iNotch: meldingen, AI-limieten, agents, Pip en een prompter in de notch"))
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
        notchToggle.onChange = { [weak self] on in self?.setNotch(on) }
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
        footer.addSubview(notchToggle)
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
        clips.onDelete = { [weak self] in self?.deleteClip($0) }
        clips.onClear = { [weak self] in self?.clearClips() }
        clips.imageFor = { [weak self] in self?.clipImage($0) }
        clips.bytesFor = { [weak self] in self?.clipBytes($0) ?? 0 }
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
        case 3: return Metrics.capped(clips.contentHeight, maxHeight: maxHeight)
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
        let clipFrame = NSRect(x: 0, y: 0, width: width, height: clips.contentHeight)
        if clips.frame.integral != clipFrame.integral { clips.frame = clipFrame }

        let w = footer.bounds.width
        let h = footer.bounds.height
        hairline.frame = NSRect(x: Metrics.inset + 6, y: h - 1, width: w - Metrics.inset * 2 - 12, height: 1)
        let pill: CGFloat = 26
        appsToggle.frame = NSRect(x: Metrics.inset, y: (h - pill) / 2, width: appsToggle.preferredWidth, height: pill)
        loginToggle.frame = NSRect(x: appsToggle.frame.maxX + 6, y: (h - pill) / 2, width: loginToggle.preferredWidth, height: pill)
        awakeToggle.frame = NSRect(x: loginToggle.frame.maxX + 6, y: (h - pill) / 2, width: awakeToggle.preferredWidth, height: pill)
        notchToggle.frame = NSRect(x: awakeToggle.frame.maxX + 6, y: (h - pill) / 2, width: notchToggle.preferredWidth, height: pill)
        quitButton.frame = NSRect(x: w - Metrics.inset - 30, y: (h - pill) / 2, width: 30, height: pill)
    }
}

// MARK: - iNotch: Pip, the companion

// A damped spring for the island's size and Pip's hop.
struct Spring {
    var value: Double
    var target: Double
    var velocity = 0.0
    var stiffness = 300.0
    var damping = 24.0

    init(_ value: Double) {
        self.value = value
        target = value
    }

    mutating func step(_ dt: Double = 1.0 / 60) -> Bool {
        let force = stiffness * (target - value) - damping * velocity
        velocity += force * dt
        value += velocity * dt
        if abs(target - value) < 0.25 && abs(velocity) < 0.25 {
            value = target
            velocity = 0
            return false
        }
        return true
    }
}

// Pip: a little peach-coloured bean with a sprout on its head. Original to iServer.
final class Companion {
    enum Mood { case idle, happy, worried, sleepy, surprised }
    var mood = Mood.idle
    var dancing = false  // bobs to the music while a song plays
    private var moodUntil = Date.distantPast
    private var nextBlink = Date().addingTimeInterval(2)
    private var blinkUntil = Date.distantPast
    private var hop = Spring(0)
    private let born = Date()

    static let body = NSColor(srgbRed: 1.0, green: 0.78, blue: 0.62, alpha: 1)
    static let leaf = NSColor(srgbRed: 0.45, green: 0.85, blue: 0.48, alpha: 1)

    // Pip's looks; all original to iServer.
    enum Style: String, CaseIterable {
        case sprout, ember, byte, puff, slime

        var name: String {
            switch self {
            case .sprout: return L("Sprout", "Kiemplant")
            case .ember: return L("Ember", "Vlammetje")
            case .byte: return L("Byte", "Robotje")
            case .puff: return L("Puff", "Wolkje")
            case .slime: return L("Slime", "Slijmpje")
            }
        }
    }

    var style: Style {
        get { Style(rawValue: UserDefaults.standard.string(forKey: "pipStyle") ?? "") ?? .sprout }
        set { UserDefaults.standard.set(newValue.rawValue, forKey: "pipStyle") }
    }

    // The face sits on the same body rectangle for every style; only the body and its extras differ.
    private func drawBody(_ body: NSRect, size: CGFloat) {
        let bodyW = body.width, bodyH = body.height
        switch style {
        case .sprout:
            let stemBase = NSPoint(x: body.midX, y: body.maxY - size * 0.02)
            let stemTop = NSPoint(x: body.midX + size * 0.04, y: body.maxY + size * 0.17)
            let stem = NSBezierPath()
            stem.move(to: stemBase)
            stem.curve(to: stemTop, controlPoint1: NSPoint(x: stemBase.x - size * 0.05, y: stemBase.y + size * 0.08),
                       controlPoint2: NSPoint(x: stemTop.x - size * 0.02, y: stemTop.y - size * 0.05))
            stem.lineWidth = max(1, size * 0.045)
            stem.lineCapStyle = .round
            Companion.leaf.setStroke()
            stem.stroke()
            for side in [-1.0, 1.0] {
                let leafPath = NSBezierPath(ovalIn: NSRect(x: -size * 0.11, y: -size * 0.045, width: size * 0.22, height: size * 0.09))
                var transform = AffineTransform()
                transform.translate(x: stemTop.x + CGFloat(side) * size * 0.08, y: stemTop.y + size * 0.02)
                transform.rotate(byDegrees: CGFloat(side) * 28)
                leafPath.transform(using: transform)
                Companion.leaf.setFill()
                leafPath.fill()
            }
            let bean = NSBezierPath(roundedRect: body, xRadius: bodyW * 0.48, yRadius: bodyH * 0.55)
            NSGradient(starting: Companion.body.blended(withFraction: 0.25, of: .white) ?? Companion.body, ending: Companion.body)?
                .draw(in: bean, angle: -90)
        case .ember:
            // A round flame: wide at the bottom, a flickering tip on top
            let flicker = CGFloat(sin(Date().timeIntervalSinceReferenceDate * 9)) * size * 0.03
            let flame = NSBezierPath()
            let tip = NSPoint(x: body.midX + flicker, y: body.maxY + size * 0.26)
            flame.move(to: tip)
            flame.curve(to: NSPoint(x: body.maxX, y: body.minY + bodyH * 0.4),
                        controlPoint1: NSPoint(x: body.midX + bodyW * 0.12, y: body.maxY + size * 0.05),
                        controlPoint2: NSPoint(x: body.maxX, y: body.maxY - bodyH * 0.1))
            flame.curve(to: NSPoint(x: body.minX, y: body.minY + bodyH * 0.4),
                        controlPoint1: NSPoint(x: body.maxX, y: body.minY - bodyH * 0.12),
                        controlPoint2: NSPoint(x: body.minX, y: body.minY - bodyH * 0.12))
            flame.curve(to: tip, controlPoint1: NSPoint(x: body.minX, y: body.maxY - bodyH * 0.1),
                        controlPoint2: NSPoint(x: body.midX - bodyW * 0.12, y: body.maxY + size * 0.05))
            NSGradient(starting: NSColor(srgbRed: 1, green: 0.85, blue: 0.35, alpha: 1),
                       ending: NSColor(srgbRed: 1, green: 0.45, blue: 0.2, alpha: 1))?.draw(in: flame, angle: -90)
        case .byte:
            // A little robot: rounded square head, antenna with a glowing tip
            let antenna = NSBezierPath()
            antenna.move(to: NSPoint(x: body.midX, y: body.maxY))
            antenna.line(to: NSPoint(x: body.midX, y: body.maxY + size * 0.14))
            antenna.lineWidth = max(1, size * 0.04)
            NSColor(white: 0.75, alpha: 1).setStroke()
            antenna.stroke()
            NSColor.systemTeal.setFill()
            NSBezierPath(ovalIn: NSRect(x: body.midX - size * 0.05, y: body.maxY + size * 0.12, width: size * 0.1, height: size * 0.1)).fill()
            let head = NSBezierPath(roundedRect: body, xRadius: bodyW * 0.24, yRadius: bodyW * 0.24)
            NSGradient(starting: NSColor(srgbRed: 0.86, green: 0.9, blue: 0.95, alpha: 1),
                       ending: NSColor(srgbRed: 0.62, green: 0.68, blue: 0.78, alpha: 1))?.draw(in: head, angle: -90)
            let screen = NSBezierPath(roundedRect: body.insetBy(dx: bodyW * 0.1, dy: bodyH * 0.14), xRadius: bodyW * 0.14, yRadius: bodyW * 0.14)
            NSColor(srgbRed: 0.12, green: 0.16, blue: 0.22, alpha: 1).setFill()
            screen.fill()
        case .puff:
            // A small cloud: a few overlapping round puffs
            let cloud = NSBezierPath()
            cloud.appendRoundedRect(NSRect(x: body.minX, y: body.minY, width: bodyW, height: bodyH * 0.7), xRadius: bodyH * 0.35, yRadius: bodyH * 0.35)
            cloud.appendOval(in: NSRect(x: body.minX + bodyW * 0.1, y: body.minY + bodyH * 0.25, width: bodyW * 0.5, height: bodyH * 0.75))
            cloud.appendOval(in: NSRect(x: body.minX + bodyW * 0.38, y: body.minY + bodyH * 0.35, width: bodyW * 0.5, height: bodyH * 0.8))
            NSGradient(starting: .white, ending: NSColor(srgbRed: 0.85, green: 0.86, blue: 1, alpha: 1))?.draw(in: cloud, angle: -90)
        case .slime:
            // A wobbly blue dome with a shine
            let wobble = CGFloat(sin(Date().timeIntervalSinceReferenceDate * 3)) * size * 0.02
            let dome = NSBezierPath()
            dome.move(to: NSPoint(x: body.minX - wobble, y: body.minY))
            dome.curve(to: NSPoint(x: body.maxX + wobble, y: body.minY),
                       controlPoint1: NSPoint(x: body.minX, y: body.maxY + bodyH * 0.35),
                       controlPoint2: NSPoint(x: body.maxX, y: body.maxY + bodyH * 0.35))
            dome.close()
            NSGradient(starting: NSColor(srgbRed: 0.55, green: 0.85, blue: 1, alpha: 1),
                       ending: NSColor(srgbRed: 0.25, green: 0.55, blue: 0.95, alpha: 1))?.draw(in: dome, angle: -90)
            NSColor.white.withAlphaComponent(0.55).setFill()
            NSBezierPath(ovalIn: NSRect(x: body.minX + bodyW * 0.22, y: body.maxY - bodyH * 0.3, width: bodyW * 0.15, height: bodyH * 0.11)).fill()
        }
    }

    // A short reaction, after which Pip goes back to its resting mood.
    func react(_ next: Mood, for seconds: TimeInterval = 2.5) {
        mood = next
        moodUntil = Date().addingTimeInterval(seconds)
        if next == .happy || next == .surprised {
            hop.velocity = next == .happy ? 90 : 60
        }
    }

    // Called every frame; `resting` is the mood when no reaction is playing.
    func tick(resting: Mood) {
        let now = Date()
        if now > moodUntil { mood = resting }
        if now > nextBlink {
            blinkUntil = now.addingTimeInterval(0.14)
            nextBlink = now.addingTimeInterval(Double.random(in: 2.5...6))
        }
        _ = hop.step()
        if mood == .happy, hop.value < 0.5, hop.velocity <= 0, now < moodUntil.addingTimeInterval(-0.6) {
            hop.velocity = 70  // keep bouncing while happy
        }
    }

    // Draws Pip in `rect` (any size). `look` is where the eyes point, in the same coordinates.
    func draw(in rect: NSRect, look: NSPoint?) {
        let now = Date()
        let size = min(rect.width, rect.height)
        let breathe = mood == .sleepy ? sin(now.timeIntervalSince(born) * 1.4) * 0.04 : sin(now.timeIntervalSince(born) * 2.2) * 0.025
        var lift = CGFloat(max(0, hop.value)) * size / 100
        if dancing, mood == .idle || mood == .happy {
            lift += CGFloat(abs(sin(now.timeIntervalSince(born) * 4.2))) * size * 0.09
        }
        let bodyW = size * 0.78
        let bodyH = size * 0.62 * (1 + breathe)
        let body = NSRect(x: rect.midX - bodyW / 2, y: rect.minY + size * 0.06 + lift, width: bodyW, height: bodyH)

        drawBody(body, size: size)

        // Cheeks (not on the robot's screen)
        NSColor(srgbRed: 1, green: 0.5, blue: 0.55, alpha: style == .byte ? 0 : 0.45).setFill()
        for side in [-1.0, 1.0] {
            NSBezierPath(ovalIn: NSRect(x: body.midX + CGFloat(side) * bodyW * 0.3 - size * 0.06, y: body.minY + bodyH * 0.28,
                                        width: size * 0.12, height: size * 0.07)).fill()
        }

        // Eyes look toward the cursor
        var shift = NSPoint.zero
        if let look {
            let dx = look.x - body.midX, dy = look.y - body.midY
            let length = max(1, hypot(dx, dy))
            shift = NSPoint(x: dx / length * size * 0.035, y: dy / length * size * 0.025)
        }
        let eyeY = body.minY + bodyH * 0.55
        let eyeGap = bodyW * 0.17
        let ink = style == .byte ? NSColor.systemTeal : NSColor(srgbRed: 0.18, green: 0.12, blue: 0.1, alpha: 1)
        let blinking = now < blinkUntil
        for side in [-1.0, 1.0] {
            let center = NSPoint(x: body.midX + CGFloat(side) * eyeGap + shift.x, y: eyeY + shift.y)
            ink.setStroke()
            ink.setFill()
            switch mood {
            case .happy:
                let arc = NSBezierPath()
                arc.appendArc(withCenter: center, radius: size * 0.05, startAngle: 20, endAngle: 160)
                arc.lineWidth = max(1, size * 0.035)
                arc.lineCapStyle = .round
                arc.stroke()
            case .sleepy:
                let line = NSBezierPath()
                line.move(to: NSPoint(x: center.x - size * 0.05, y: center.y))
                line.line(to: NSPoint(x: center.x + size * 0.05, y: center.y))
                line.lineWidth = max(1, size * 0.03)
                line.lineCapStyle = .round
                line.stroke()
            default:
                let height = blinking ? size * 0.012 : size * (mood == .surprised ? 0.12 : 0.1)
                let width = size * (mood == .surprised ? 0.085 : 0.07)
                NSBezierPath(ovalIn: NSRect(x: center.x - width / 2, y: center.y - height / 2, width: width, height: height)).fill()
                if !blinking {
                    NSColor.white.setFill()
                    NSBezierPath(ovalIn: NSRect(x: center.x - width * 0.05, y: center.y + height * 0.1,
                                                width: width * 0.4, height: width * 0.4)).fill()
                }
            }
        }

        // Mouth
        let mouth = NSBezierPath()
        let mouthCenter = NSPoint(x: body.midX + shift.x * 0.5, y: body.minY + bodyH * 0.3)
        mouth.lineWidth = max(1, size * 0.03)
        mouth.lineCapStyle = .round
        ink.setStroke()
        switch mood {
        case .happy:
            mouth.appendArc(withCenter: NSPoint(x: mouthCenter.x, y: mouthCenter.y + size * 0.03), radius: size * 0.06,
                            startAngle: 200, endAngle: 340)
            mouth.stroke()
        case .surprised:
            ink.setFill()
            NSBezierPath(ovalIn: NSRect(x: mouthCenter.x - size * 0.03, y: mouthCenter.y - size * 0.035,
                                        width: size * 0.06, height: size * 0.07)).fill()
        case .worried:
            mouth.move(to: NSPoint(x: mouthCenter.x - size * 0.05, y: mouthCenter.y))
            mouth.curve(to: NSPoint(x: mouthCenter.x + size * 0.05, y: mouthCenter.y),
                        controlPoint1: NSPoint(x: mouthCenter.x - size * 0.02, y: mouthCenter.y + size * 0.03),
                        controlPoint2: NSPoint(x: mouthCenter.x + size * 0.02, y: mouthCenter.y - size * 0.03))
            mouth.stroke()
            // a drop of sweat
            NSColor(srgbRed: 0.45, green: 0.75, blue: 1, alpha: 0.9).setFill()
            let drop = NSRect(x: body.maxX - bodyW * 0.12, y: body.maxY - bodyH * 0.35, width: size * 0.07, height: size * 0.1)
            NSBezierPath(ovalIn: drop).fill()
        case .sleepy:
            mouth.appendArc(withCenter: mouthCenter, radius: size * 0.025, startAngle: 0, endAngle: 360)
            mouth.stroke()
            if size > 30 {
                let z = "z" as NSString
                z.draw(at: NSPoint(x: body.maxX - size * 0.02, y: body.maxY),
                       withAttributes: [.font: NSFont.systemFont(ofSize: size * 0.2, weight: .bold),
                                        .foregroundColor: NSColor.white.withAlphaComponent(0.7)])
            }
        case .idle:
            mouth.appendArc(withCenter: NSPoint(x: mouthCenter.x, y: mouthCenter.y + size * 0.02), radius: size * 0.035,
                            startAngle: 210, endAngle: 330)
            mouth.stroke()
        }
    }
}

// Small marks that tell Claude and Codex apart in the notch. Drawn here, not the companies' logo files.
enum ProviderMark {
    static let claude = NSColor(srgbRed: 0.85, green: 0.47, blue: 0.34, alpha: 1)

    static func draw(_ provider: String, in rect: NSRect) {
        let center = NSPoint(x: rect.midX, y: rect.midY)
        let radius = min(rect.width, rect.height) / 2
        if provider == "Claude" {
            // A starburst of rounded rays
            let rays = NSBezierPath()
            for index in 0..<12 {
                let angle = CGFloat(index) * .pi / 6 + .pi / 12
                let outer = radius * (index % 2 == 0 ? 1 : 0.78)
                rays.move(to: NSPoint(x: center.x + cos(angle) * radius * 0.18, y: center.y + sin(angle) * radius * 0.18))
                rays.line(to: NSPoint(x: center.x + cos(angle) * outer, y: center.y + sin(angle) * outer))
            }
            rays.lineWidth = max(1.2, radius * 0.28)
            rays.lineCapStyle = .round
            claude.setStroke()
            rays.stroke()
        } else {
            // Six loops around a centre, like a knot
            NSColor.white.setStroke()
            for index in 0..<6 {
                let loop = NSBezierPath(roundedRect: NSRect(x: -radius * 0.28, y: -radius * 0.05, width: radius * 0.56, height: radius * 0.95),
                                        xRadius: radius * 0.28, yRadius: radius * 0.28)
                var transform = AffineTransform()
                transform.translate(x: center.x, y: center.y)
                transform.rotate(byDegrees: CGFloat(index) * 60)
                loop.transform(using: transform)
                loop.lineWidth = max(1, radius * 0.16)
                loop.stroke()
            }
        }
    }
}

// MARK: - iNotch: the island

struct NotchAlert {
    let symbol: String
    let tint: NSColor
    let title: String
    let detail: String
}

// Notch-shaped surface: compact around the hardware notch, wider on hover, a panel when clicked, wide for alerts.
final class NotchView: NSView {
    enum Mode { case hidden, compact, peek, expanded, alert, approval, drop }
    var mode = Mode.compact
    var notch = NSSize(width: 200, height: 32)  // the hardware cut-out (or a capsule on Macs without one)
    var hasNotch = true
    var companion: Companion?
    var leftText: String?        // shown beside Pip when peeking (no usage readings)
    var rightText: String?
    var claudeUsage: Double?     // 5-hour usage 0...1, shown with its mark when peeking
    var codexUsage: Double?
    var rightDot: NSColor?       // status dot in the right wing

    // What the right wing shows when compact.
    enum Wing: Equatable { case none, dot(NSColor), text(String), timer(String, Double), bars, download }
    var rightWing = Wing.none
    var music: NowPlaying?       // shown when peeking
    var onDragEnter: () -> Void = {}
    var onDragExit: () -> Void = {}
    var onDrop: ([URL]) -> Void = { _ in }
    var alert: NotchAlert?
    let content = NotchContent()
    let card = ApprovalCard()
    // Underdamped springs overshoot a little, which gives the island its jelly feel.
    private var width = NotchView.jelly(200)
    private var shift = NotchView.jelly(0)
    private var height = NotchView.jelly(32)
    private var radius = Spring(10)

    private static func jelly(_ value: Double) -> Spring {
        var spring = Spring(value)
        spring.stiffness = 260
        spring.damping = 29  // just under critical damping: a hint of give, no wobble
        return spring
    }
    var onClick: () -> Void = {}
    var onPip: () -> Void = {}

    // Where Pip sits in the open panel.
    private var pipRect: NSRect {
        let rect = shapeRect
        return NSRect(x: rect.minX + 16, y: rect.maxY - notch.height + 2, width: notch.height - 4, height: notch.height - 4)
    }

    override init(frame frameRect: NSRect) {
        super.init(frame: frameRect)
        addSubview(content)
        addSubview(card)
        content.alphaValue = 0
        content.isHidden = true
        card.alphaValue = 0
        card.isHidden = true
        registerForDraggedTypes([.fileURL])
    }

    // Files dragged onto the island go to the shelf.
    override func draggingEntered(_ sender: NSDraggingInfo) -> NSDragOperation {
        onDragEnter()
        return .copy
    }

    override func draggingUpdated(_ sender: NSDraggingInfo) -> NSDragOperation { .copy }

    override func draggingExited(_ sender: NSDraggingInfo?) { onDragExit() }

    override func performDragOperation(_ sender: NSDraggingInfo) -> Bool {
        let urls = sender.draggingPasteboard.readObjects(forClasses: [NSURL.self], options: [.urlReadingFileURLsOnly: true]) as? [URL] ?? []
        guard !urls.isEmpty else { return false }
        onDrop(urls)
        return true
    }

    required init?(coder: NSCoder) { fatalError() }

    private var wing: CGFloat {
        if case .timer = rightWing { return 64 }
        return 38
    }
    private var hasLeft: Bool { companion != nil }
    private var hasRight: Bool { rightWing != .none }

    // Hover width of each side: just enough for what it shows, so there is no empty black space.
    private var peekSides: (CGFloat, CGFloat) {
        let pip: CGFloat = companion == nil ? 14 : 42
        let indicator: CGFloat = rightWing == .none ? 12 : 34
        let left: CGFloat, right: CGFloat
        if let music {
            left = pip + 28 + min(150, Draw.width(music.title, font: termFont(11.5, .semibold))) + 14
            right = 12 + min(130, Draw.width(music.artist, font: termFont(11.5, .medium))) + indicator
        } else if claudeUsage != nil || codexUsage != nil {
            let font = roundedFont(13, .bold)
            func reading(_ value: Double?) -> CGFloat {
                value.map { 22 + Draw.width("\(Int(($0 * 100).rounded()))%", font: font) } ?? 0
            }
            left = pip + reading(claudeUsage) + 12
            right = 12 + reading(codexUsage) + indicator
        } else {
            left = pip + (peekLabel.map { min(170, Draw.width($0, font: termFont(11.5, .semibold))) + 14 } ?? 0)
            right = indicator
        }
        return (max(38, left), max(rightWing == .none ? 0 : 38, right))
    }

    // Without usage or music, the status text sits beside Pip.
    private var peekLabel: String? { leftText ?? rightText }

    // Size of the black shape for each mode.
    // (width, height, corner radius, horizontal shift). Each side grows on its own, so the shape can be off-centre.
    private func target(_ mode: Mode) -> (CGFloat, CGFloat, CGFloat, CGFloat) {
        let base = notch.width
        let corner: CGFloat = hasNotch ? 10 : notch.height / 2
        func sides(_ left: CGFloat, _ right: CGFloat, _ height: CGFloat, _ radius: CGFloat) -> (CGFloat, CGFloat, CGFloat, CGFloat) {
            (base + left + right, height, radius, (right - left) / 2)
        }
        switch mode {
        case .hidden: return (base, notch.height, corner, 0)
        case .compact: return sides(hasLeft ? 38 : 0, hasRight ? wing : 0, notch.height, corner)
        case .peek:
            let (left, right) = peekSides
            return sides(left, right, notch.height + 4, hasNotch ? 14 : (notch.height + 4) / 2)
        case .alert: return (base + 330, notch.height + 6, hasNotch ? 16 : (notch.height + 6) / 2, 0)
        case .expanded: return (max(520, base + 300), notch.height + 18 + content.preferredHeight, 26, 0)
        case .approval: return (max(520, base + 300), notch.height + 112, 26, 0)
        case .drop: return (max(460, base + 260), notch.height + 120, 26, 0)
        }
    }


    // Re-target the open panel's height, e.g. after switching pages.
    func refit() {
        guard mode == .expanded else { return }
        setMode(.expanded)
    }

    func setMode(_ next: Mode) {
        mode = next
        let (w, h, r, x) = target(next)
        shift.target = Double(x)
        width.target = Double(w)
        height.target = Double(h)
        radius.target = Double(r)
        content.isHidden = false
        card.isHidden = false
        Animator.shared.run(self) { [weak self] in
            guard let self else { return false }
            let moving = [self.width.step(), self.height.step(), self.radius.step(), self.shift.step()].contains(true)
            self.needsLayout = true
            self.needsDisplay = true
            if !moving, self.mode != .expanded { self.content.isHidden = true }
            if !moving, self.mode != .approval { self.card.isHidden = true }
            return moving
        }
    }

    // Snap to the current mode without animating (first show, screen change).
    func settle() {
        let (w, h, r, x) = target(mode)
        shift = NotchView.jelly(Double(x))
        width = NotchView.jelly(Double(w))
        height = NotchView.jelly(Double(h))
        radius = Spring(Double(r))
        needsLayout = true
        needsDisplay = true
    }

    // Squash and stretch: while the island grows taller it gets a bit narrower, and the other way round,
    // as if it keeps its volume.
    var shapeRect: NSRect {
        let tall = CGFloat(max(-0.03, min(0.03, height.velocity / 5000)))
        let wide = CGFloat(max(-0.02, min(0.02, width.velocity / 8000)))
        let w = CGFloat(width.value) * (1 - tall * 0.6 + wide * 0.2)
        let h = max(notch.height, CGFloat(height.value) * (1 - wide * 0.5 + tall * 0.2))
        return NSRect(x: bounds.midX + CGFloat(shift.value) - w / 2, y: bounds.maxY - h, width: w, height: h)
    }

    // Square top flush with the screen edge, small flared "ears", rounded bottom.
    var shapePath: NSBezierPath {
        let rect = shapeRect
        let r = min(CGFloat(radius.value), rect.height / 2, rect.width / 2)
        let path = NSBezierPath()
        if hasNotch {
            let ear: CGFloat = 6
            path.move(to: NSPoint(x: rect.minX - ear, y: rect.maxY))
            path.line(to: NSPoint(x: rect.maxX + ear, y: rect.maxY))
            path.curve(to: NSPoint(x: rect.maxX, y: rect.maxY - ear), controlPoint1: NSPoint(x: rect.maxX, y: rect.maxY),
                       controlPoint2: NSPoint(x: rect.maxX, y: rect.maxY))
            path.line(to: NSPoint(x: rect.maxX, y: rect.minY + r))
            path.appendArc(withCenter: NSPoint(x: rect.maxX - r, y: rect.minY + r), radius: r, startAngle: 0, endAngle: -90, clockwise: true)
            path.line(to: NSPoint(x: rect.minX + r, y: rect.minY))
            path.appendArc(withCenter: NSPoint(x: rect.minX + r, y: rect.minY + r), radius: r, startAngle: 270, endAngle: 180, clockwise: true)
            path.line(to: NSPoint(x: rect.minX, y: rect.maxY - ear))
            path.curve(to: NSPoint(x: rect.minX - ear, y: rect.maxY), controlPoint1: NSPoint(x: rect.minX, y: rect.maxY),
                       controlPoint2: NSPoint(x: rect.minX, y: rect.maxY))
            path.close()
        } else {
            path.appendRoundedRect(rect, xRadius: r, yRadius: r)
        }
        return path
    }

    // How open the panel is, 0...1, for fading its content.
    private var openness: CGFloat {
        let closed = notch.height, open = target(mode == .approval ? .approval : .expanded).1
        return min(1, max(0, (CGFloat(height.value) - closed - 40) / max(1, open - closed - 40)))
    }

    override func layout() {
        super.layout()
        let rect = shapeRect
        content.frame = NSRect(x: rect.minX + 18, y: rect.minY + 12, width: max(0, rect.width - 36),
                               height: max(0, rect.height - notch.height - 18))
        content.alphaValue = mode == .expanded ? openness * openness : 0
        card.frame = content.frame
        card.alphaValue = mode == .approval ? openness * openness : 0
    }

    override func hitTest(_ point: NSPoint) -> NSView? {
        let local = convert(point, from: superview)
        guard shapePath.contains(local) else { return nil }
        if mode == .expanded, let hit = content.hitTest(local) { return hit }
        if mode == .approval, let hit = card.hitTest(local) { return hit }
        return self
    }

    override func mouseUp(with event: NSEvent) {
        let point = convert(event.locationInWindow, from: nil)
        guard shapePath.contains(point) else { return }
        if mode == .expanded, pipRect.insetBy(dx: -6, dy: -4).contains(point) { onPip() } else { onClick() }
    }

    override func draw(_ dirtyRect: NSRect) {
        guard mode != .hidden || width.value > Double(notch.width) + 1 else { return }
        NSColor.black.setFill()
        shapePath.fill()
        let rect = shapeRect
        let band = NSRect(x: rect.minX, y: rect.maxY - notch.height, width: rect.width, height: notch.height)
        let look = window.map { convert($0.convertPoint(fromScreen: NSEvent.mouseLocation), from: nil) }

        switch mode {
        case .alert:
            guard let alert else { break }
            let iconRect = NSRect(x: band.minX + 14, y: band.midY - 11, width: 22, height: 22)
            drawSymbol(alert.symbol, in: iconRect, pointSize: 15, weight: .semibold, color: alert.tint)
            if let companion, band.width > notch.width + 200 {
                companion.draw(in: NSRect(x: band.minX + 42, y: band.minY + 3, width: band.height - 4, height: band.height - 4), look: look)
            }
            let textX = band.midX + notch.width / 2 + 12
            let maxWidth = band.maxX - 14 - textX
            if maxWidth > 40 {
                drawLine(alert.title, at: NSPoint(x: textX, y: band.midY + 1), width: maxWidth, font: termFont(12, .semibold), color: .white)
                drawLine(alert.detail, at: NSPoint(x: textX, y: band.midY - 13), width: maxWidth, font: termFont(10.5, .medium),
                         color: NSColor.white.withAlphaComponent(0.6))
            }
        case .compact, .peek, .hidden:
            let notchLeft = bounds.midX - notch.width / 2, notchRight = bounds.midX + notch.width / 2
            let leftWidth = notchLeft - band.minX, rightWidth = band.maxX - notchRight
            let wingWidth = leftWidth
            if let companion, leftWidth > 12 {
                let side = min(band.height - 4, 30)
                companion.draw(in: NSRect(x: band.minX + max(4, (min(leftWidth, 38) - side) / 2), y: band.minY + 2,
                                          width: side, height: side), look: look)
            }
            if mode == .peek, let music, wingWidth > 60 {
                // Now playing: cover and title on the left, the right wing keeps its live status
                let art = NSRect(x: band.minX + 40, y: band.midY - 10, width: 20, height: 20)
                if let artwork = music.artwork {
                    NSGraphicsContext.saveGraphicsState()
                    NSBezierPath(roundedRect: art, xRadius: 5, yRadius: 5).addClip()
                    artwork.draw(in: art)
                    NSGraphicsContext.restoreGraphicsState()
                } else {
                    drawSymbol("music.note", in: art, pointSize: 13, weight: .semibold, color: .systemPink)
                }
                drawLine(music.title, at: NSPoint(x: art.maxX + 8, y: band.midY - 7), width: notchLeft - art.maxX - 16,
                         font: termFont(11.5, .semibold), color: .white)
                drawLine(music.artist, at: NSPoint(x: notchRight + 12, y: band.midY - 7), width: rightWidth - 46,
                         font: termFont(11.5, .medium), color: NSColor.white.withAlphaComponent(0.6))
            } else if mode == .peek, claudeUsage != nil || codexUsage != nil, wingWidth > 30 {
                // Like codex-island: each provider's mark and its 5-hour percentage, one on each side.
                let font = roundedFont(13, .bold)
                if let claudeUsage {
                    let mark = NSRect(x: band.minX + 42, y: band.midY - 8, width: 16, height: 16)
                    ProviderMark.draw("Claude", in: mark)
                    Draw.text("\(Int((claudeUsage * 100).rounded()))%", font: font, color: Draw.level(claudeUsage, .white),
                              at: NSPoint(x: mark.maxX + 6, y: band.midY - 8))
                }
                if let codexUsage {
                    let mark = NSRect(x: notchRight + 12, y: band.midY - 8, width: 16, height: 16)
                    ProviderMark.draw("Codex", in: mark)
                    Draw.text("\(Int((codexUsage * 100).rounded()))%", font: font, color: Draw.level(codexUsage, .white),
                              at: NSPoint(x: mark.maxX + 6, y: band.midY - 8))
                }
            } else if mode == .peek, let label = peekLabel, wingWidth > 60 {
                drawLine(label, at: NSPoint(x: band.minX + 42, y: band.midY - 7), width: notchLeft - band.minX - 50,
                         font: termFont(11.5, .semibold), color: .white)
            }
            if rightWidth > 12 { drawRightWing(in: band, wingWidth: rightWidth) }
        case .drop:
            let zone = NSRect(x: rect.minX + 18, y: rect.minY + 14, width: rect.width - 36, height: rect.height - notch.height - 24)
            let dashed = NSBezierPath(roundedRect: zone, xRadius: 16, yRadius: 16)
            dashed.setLineDash([7, 5], count: 2, phase: 0)
            dashed.lineWidth = 2
            NSColor.white.withAlphaComponent(0.45).setStroke()
            dashed.stroke()
            drawSymbol("tray.and.arrow.down.fill", in: NSRect(x: zone.midX - 14, y: zone.midY + 2, width: 28, height: 28), pointSize: 22,
                       weight: .semibold, color: .white)
            Draw.text(L("Drop to keep on the shelf", "Loslaten om op de plank te leggen"), font: termFont(12.5, .semibold),
                      color: .white, centeredAt: NSPoint(x: zone.midX, y: zone.midY - 16))
            if let companion {
                companion.draw(in: NSRect(x: band.minX + 16, y: band.minY + 2, width: band.height - 4, height: band.height - 4), look: look)
            }
        case .expanded, .approval:
            if let companion {
                companion.draw(in: NSRect(x: band.minX + 16, y: band.minY + 2, width: band.height - 4, height: band.height - 4), look: look)
            }
            if mode == .approval {
                let dot = NSRect(x: band.maxX - 26, y: band.midY - 5, width: 10, height: 10)
                NSColor.systemOrange.setFill()
                NSBezierPath(ovalIn: dot).fill()
            }
        }
    }

    private func drawLine(_ text: String, at point: NSPoint, width: CGFloat, font: NSFont, color: NSColor) {
        let attrs: [NSAttributedString.Key: Any] = [.font: font, .foregroundColor: color]
        (text as NSString).draw(with: NSRect(x: point.x, y: point.y, width: width, height: font.pointSize + 4),
                                options: [.usesLineFragmentOrigin, .truncatesLastVisibleLine], attributes: attrs)
    }

    // The right wing: a status dot, a timer, music bars, a download arrow or a usage figure.
    private func drawRightWing(in band: NSRect, wingWidth: CGFloat) {
        let width = min(wingWidth, wing)
        let center = NSPoint(x: band.maxX - width / 2, y: band.midY)
        let t = Date().timeIntervalSinceReferenceDate
        switch rightWing {
        case .none:
            break
        case .dot(let color):
            color.setFill()
            NSBezierPath(ovalIn: NSRect(x: center.x - 4, y: center.y - 4, width: 8, height: 8)).fill()
        case .text(let text):
            guard mode == .compact else { break }
            let font = roundedFont(11, .bold)
            Draw.text(text, font: font, color: .white, at: NSPoint(x: center.x - Draw.width(text, font: font) / 2, y: center.y - 7))
        case .timer(let text, let fraction):
            let ring = NSPoint(x: band.maxX - width + 14, y: center.y)
            Draw.ring(center: ring, radius: 7, width: 2.5, fraction: fraction, tint: .systemOrange)
            Draw.text(text, font: roundedFont(11.5, .bold), color: .systemOrange, at: NSPoint(x: ring.x + 12, y: center.y - 7.5))
        case .bars:
            // A small equaliser
            NSColor.systemPink.setFill()
            for index in 0..<4 {
                let height = 4 + CGFloat(abs(sin(t * (5 + Double(index) * 1.7) + Double(index)))) * 10
                let bar = NSRect(x: center.x - 9 + CGFloat(index) * 5, y: center.y - height / 2, width: 3, height: height)
                NSBezierPath(roundedRect: bar, xRadius: 1.5, yRadius: 1.5).fill()
            }
        case .download:
            let pulse = 0.6 + 0.4 * abs(sin(t * 3))
            drawSymbol("arrow.down.circle", in: NSRect(x: center.x - 8, y: center.y - 8, width: 16, height: 16), pointSize: 13,
                       weight: .semibold, color: NSColor.systemBlue.withAlphaComponent(CGFloat(pulse)))
        }
    }
}

// The open panel: Agents, Limits and Prompter pages.
final class NotchContent: NSView {
    override var isFlipped: Bool { true }
    let tabs = ModeBar(titles: [L("Now", "Nu"), L("Agents", "Agents"), L("Limits", "Limieten"), L("Shelf", "Plank"),
                                L("Prompter", "Prompter")])
    let now = NowPage()
    let agents = AgentsPage()
    let usage = UsagePage()
    let shelf = ShelfPage()
    let prompter = PrompterPage()
    private(set) var page = 0
    var onPage: () -> Void = {}

    // Height of the open panel's content for the current page.
    var preferredHeight: CGFloat {
        switch page {
        case 0: return 44 + now.preferredHeight
        case 1: return 44 + max(100, CGFloat(agents.count) * 46 + 4) + 36
        case 2: return 44 + 256
        case 3: return 44 + shelf.preferredHeight
        default: return 44 + 162
        }
    }

    override init(frame frameRect: NSRect) {
        super.init(frame: frameRect)
        tabs.onSelect = { [weak self] in self?.show($0) }
        for view in [tabs, now, agents, usage, shelf, prompter] as [NSView] { addSubview(view) }
        show(0)
    }

    required init?(coder: NSCoder) { fatalError() }

    // Clicks on empty parts of the open panel stay here instead of closing it.
    override func mouseDown(with event: NSEvent) {}
    override func mouseUp(with event: NSEvent) {}

    func show(_ index: Int) {
        page = index
        for (number, view) in pages.enumerated() { view.isHidden = number != index }
        onPage()
    }

    override func layout() {
        super.layout()
        tabs.frame = NSRect(x: -Metrics.inset + 2, y: 0, width: bounds.width + Metrics.inset * 2 - 4, height: 36)
        let page = NSRect(x: 0, y: 44, width: bounds.width, height: max(0, bounds.height - 44))
        for view in pages { view.frame = page }
    }

    private var pages: [NSView] { [now, agents, usage, shelf, prompter] }
}

final class AgentsPage: NSView {
    override var isFlipped: Bool { true }
    var onHook: () -> Void = {}
    private lazy var hookButton = QuietButton("") { [weak self] in self?.onHook() }
    private let hookLabel = makeLabel("", size: 10.5, weight: .regular, color: NSColor.white.withAlphaComponent(0.5))
    private var sessions: [AgentSession] = []
    var count: Int { sessions.count }
    private let empty = makeLabel("", size: 12, weight: .medium, color: NSColor.white.withAlphaComponent(0.55))

    override init(frame frameRect: NSRect) {
        super.init(frame: frameRect)
        empty.alignment = .center
        empty.stringValue = L("No Claude Code or Codex sessions in the last 30 minutes",
                              "Geen Claude Code- of Codex-sessies in het afgelopen halfuur")
        addSubview(empty)
        addSubview(hookButton)
        addSubview(hookLabel)
    }

    func showHook(installed: Bool) {
        hookButton.title.stringValue = installed ? L("Turn off", "Uitzetten") : L("Approve from the notch", "Goedkeuren vanuit de notch")
        hookLabel.stringValue = installed
            ? L("Claude Code asks for permission here", "Claude Code vraagt hier om toestemming")
            : L("Allow or deny Claude Code requests here", "Sta Claude Code-verzoeken hier toe of weiger ze")
        needsLayout = true
    }

    required init?(coder: NSCoder) { fatalError() }

    func show(_ sessions: [AgentSession]) {
        self.sessions = Array(sessions.prefix(5))
        empty.isHidden = !sessions.isEmpty
        needsDisplay = true
    }

    override func layout() {
        super.layout()
        empty.frame = NSRect(x: 0, y: 36, width: bounds.width, height: 18)
        let width = hookButton.title.intrinsicContentSize.width + 28
        hookButton.frame = NSRect(x: 0, y: bounds.height - 28, width: width, height: 26)
        hookLabel.frame = NSRect(x: width + 10, y: bounds.height - 21, width: max(0, bounds.width - width - 12), height: 14)
    }

    override func draw(_ dirtyRect: NSRect) {
        var y: CGFloat = 0
        for session in sessions {
            let row = NSRect(x: 0, y: y, width: bounds.width, height: 44)
            let card = NSBezierPath(roundedRect: row.insetBy(dx: 0, dy: 2), xRadius: 12, yRadius: 12)
            NSColor.white.withAlphaComponent(0.07).setFill()
            card.fill()
            let codex = session.agent == "Codex"
            let tile = NSRect(x: row.minX + 10, y: row.midY - 13, width: 26, height: 26)
            let tint: NSColor = codex ? NSColor(white: 0.85, alpha: 1) : NSColor(srgbRed: 0.85, green: 0.47, blue: 0.34, alpha: 1)
            tint.withAlphaComponent(0.2).setFill()
            NSBezierPath(roundedRect: tile, xRadius: 7, yRadius: 7).fill()
            drawSymbol(codex ? "chevron.left.forwardslash.chevron.right" : "sparkle", in: tile, pointSize: 12, weight: .bold, color: tint)

            let (label, color): (String, NSColor) = {
                switch session.state {
                case .working: return (L("Working", "Bezig"), .systemBlue)
                case .waiting: return (L("Waiting", "Wacht"), .systemOrange)
                case .done: return (L("Done", "Klaar"), .systemGreen)
                }
            }()
            let pillFont = termFont(10.5, .semibold)
            let pillWidth = Draw.width(label, font: pillFont) + 22
            let pill = NSRect(x: row.maxX - 10 - pillWidth, y: row.midY - 10, width: pillWidth, height: 20)
            color.withAlphaComponent(0.22).setFill()
            NSBezierPath(roundedRect: pill, xRadius: 10, yRadius: 10).fill()
            color.setFill()
            NSBezierPath(ovalIn: NSRect(x: pill.minX + 8, y: pill.midY - 3, width: 6, height: 6)).fill()
            Draw.text(label, font: pillFont, color: color, at: NSPoint(x: pill.minX + 17, y: pill.midY - 7))

            let textX = tile.maxX + 10
            let textWidth = pill.minX - 8 - textX
            let title = session.project + "  ·  " + session.agent
            let titleAttrs: [NSAttributedString.Key: Any] = [.font: termFont(12, .semibold), .foregroundColor: NSColor.white]
            (title as NSString).draw(with: NSRect(x: textX, y: row.minY + 7, width: textWidth, height: 16),
                                     options: [.usesLineFragmentOrigin, .truncatesLastVisibleLine], attributes: titleAttrs)
            let detailAttrs: [NSAttributedString.Key: Any] = [.font: termFont(10.5, .regular),
                                                              .foregroundColor: NSColor.white.withAlphaComponent(0.6)]
            (session.action as NSString).draw(with: NSRect(x: textX, y: row.minY + 23, width: textWidth, height: 14),
                                              options: [.usesLineFragmentOrigin, .truncatesLastVisibleLine], attributes: detailAttrs)
            y += 46
        }
    }
}

final class UsagePage: NSView {
    override var isFlipped: Bool { true }
    var onConnectClaude: () -> Void = {}
    var onRefresh: () -> Void = {}
    private var providers: [ProviderUsage] = []
    private var claudeConnected = false
    private lazy var connect = AccentButton { [weak self] in self?.onConnectClaude() }
    private lazy var refresh = IconButton(symbol: "arrow.clockwise", help: L("Refresh", "Vernieuwen")) { [weak self] in self?.onRefresh() }
    private let footer = makeLabel("", size: 10.5, weight: .regular, color: NSColor.white.withAlphaComponent(0.5))

    override init(frame frameRect: NSRect) {
        super.init(frame: frameRect)
        connect.title = L("Connect Claude", "Claude koppelen")
        for view in [connect, refresh, footer] as [NSView] { addSubview(view) }
    }

    required init?(coder: NSCoder) { fatalError() }

    func show(_ providers: [ProviderUsage], claudeConnected: Bool, updated: Date?) {
        self.providers = providers
        self.claudeConnected = claudeConnected
        connect.isHidden = claudeConnected
        footer.stringValue = claudeConnected
            ? updated.map { L("Updated", "Bijgewerkt") + " " + NotchFormat.ago($0) } ?? L("Not loaded yet", "Nog niet geladen")
            : L("Claude limits need your Claude Code sign-in from the Keychain", "Claude-limieten gebruiken je Claude Code-inlog uit de sleutelhanger")
        needsLayout = true
        needsDisplay = true
    }

    override func layout() {
        super.layout()
        let width = connect.preferredWidth
        connect.frame = NSRect(x: bounds.width / 4 - width / 2, y: 70, width: width, height: 28)
        refresh.frame = NSRect(x: bounds.width - 26, y: bounds.height - 26, width: 26, height: 24)
        footer.frame = NSRect(x: 2, y: bounds.height - 22, width: bounds.width - 34, height: 14)
    }

    override func draw(_ dirtyRect: NSRect) {
        let column = (bounds.width - 12) / 2
        for (index, name) in ["Claude", "Codex"].enumerated() {
            let x = CGFloat(index) * (column + 12)
            let box = NSRect(x: x, y: 0, width: column, height: bounds.height - 34)
            NSColor.white.withAlphaComponent(0.07).setFill()
            NSBezierPath(roundedRect: box, xRadius: 14, yRadius: 14).fill()
            let provider = providers.first { $0.name == name }
            Draw.text(name, font: termFont(13, .semibold), color: .white, at: NSPoint(x: box.minX + 14, y: box.minY + 12))
            if let plan = provider?.plan {
                let font = termFont(10.5, .semibold)
                let w = Draw.width(plan, font: font) + 14
                let pill = NSRect(x: box.maxX - 14 - w, y: box.minY + 12, width: w, height: 18)
                NSColor.white.withAlphaComponent(0.12).setFill()
                NSBezierPath(roundedRect: pill, xRadius: 9, yRadius: 9).fill()
                Draw.text(plan, font: font, color: NSColor.white.withAlphaComponent(0.8), at: NSPoint(x: pill.minX + 7, y: pill.minY + 2))
            }
            if name == "Claude" && !claudeConnected { continue }
            var y = box.minY + 44
            let windows: [(String, QuotaWindow?)] = [(L("5 hours", "5 uur"), provider?.fiveHour), (L("Week", "Week"), provider?.weekly)]
            if windows.allSatisfy({ $0.1 == nil }) {
                let note = provider?.note ?? L("Loading…", "Laden…")
                let attrs: [NSAttributedString.Key: Any] = [.font: termFont(11, .medium), .foregroundColor: NSColor.white.withAlphaComponent(0.6)]
                (note as NSString).draw(with: NSRect(x: box.minX + 14, y: y, width: box.width - 28, height: 60),
                                        options: [.usesLineFragmentOrigin], attributes: attrs)
                continue
            }
            for (label, window) in windows {
                guard let window else { continue }
                Draw.text(label, font: termFont(11, .medium), color: NSColor.white.withAlphaComponent(0.6), at: NSPoint(x: box.minX + 14, y: y))
                let percent = "\(Int((window.used * 100).rounded()))%"
                let font = roundedFont(13, .bold)
                Draw.text(percent, font: font, color: .white, at: NSPoint(x: box.maxX - 14 - Draw.width(percent, font: font), y: y - 1))
                let bar = NSRect(x: box.minX + 14, y: y + 20, width: box.width - 28, height: 6)
                NSColor.white.withAlphaComponent(0.12).setFill()
                NSBezierPath(roundedRect: bar, xRadius: 3, yRadius: 3).fill()
                var filled = bar
                filled.size.width = max(bar.height, bar.width * CGFloat(min(1, window.used)))
                Draw.level(window.used, name == "Claude" ? NSColor(srgbRed: 0.85, green: 0.47, blue: 0.34, alpha: 1) : .systemTeal).setFill()
                NSBezierPath(roundedRect: filled, xRadius: 3, yRadius: 3).fill()
                if let reset = window.resetsAt {
                    Draw.text(L("resets", "reset") + " " + NotchFormat.until(reset), font: termFont(10, .regular),
                              color: NSColor.white.withAlphaComponent(0.5), at: NSPoint(x: box.minX + 14, y: y + 30))
                }
                y += 56
            }
            if let asOf = provider?.asOf, name == "Codex" {
                Draw.text(L("as of", "stand van") + " " + NotchFormat.ago(asOf), font: termFont(10, .regular),
                          color: NSColor.white.withAlphaComponent(0.4), at: NSPoint(x: box.minX + 14, y: box.maxY - 20))
            }
        }
    }
}

// Type or paste the script right here; it is saved as you type.
final class PrompterPage: NSView, NSTextViewDelegate {
    override var isFlipped: Bool { true }
    var onText: (String) -> Void = { _ in }
    var onPlay: () -> Void = {}
    var onReset: () -> Void = {}
    var onSpeed: (Int) -> Void = { _ in }
    var onSize: (Int) -> Void = { _ in }
    private let scroll = NSScrollView()
    private let editor = NSTextView()
    private let placeholder = makeLabel(L("Type or paste your script here…", "Typ of plak hier je tekst…"), size: 13,
                                        weight: .regular, color: NSColor.white.withAlphaComponent(0.35))
    private let info = makeLabel("", size: 11, weight: .medium, color: NSColor.white.withAlphaComponent(0.55))
    private lazy var play = AccentButton { [weak self] in self?.onPlay() }
    private lazy var reset = IconButton(symbol: "backward.end.fill", help: L("Back to the start", "Terug naar begin")) { [weak self] in self?.onReset() }
    private lazy var slower = IconButton(symbol: "tortoise.fill", help: L("Slower", "Langzamer")) { [weak self] in self?.onSpeed(-1) }
    private lazy var faster = IconButton(symbol: "hare.fill", help: L("Faster", "Sneller")) { [weak self] in self?.onSpeed(1) }
    private lazy var smaller = IconButton(symbol: "textformat.size.smaller", help: L("Smaller text", "Kleinere tekst")) { [weak self] in self?.onSize(-1) }
    private lazy var bigger = IconButton(symbol: "textformat.size.larger", help: L("Bigger text", "Grotere tekst")) { [weak self] in self?.onSize(1) }

    override init(frame frameRect: NSRect) {
        super.init(frame: frameRect)
        editor.isRichText = false
        editor.allowsUndo = true
        editor.font = NSFont.systemFont(ofSize: 13)
        editor.textColor = .white
        editor.insertionPointColor = .white
        editor.drawsBackground = false
        editor.textContainerInset = NSSize(width: 8, height: 8)
        editor.isAutomaticQuoteSubstitutionEnabled = false
        editor.delegate = self
        editor.autoresizingMask = [.width]
        scroll.documentView = editor
        scroll.drawsBackground = false
        scroll.hasVerticalScroller = true
        scroll.autohidesScrollers = true
        scroll.scrollerStyle = .overlay
        scroll.borderType = .noBorder
        scroll.wantsLayer = true
        scroll.layer?.cornerRadius = 12
        scroll.layer?.backgroundColor = NSColor.white.withAlphaComponent(0.07).cgColor
        for view in [scroll, placeholder, info, play, reset, slower, faster, smaller, bigger] as [NSView] { addSubview(view) }
    }

    required init?(coder: NSCoder) { fatalError() }

    func textDidChange(_ notification: Notification) {
        placeholder.isHidden = !editor.string.isEmpty
        onText(editor.string)
    }

    func show(text: String, running: Bool, speed: Int, size: Int) {
        if editor.string != text, window?.firstResponder !== editor { editor.string = text }
        placeholder.isHidden = !text.isEmpty
        info.stringValue = L("Speed", "Snelheid") + " \(speed)  ·  " + L("Size", "Grootte") + " \(size)  ·  "
            + L("hidden from screen recordings", "onzichtbaar in schermopnames")
        play.title = running ? L("Stop", "Stop") : L("Start", "Start")
        play.enabled = running || !text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
        needsLayout = true
    }

    override func layout() {
        super.layout()
        scroll.frame = NSRect(x: 0, y: 0, width: bounds.width, height: 96)
        editor.frame.size.width = scroll.contentSize.width
        placeholder.frame = NSRect(x: 13, y: 9, width: bounds.width - 26, height: 18)
        info.frame = NSRect(x: 2, y: 104, width: bounds.width - 4, height: 14)
        let y: CGFloat = 126
        let playWidth = max(84, play.preferredWidth)
        play.frame = NSRect(x: 0, y: y, width: playWidth, height: 30)
        var x = bounds.width - 30
        for button in [bigger, smaller, faster, slower, reset] {
            button.frame = NSRect(x: x, y: y + 3, width: 28, height: 24)
            x -= 32
        }
    }
}

enum NotchFormat {
    static func ago(_ date: Date) -> String {
        let seconds = Int(Date().timeIntervalSince(date))
        if seconds < 60 { return L("just now", "zojuist") }
        if seconds < 3600 { return "\(seconds / 60)m " + L("ago", "geleden") }
        if seconds < 86_400 { return "\(seconds / 3600)\(L("h", "u")) " + L("ago", "geleden") }
        return "\(seconds / 86_400)d " + L("ago", "geleden")
    }

    static func until(_ date: Date) -> String {
        let seconds = max(0, Int(date.timeIntervalSinceNow))
        if seconds < 3600 { return L("in", "over") + " \(seconds / 60)m" }
        if seconds < 86_400 { return L("in", "over") + " \(seconds / 3600)\(L("h", "u")) \((seconds % 3600) / 60)m" }
        return L("in", "over") + " \(seconds / 86_400)d \((seconds % 86_400) / 3600)\(L("h", "u"))"
    }
}

// The "Now" page: what's playing, a timer, and downloads in progress.
final class NowPage: NSView {
    override var isFlipped: Bool { true }
    var onMusic: (String) -> Void = { _ in }       // "playpause", "next track", "previous track"
    var onTimer: (Double) -> Void = { _ in }       // start with minutes
    var onTimerPause: () -> Void = {}
    var onTimerStop: () -> Void = {}
    var music: NowPlaying?
    var timer: NotchTimer?
    var downloads: [DownloadItem] = []
    private lazy var previous = IconButton(symbol: "backward.fill", help: L("Previous", "Vorige")) { [weak self] in self?.onMusic("previous track") }
    private lazy var play = IconButton(symbol: "play.fill", help: L("Play/pause", "Afspelen/pauze")) { [weak self] in self?.onMusic("playpause") }
    private lazy var next = IconButton(symbol: "forward.fill", help: L("Next", "Volgende")) { [weak self] in self?.onMusic("next track") }
    private lazy var pause = IconButton(symbol: "pause.fill", help: L("Pause/resume", "Pauze/verder")) { [weak self] in self?.onTimerPause() }
    private lazy var stop = IconButton(symbol: "xmark", help: L("Stop timer", "Timer stoppen")) { [weak self] in self?.onTimerStop() }
    private var presets: [SortChip] = []
    private static let minutes: [Double] = [1, 5, 10, 15, 25, 45]

    static let musicHeight: CGFloat = 96
    static let timerHeight: CGFloat = 66

    override init(frame frameRect: NSRect) {
        super.init(frame: frameRect)
        for view in [previous, play, next, pause, stop] as [NSView] { addSubview(view) }
        for minutes in NowPage.minutes {
            let chip = SortChip("\(Int(minutes))m")
            chip.onClick = { [weak self] in self?.onTimer(minutes) }
            presets.append(chip)
            addSubview(chip)
        }
    }

    required init?(coder: NSCoder) { fatalError() }

    override func mouseDown(with event: NSEvent) {}
    override func mouseUp(with event: NSEvent) {}

    var preferredHeight: CGFloat {
        NowPage.musicHeight + 8 + NowPage.timerHeight + (downloads.isEmpty ? 0 : 8 + CGFloat(downloads.count) * 34)
    }

    func refresh() {
        let hasMusic = music != nil
        for button in [previous, play, next] { button.isHidden = !hasMusic }
        play.symbol = music?.playing == true ? "pause.fill" : "play.fill"
        let running = timer?.running == true
        pause.isHidden = !running
        stop.isHidden = !running
        pause.symbol = timer?.paused != nil ? "play.fill" : "pause.fill"
        presets.forEach { $0.isHidden = running }
        needsLayout = true
        needsDisplay = true
    }

    override func layout() {
        super.layout()
        let musicBox = NSRect(x: 0, y: 0, width: bounds.width, height: NowPage.musicHeight)
        var x = musicBox.maxX - 14 - 28
        for button in [next, play, previous] {
            button.frame = NSRect(x: x, y: musicBox.midY - 14, width: 28, height: 28)
            x -= 32
        }
        let timerBox = NSRect(x: 0, y: musicBox.maxY + 8, width: bounds.width, height: NowPage.timerHeight)
        stop.frame = NSRect(x: timerBox.maxX - 14 - 28, y: timerBox.midY - 14, width: 28, height: 28)
        pause.frame = NSRect(x: stop.frame.minX - 32, y: timerBox.midY - 14, width: 28, height: 28)
        var chipX = timerBox.maxX - 12
        for chip in presets.reversed() {
            let width: CGFloat = 44
            chipX -= width
            chip.frame = NSRect(x: chipX, y: timerBox.midY - 12, width: width, height: 24)
            chipX -= 4
        }
    }

    override func draw(_ dirtyRect: NSRect) {
        let dim = NSColor.white.withAlphaComponent(0.55)
        // Music
        let musicBox = NSRect(x: 0, y: 0, width: bounds.width, height: NowPage.musicHeight)
        NSColor.white.withAlphaComponent(0.07).setFill()
        NSBezierPath(roundedRect: musicBox, xRadius: 16, yRadius: 16).fill()
        let art = NSRect(x: musicBox.minX + 12, y: musicBox.minY + 12, width: 72, height: 72)
        if let music {
            if let artwork = music.artwork {
                NSGraphicsContext.saveGraphicsState()
                NSBezierPath(roundedRect: art, xRadius: 12, yRadius: 12).addClip()
                artwork.draw(in: art, from: .zero, operation: .sourceOver, fraction: 1, respectFlipped: true, hints: nil)
                NSGraphicsContext.restoreGraphicsState()
            } else {
                Draw.tile("music.note", in: art, color: .systemPink)
            }
            let textX = art.maxX + 14
            let textWidth = previous.frame.minX - 10 - textX
            drawLine(music.title, at: NSPoint(x: textX, y: musicBox.minY + 16), width: textWidth, font: termFont(13.5, .semibold), color: .white)
            drawLine(music.artist + "  ·  " + music.app, at: NSPoint(x: textX, y: musicBox.minY + 36), width: textWidth,
                     font: termFont(11.5, .regular), color: dim)
            if music.duration > 0 {
                let bar = NSRect(x: textX, y: musicBox.minY + 66, width: textWidth, height: 4)
                NSColor.white.withAlphaComponent(0.15).setFill()
                NSBezierPath(roundedRect: bar, xRadius: 2, yRadius: 2).fill()
                var filled = bar
                filled.size.width = bar.width * CGFloat(music.elapsed / music.duration)
                NSColor.white.setFill()
                NSBezierPath(roundedRect: filled, xRadius: 2, yRadius: 2).fill()
                let times = NotchTimer.text(music.elapsed) + " / " + NotchTimer.text(music.duration)
                Draw.text(times, font: digitFont(10, .medium), color: dim, at: NSPoint(x: textX, y: musicBox.minY + 74))
            }
        } else {
            Draw.tile("music.note", in: art, color: NSColor.white.withAlphaComponent(0.4))
            drawLine(L("Nothing playing", "Er speelt niets"), at: NSPoint(x: art.maxX + 14, y: musicBox.minY + 26),
                     width: musicBox.width - art.width - 40, font: termFont(13, .semibold), color: NSColor.white.withAlphaComponent(0.7))
            drawLine(L("Play something in Music or Spotify", "Speel iets af in Music of Spotify"), at: NSPoint(x: art.maxX + 14, y: musicBox.minY + 46),
                     width: musicBox.width - art.width - 40, font: termFont(11.5, .regular), color: dim)
        }

        // Timer
        let timerBox = NSRect(x: 0, y: musicBox.maxY + 8, width: bounds.width, height: NowPage.timerHeight)
        NSColor.white.withAlphaComponent(0.07).setFill()
        NSBezierPath(roundedRect: timerBox, xRadius: 16, yRadius: 16).fill()
        if let timer, timer.running {
            let center = NSPoint(x: timerBox.minX + 36, y: timerBox.midY)
            NSGraphicsContext.saveGraphicsState()
            // ring() draws for non-flipped views; flip locally around the centre
            let flip = NSAffineTransform()
            flip.translateX(by: 0, yBy: center.y * 2)
            flip.scaleX(by: 1, yBy: -1)
            flip.concat()
            Draw.ring(center: center, radius: 18, width: 5, fraction: timer.fraction, tint: .systemOrange)
            NSGraphicsContext.restoreGraphicsState()
            Draw.text(NotchTimer.text(timer.remaining), font: roundedFont(26, .bold), color: .white,
                      at: NSPoint(x: timerBox.minX + 68, y: timerBox.midY - 17))
            if timer.paused != nil {
                Draw.text(L("paused", "gepauzeerd"), font: termFont(11, .medium), color: dim,
                          at: NSPoint(x: timerBox.minX + 170, y: timerBox.midY - 7))
            }
        } else {
            drawSymbol("timer", in: NSRect(x: timerBox.minX + 14, y: timerBox.midY - 11, width: 22, height: 22), pointSize: 16,
                       weight: .semibold, color: .systemOrange)
            Draw.text(L("Timer", "Timer"), font: termFont(13, .semibold), color: .white, at: NSPoint(x: timerBox.minX + 44, y: timerBox.midY - 9))
        }

        // Downloads
        var y = timerBox.maxY + 8
        for item in downloads {
            let row = NSRect(x: 0, y: y, width: bounds.width, height: 30)
            NSColor.white.withAlphaComponent(0.07).setFill()
            NSBezierPath(roundedRect: row, xRadius: 10, yRadius: 10).fill()
            Draw.tile("arrow.down", in: NSRect(x: row.minX + 7, y: row.minY + 4, width: 22, height: 22), color: .systemBlue)
            drawLine(item.name, at: NSPoint(x: row.minX + 34, y: row.minY + 7), width: row.width - 130, font: termFont(12, .medium), color: .white)
            let size = Scanner.formatBytes(item.bytes)
            let font = digitFont(11, .medium)
            Draw.text(size, font: font, color: dim, at: NSPoint(x: row.maxX - 12 - Draw.width(size, font: font), y: row.minY + 8))
            y += 34
        }
    }

    private func drawLine(_ text: String, at point: NSPoint, width: CGFloat, font: NSFont, color: NSColor) {
        let attrs: [NSAttributedString.Key: Any] = [.font: font, .foregroundColor: color]
        (text as NSString).draw(with: NSRect(x: point.x, y: point.y, width: max(10, width), height: font.pointSize + 5),
                                options: [.usesLineFragmentOrigin, .truncatesLastVisibleLine], attributes: attrs)
    }
}

// One file on the shelf; drag it out to drop it anywhere, click to show it in Finder.
final class ShelfTile: HoverView, NSDraggingSource {
    let url: URL
    var onRemove: () -> Void = {}
    var onReveal: () -> Void = {}
    private let icon: NSImage
    private let name: NSTextField
    private lazy var remove = IconButton(symbol: "xmark.circle.fill", help: L("Remove from the shelf", "Van de plank halen")) { [weak self] in
        self?.onRemove()
    }
    private var downAt: NSPoint?

    init(url: URL) {
        self.url = url
        icon = NSWorkspace.shared.icon(forFile: url.path)
        name = makeLabel(url.lastPathComponent, size: 10.5, weight: .medium, color: .white)
        name.alignment = .center
        name.lineBreakMode = .byTruncatingMiddle
        name.cell?.lineBreakMode = .byTruncatingMiddle
        super.init(frame: .zero)
        toolTip = url.path
        addSubview(name)
        addSubview(remove)
        remove.isHidden = true
    }

    required init?(coder: NSCoder) { fatalError() }

    override var isFlipped: Bool { true }

    override func refresh() {
        super.refresh()
        remove.isHidden = !hovered
    }

    override func hitTest(_ point: NSPoint) -> NSView? {
        let local = convert(point, from: superview)
        guard bounds.contains(local) else { return nil }
        if !remove.isHidden, remove.frame.contains(local) { return remove }
        return self
    }

    override func mouseDown(with event: NSEvent) {
        downAt = event.locationInWindow
        super.mouseDown(with: event)
    }

    override func mouseUp(with event: NSEvent) {
        defer { downAt = nil }
        guard downAt != nil else { return }
        super.mouseUp(with: event)
    }

    override func mouseDragged(with event: NSEvent) {
        guard let start = downAt, hypot(event.locationInWindow.x - start.x, event.locationInWindow.y - start.y) > 4 else { return }
        downAt = nil
        pressed = false
        let item = NSDraggingItem(pasteboardWriter: url as NSURL)
        item.setDraggingFrame(NSRect(x: (bounds.width - 44) / 2, y: 6, width: 44, height: 44), contents: icon)
        beginDraggingSession(with: [item], event: event, source: self)
    }

    func draggingSession(_ session: NSDraggingSession, sourceOperationMaskFor context: NSDraggingContext) -> NSDragOperation {
        context == .outsideApplication ? [.copy, .move, .link, .generic] : []
    }

    override func layout() {
        super.layout()
        name.frame = NSRect(x: 2, y: 54, width: bounds.width - 4, height: 14)
        remove.frame = NSRect(x: bounds.width - 26, y: 0, width: 24, height: 22)
    }

    override func draw(_ dirtyRect: NSRect) {
        if hovered {
            NSColor.white.withAlphaComponent(0.08).setFill()
            NSBezierPath(roundedRect: bounds, xRadius: 10, yRadius: 10).fill()
        }
        icon.draw(in: NSRect(x: (bounds.width - 44) / 2, y: 6, width: 44, height: 44), from: .zero, operation: .sourceOver,
                  fraction: 1, respectFlipped: true, hints: nil)
    }
}

final class ShelfPage: NSView {
    override var isFlipped: Bool { true }
    var onAirDrop: () -> Void = {}
    var onClear: () -> Void = {}
    var onRemove: (URL) -> Void = { _ in }
    var onReveal: (URL) -> Void = { _ in }
    private var tiles: [ShelfTile] = []
    private let title = makeLabel("", size: 11, weight: .semibold, color: NSColor.white.withAlphaComponent(0.6))
    private let empty = makeLabel(L("Drag files onto the notch to keep them here, then drag them out wherever you need them",
                                    "Sleep bestanden naar de notch om ze hier te bewaren en sleep ze er later uit"),
                                  size: 12, weight: .medium, color: NSColor.white.withAlphaComponent(0.5))
    private lazy var airdrop = QuietButton(L("AirDrop", "AirDrop")) { [weak self] in self?.onAirDrop() }
    private lazy var clear = QuietButton(L("Clear", "Leegmaken")) { [weak self] in self?.onClear() }
    private static let columns = 5
    private static let tileHeight: CGFloat = 74

    override init(frame frameRect: NSRect) {
        super.init(frame: frameRect)
        empty.alignment = .center
        empty.maximumNumberOfLines = 2
        empty.cell?.usesSingleLineMode = false
        empty.cell?.wraps = true
        for view in [title, empty, airdrop, clear] as [NSView] { addSubview(view) }
    }

    required init?(coder: NSCoder) { fatalError() }

    override func mouseDown(with event: NSEvent) {}
    override func mouseUp(with event: NSEvent) {}

    var preferredHeight: CGFloat {
        tiles.isEmpty ? 90 : 36 + CGFloat((tiles.count + ShelfPage.columns - 1) / ShelfPage.columns) * (ShelfPage.tileHeight + 6)
    }

    func show(_ urls: [URL]) {
        tiles.forEach { $0.removeFromSuperview() }
        tiles = urls.map { url in
            let tile = ShelfTile(url: url)
            tile.onRemove = { [weak self] in self?.onRemove(url) }
            tile.onClick = { [weak self] in self?.onReveal(url) }
            return tile
        }
        tiles.forEach(addSubview)
        title.stringValue = urls.count == 1 ? L("1 file", "1 bestand") : L("\(urls.count) files", "\(urls.count) bestanden")
        for view in [title, airdrop, clear] as [NSView] { view.isHidden = urls.isEmpty }
        empty.isHidden = !urls.isEmpty
        needsLayout = true
    }

    override func layout() {
        super.layout()
        empty.frame = NSRect(x: 20, y: 22, width: bounds.width - 40, height: 40)
        title.frame = NSRect(x: 2, y: 6, width: 160, height: 14)
        clear.frame = NSRect(x: bounds.width - 96, y: 0, width: 96, height: 26)
        airdrop.frame = NSRect(x: clear.frame.minX - 104, y: 0, width: 96, height: 26)
        let width = bounds.width / CGFloat(ShelfPage.columns)
        for (index, tile) in tiles.enumerated() {
            let row = index / ShelfPage.columns, column = index % ShelfPage.columns
            tile.frame = NSRect(x: CGFloat(column) * width + 2, y: 36 + CGFloat(row) * (ShelfPage.tileHeight + 6),
                                width: width - 4, height: ShelfPage.tileHeight)
        }
    }
}

// MARK: - iNotch: teleprompter

final class PrompterView: NSView {
    var text = ""
    var fontSize: CGFloat = 24
    var offset: CGFloat = 0
    var onClick: () -> Void = {}

    override var isFlipped: Bool { true }

    var textHeight: CGFloat {
        attributed.boundingRect(with: NSSize(width: bounds.width - 48, height: .greatestFiniteMagnitude),
                                options: [.usesLineFragmentOrigin]).height
    }

    private var attributed: NSAttributedString {
        let style = NSMutableParagraphStyle()
        style.alignment = .center
        style.lineSpacing = fontSize * 0.25
        return NSAttributedString(string: text, attributes: [
            .font: NSFont.systemFont(ofSize: fontSize, weight: .semibold), .foregroundColor: NSColor.white, .paragraphStyle: style,
        ])
    }

    override func mouseUp(with event: NSEvent) { onClick() }

    override func scrollWheel(with event: NSEvent) {
        offset = max(-bounds.height / 2, offset - event.scrollingDeltaY)
        needsDisplay = true
    }

    override func draw(_ dirtyRect: NSRect) {
        let shape = NSBezierPath(roundedRect: bounds, xRadius: 22, yRadius: 22)
        NSColor.black.setFill()
        shape.fill()
        NSGraphicsContext.saveGraphicsState()
        shape.addClip()
        attributed.draw(with: NSRect(x: 24, y: 24 - offset, width: bounds.width - 48, height: textHeight + 20),
                        options: [.usesLineFragmentOrigin])
        // Fade the top and bottom edges
        NSGradient(starting: .black, ending: NSColor.black.withAlphaComponent(0))?.draw(in: NSRect(x: 0, y: 0, width: bounds.width, height: 26), angle: 90)
        NSGradient(starting: NSColor.black.withAlphaComponent(0), ending: .black)?
            .draw(in: NSRect(x: 0, y: bounds.height - 30, width: bounds.width, height: 30), angle: 90)
        NSGraphicsContext.restoreGraphicsState()
    }
}

// Scrolls text under the notch, like a teleprompter. Hidden from screen recordings and screenshots.
final class Prompter {
    private let defaults = UserDefaults.standard
    private var panel: NSPanel?
    private let view = PrompterView()
    private var timer: Timer?
    private(set) var running = false
    var onChange: () -> Void = {}

    var text: String {
        get { defaults.string(forKey: "prompterText") ?? "" }
        set { defaults.set(newValue, forKey: "prompterText") }
    }
    var speed: Int {
        get { max(1, defaults.integer(forKey: "prompterSpeed") == 0 ? 4 : defaults.integer(forKey: "prompterSpeed")) }
        set { defaults.set(min(10, max(1, newValue)), forKey: "prompterSpeed") }
    }
    var size: Int {
        get { defaults.integer(forKey: "prompterSize") == 0 ? 3 : defaults.integer(forKey: "prompterSize") }
        set { defaults.set(min(6, max(1, newValue)), forKey: "prompterSize") }
    }

    func toggle(below notch: NSRect, on screen: NSScreen) {
        running ? stop() : start(below: notch, on: screen)
    }

    func start(below notch: NSRect, on screen: NSScreen) {
        guard !text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { return }
        let width: CGFloat = 560, height: CGFloat = 170
        let frame = NSRect(x: notch.midX - width / 2, y: notch.minY - height - 8, width: width, height: height)
        let panel = self.panel ?? {
            let panel = NSPanel(contentRect: frame, styleMask: [.borderless, .nonactivatingPanel], backing: .buffered, defer: false)
            panel.isOpaque = false
            panel.backgroundColor = .clear
            panel.hasShadow = false
            panel.level = NSWindow.Level(rawValue: NSWindow.Level.mainMenu.rawValue + 2)
            panel.collectionBehavior = [.canJoinAllSpaces, .stationary, .fullScreenAuxiliary, .ignoresCycle]
            panel.sharingType = .none  // not captured by screen recordings or screenshots
            panel.contentView = view
            return panel
        }()
        self.panel = panel
        panel.setFrame(frame, display: true)
        view.text = text
        view.fontSize = CGFloat(14 + size * 4)
        view.offset = -20
        view.onClick = { [weak self] in self?.stop() }
        panel.orderFrontRegardless()
        running = true
        timer?.invalidate()
        timer = Timer.scheduledTimer(withTimeInterval: 1.0 / 60, repeats: true) { [weak self] _ in self?.advance() }
        RunLoop.main.add(timer!, forMode: .common)
        onChange()
    }

    func stop() {
        timer?.invalidate()
        timer = nil
        panel?.orderOut(nil)
        running = false
        onChange()
    }

    func restart() {
        view.offset = -20
        view.needsDisplay = true
    }

    private func advance() {
        view.offset += CGFloat(speed) * 0.1  // 6 points a second per speed step
        if view.offset > view.textHeight + 40 { view.offset = -view.bounds.height + 40 }
        view.needsDisplay = true
    }

    func adjust(speed delta: Int) {
        speed += delta
        onChange()
    }

    func adjust(size delta: Int) {
        size += delta
        view.fontSize = CGFloat(14 + size * 4)
        view.needsDisplay = true
        onChange()
    }
}

// MARK: - iNotch live activities: music, shelf, timer, downloads

struct NowPlaying {
    var app: String          // "Spotify" or "Music"
    var title: String
    var artist: String
    var playing: Bool
    var position: Double     // seconds, at `stamp`
    var duration: Double     // seconds, 0 when unknown
    var stamp = Date()
    var artwork: NSImage?

    // Where playback is now, moving on while it plays.
    var elapsed: Double {
        let now = playing ? position + Date().timeIntervalSince(stamp) : position
        return duration > 0 ? min(duration, max(0, now)) : max(0, now)
    }
}

// Spotify and Music announce every track change and play/pause themselves; listening needs no permission.
// Controls, artwork and the exact position use Apple events, which macOS asks you to allow once per app.
final class MusicWatcher {
    static let apps = [("Spotify", "com.spotify.client"), ("Music", "com.apple.Music")]
    var onChange: (NowPlaying?) -> Void = { _ in }
    private(set) var current: NowPlaying?
    private var observers: [NSObjectProtocol] = []

    func start() {
        let center = DistributedNotificationCenter.default()
        observers.append(center.addObserver(forName: Notification.Name("com.spotify.client.PlaybackStateChanged"), object: nil, queue: .main) {
            [weak self] note in self?.received("Spotify", note.userInfo ?? [:])
        })
        observers.append(center.addObserver(forName: Notification.Name("com.apple.Music.playerInfo"), object: nil, queue: .main) {
            [weak self] note in self?.received("Music", note.userInfo ?? [:])
        })
        // Pick up a song that was already playing, but only from apps that already allow it (no prompt now).
        for (app, id) in MusicWatcher.apps where MusicWatcher.running(id) && MusicWatcher.allowed(id, ask: false) {
            if let found = MusicWatcher.query(app) { update(found) }
        }
    }

    func stop() {
        observers.forEach { DistributedNotificationCenter.default().removeObserver($0) }
        observers = []
    }

    static func running(_ bundleID: String) -> Bool {
        !NSRunningApplication.runningApplications(withBundleIdentifier: bundleID).isEmpty
    }

    // Whether iServer may send Apple events to the app; with `ask` macOS shows its permission prompt.
    static func allowed(_ bundleID: String, ask: Bool) -> Bool {
        let target = NSAppleEventDescriptor(bundleIdentifier: bundleID)
        guard let descriptor = target.aeDesc else { return false }
        return AEDeterminePermissionToAutomateTarget(descriptor, typeWildCard, typeWildCard, ask) == noErr
    }

    private func received(_ app: String, _ info: [AnyHashable: Any]) {
        let state = (info["Player State"] as? String ?? "").lowercased()
        guard state != "stopped", let title = info["Name"] as? String else {
            if current?.app == app { update(nil) }
            return
        }
        var duration = (info["Duration"] as? NSNumber)?.doubleValue ?? 0       // Spotify, in ms
        if duration == 0 { duration = (info["Total Time"] as? NSNumber)?.doubleValue ?? 0 }  // Music, in ms
        var next = NowPlaying(app: app, title: title, artist: info["Artist"] as? String ?? "", playing: state == "playing",
                              position: (info["Playback Position"] as? NSNumber)?.doubleValue ?? 0, duration: duration / 1000)
        if let current, current.app == app, current.title == title {
            next.artwork = current.artwork
            if info["Playback Position"] == nil { next.position = current.elapsed }
        }
        update(next)
        let bundle = MusicWatcher.apps.first { $0.0 == app }?.1 ?? ""
        if next.artwork == nil || info["Playback Position"] == nil, MusicWatcher.allowed(bundle, ask: false) {
            refreshDetails()
        }
    }

    private func update(_ next: NowPlaying?) {
        current = next
        onChange(next)
    }

    // Exact position and artwork, when the app allows Apple events.
    func refreshDetails() {
        guard let app = current?.app, let fresh = MusicWatcher.query(app) else { return }
        var next = fresh
        if next.artwork == nil, current?.title == next.title { next.artwork = current?.artwork }
        update(next)
    }

    // Play/pause, next or previous. The first time, macOS asks whether iServer may control the app.
    func command(_ verb: String) {
        let app = current?.app ?? MusicWatcher.apps.first { MusicWatcher.running($0.1) }?.0
        guard let app, let bundle = MusicWatcher.apps.first(where: { $0.0 == app })?.1, MusicWatcher.running(bundle) else { return }
        DispatchQueue.global(qos: .userInitiated).async {
            _ = MusicWatcher.allowed(bundle, ask: true)
            DispatchQueue.main.async {
                MusicWatcher.run("tell application \"\(app)\" to \(verb)")
                DispatchQueue.main.asyncAfter(deadline: .now() + 0.4) { self.refreshDetails() }
            }
        }
    }

    @discardableResult
    static func run(_ source: String) -> NSAppleEventDescriptor? {
        var error: NSDictionary?
        return NSAppleScript(source: source)?.executeAndReturnError(&error)
    }

    static func query(_ app: String) -> NowPlaying? {
        let durationExpression = app == "Spotify" ? "(duration of current track) / 1000" : "duration of current track"
        let source = """
            tell application "\(app)"
                if player state is stopped then return ""
                return (name of current track) & linefeed & (artist of current track) & linefeed & (player state as text) \
            & linefeed & (player position as text) & linefeed & (\(durationExpression) as text)
            end tell
            """
        guard let text = run(source)?.stringValue, !text.isEmpty else { return nil }
        let parts = text.components(separatedBy: "\n")
        guard parts.count >= 5 else { return nil }
        func number(_ text: String) -> Double { Double(text.replacingOccurrences(of: ",", with: ".")) ?? 0 }
        var playing = NowPlaying(app: app, title: parts[0], artist: parts[1], playing: parts[2] == "playing",
                                 position: number(parts[3]), duration: number(parts[4]))
        playing.artwork = artwork(app)
        return playing
    }

    static func artwork(_ app: String) -> NSImage? {
        if app == "Music" {
            guard let data = run("tell application \"Music\" to get raw data of artwork 1 of current track")?.data else { return nil }
            return NSImage(data: data)
        }
        guard let link = run("tell application \"Spotify\" to get artwork url of current track")?.stringValue,
              let url = URL(string: link), url.scheme == "https" else { return nil }
        let done = DispatchSemaphore(value: 0)
        var image: NSImage?
        URLSession.shared.dataTask(with: url) { data, _, _ in
            image = data.flatMap(NSImage.init(data:))
            done.signal()
        }.resume()
        _ = done.wait(timeout: .now() + 4)
        return image
    }

    static func demo() -> NowPlaying {
        let art = NSImage(size: NSSize(width: 64, height: 64), flipped: false) { rect in
            NSGradient(colors: [.systemPink, .systemPurple, .systemIndigo])?.draw(in: rect, angle: -45)
            return true
        }
        return NowPlaying(app: "Spotify", title: "Midnight City Lights", artist: "The Night Shift", playing: true,
                          position: 74, duration: 214, artwork: art)
    }
}

// Files dropped on the notch, kept as references until you drag them out or clear them.
final class Shelf {
    private(set) var items: [URL] = []
    var onChange: () -> Void = {}

    init() {
        items = (UserDefaults.standard.stringArray(forKey: "shelf") ?? []).map { URL(fileURLWithPath: $0) }
        prune()
    }

    func add(_ urls: [URL]) {
        for url in urls where !items.contains(url) { items.append(url) }
        save()
    }

    func remove(_ url: URL) {
        items.removeAll { $0 == url }
        save()
    }

    func clear() {
        items.removeAll()
        save()
    }

    // Drops files that were moved or deleted elsewhere.
    func prune() {
        let before = items.count
        items = items.filter { FileManager.default.fileExists(atPath: $0.path) }
        if items.count != before { save() }
    }

    private func save() {
        UserDefaults.standard.set(items.map(\.path), forKey: "shelf")
        onChange()
    }
}

// A countdown that lives in the notch.
final class NotchTimer {
    private(set) var endsAt: Date?
    private(set) var paused: TimeInterval?   // time left while paused
    private(set) var total: TimeInterval = 0
    var onFinish: () -> Void = {}

    var running: Bool { endsAt != nil || paused != nil }

    var remaining: TimeInterval {
        if let paused { return paused }
        return max(0, endsAt?.timeIntervalSinceNow ?? 0)
    }

    var fraction: Double { total > 0 ? remaining / total : 0 }

    func start(minutes: Double) {
        total = minutes * 60
        endsAt = Date().addingTimeInterval(total)
        paused = nil
    }

    func togglePause() {
        if let paused {
            endsAt = Date().addingTimeInterval(paused)
            self.paused = nil
        } else if endsAt != nil {
            paused = remaining
            endsAt = nil
        }
    }

    func stop() {
        endsAt = nil
        paused = nil
    }

    func tick() {
        guard let endsAt, endsAt <= Date() else { return }
        stop()
        onFinish()
    }

    static func text(_ seconds: TimeInterval) -> String {
        let total = Int(seconds.rounded(.up))
        return total >= 3600 ? String(format: "%d:%02d:%02d", total / 3600, (total % 3600) / 60, total % 60)
            : String(format: "%d:%02d", total / 60, total % 60)
    }
}

struct DownloadItem {
    let path: String
    let name: String
    var bytes: UInt64
}

// Files that browsers are still writing in ~/Downloads (Safari .download, Chrome .crdownload, Firefox .part).
enum DownloadWatcher {
    static let suffixes = [".download", ".crdownload", ".part", ".partial"]

    // Only files written to in the last two minutes; an abandoned partial file isn't a download in progress.
    static func scan() -> [DownloadItem] {
        DevClean.children(of: NSHomeDirectory() + "/Downloads").compactMap { path in
            guard let suffix = suffixes.first(where: { path.hasSuffix($0) }),
                  let modified = latestChange(path), Date().timeIntervalSince(modified) < 120 else { return nil }
            let name = String((path as NSString).lastPathComponent.dropLast(suffix.count))
            return DownloadItem(path: path, name: name, bytes: DevClean.allocatedSize(path))
        }
    }

    // Safari's .download is a folder with the growing file inside, so look one level in as well.
    static func latestChange(_ path: String) -> Date? {
        ([path] + DevClean.children(of: path)).compactMap(AgentWatcher.modified).max()
    }

    // The finished file next to the partial one, once the browser has renamed it.
    static func finished(_ item: DownloadItem) -> Bool {
        FileManager.default.fileExists(atPath: (item.path as NSString).deletingLastPathComponent + "/" + item.name)
    }
}

// MARK: - iNotch: approving Claude Code requests from the notch

struct ApprovalRequest {
    let id = UUID()
    let tool: String
    let summary: String
    let project: String
    let received = Date()
}

enum ApprovalAnswer { case allow, deny, terminal }

// Claude Code's PermissionRequest hook posts each request to this local server and waits for the answer.
// Only 127.0.0.1 is listened on. If iServer isn't running the hook gets no answer and Claude Code asks in
// the terminal as usual.
final class ApprovalServer {
    static let port: UInt16 = 47_823
    static let path = "/iserver/claude/permission"
    var onRequest: (ApprovalRequest) -> Void = { _ in }
    var onExpire: (UUID) -> Void = { _ in }
    private var listener: NWListener?
    private var waiting: [UUID: NWConnection] = [:]
    private let queue = DispatchQueue(label: "iserver.approvals")

    func start() {
        guard listener == nil else { return }
        let parameters = NWParameters.tcp
        parameters.requiredLocalEndpoint = .hostPort(host: "127.0.0.1", port: NWEndpoint.Port(rawValue: ApprovalServer.port)!)
        parameters.allowLocalEndpointReuse = true
        guard let listener = try? NWListener(using: parameters) else { return }
        listener.newConnectionHandler = { [weak self] connection in self?.accept(connection) }
        listener.start(queue: queue)
        self.listener = listener
    }

    func stop() {
        listener?.cancel()
        listener = nil
        queue.async {
            for connection in self.waiting.values { self.reply(connection, body: "") }
            self.waiting.removeAll()
        }
    }

    private func accept(_ connection: NWConnection) {
        connection.start(queue: queue)
        read(connection, buffer: Data())
    }

    // Reads one HTTP request (headers plus a Content-Length body).
    private func read(_ connection: NWConnection, buffer: Data) {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 65_536) { [weak self] data, _, complete, error in
            guard let self else { return }
            var buffer = buffer
            if let data { buffer.append(data) }
            guard buffer.count < 2_000_000, error == nil else { return connection.cancel() }
            if let split = buffer.range(of: Data("\r\n\r\n".utf8)) {
                let head = String(decoding: buffer[..<split.lowerBound], as: UTF8.self)
                let length = head.split(separator: "\r\n").first { $0.lowercased().hasPrefix("content-length:") }
                    .flatMap { Int($0.split(separator: ":")[1].trimmingCharacters(in: .whitespaces)) } ?? 0
                let body = buffer[split.upperBound...]
                if body.count >= length {
                    let firstLine = head.split(separator: "\r\n").first.map(String.init) ?? ""
                    self.handle(connection, line: firstLine, body: Data(body.prefix(length)))
                    return
                }
            }
            if complete { connection.cancel() } else { self.read(connection, buffer: buffer) }
        }
    }

    private func handle(_ connection: NWConnection, line: String, body: Data) {
        guard line.hasPrefix("POST \(ApprovalServer.path)"),
              let payload = (try? JSONSerialization.jsonObject(with: body)) as? [String: Any] else {
            return reply(connection, body: "", status: "404 Not Found")
        }
        let tool = payload["tool_name"] as? String ?? "Tool"
        let input = payload["tool_input"] as? [String: Any] ?? [:]
        let project = (payload["cwd"] as? String).map { ($0 as NSString).lastPathComponent } ?? "Claude Code"
        let request = ApprovalRequest(tool: tool, summary: ApprovalServer.summary(tool, input), project: project)
        waiting[request.id] = connection
        // Claude Code waits up to the hook's timeout (120 s); give up a little before that.
        queue.asyncAfter(deadline: .now() + 110) { [weak self] in
            guard let self, let connection = self.waiting.removeValue(forKey: request.id) else { return }
            self.reply(connection, body: "")
            DispatchQueue.main.async { self.onExpire(request.id) }
        }
        DispatchQueue.main.async { self.onRequest(request) }
    }

    func answer(_ id: UUID, _ answer: ApprovalAnswer) {
        queue.async {
            guard let connection = self.waiting.removeValue(forKey: id) else { return }
            let decision: [String: Any]
            switch answer {
            case .allow: decision = ["behavior": "allow"]
            case .deny: decision = ["behavior": "deny", "message": "Denied from iServer"]
            case .terminal: return self.reply(connection, body: "")  // no decision: Claude Code asks in the terminal
            }
            let output: [String: Any] = ["hookSpecificOutput": ["hookEventName": "PermissionRequest", "decision": decision]]
            let data = (try? JSONSerialization.data(withJSONObject: output)) ?? Data()
            self.reply(connection, body: String(decoding: data, as: UTF8.self))
        }
    }

    private func reply(_ connection: NWConnection, body: String, status: String = "200 OK") {
        let response = "HTTP/1.1 \(status)\r\nContent-Type: application/json\r\nContent-Length: \(body.utf8.count)\r\nConnection: close\r\n\r\n\(body)"
        connection.send(content: Data(response.utf8), completion: .contentProcessed { _ in connection.cancel() })
    }

    static func summary(_ tool: String, _ input: [String: Any]) -> String {
        if let command = input["command"] as? String { return command }
        if let file = input["file_path"] as? String { return DevClean.tilde(file) }
        if let url = input["url"] as? String { return url }
        if let pattern = input["pattern"] as? String { return pattern }
        if let prompt = input["description"] as? String { return prompt }
        return tool
    }
}

// Adds or removes iServer's PermissionRequest hook in ~/.claude/settings.json, keeping everything else.
enum ClaudeHook {
    static let file = NSHomeDirectory() + "/.claude/settings.json"
    static var command: String {
        "curl -sf --max-time 115 -X POST -H 'Content-Type: application/json' --data-binary @- "
            + "http://127.0.0.1:\(ApprovalServer.port)\(ApprovalServer.path) || true"
    }

    private static func load() -> [String: Any]? {
        guard FileManager.default.fileExists(atPath: file) else { return [:] }
        guard let data = FileManager.default.contents(atPath: file) else { return nil }
        if data.isEmpty { return [:] }
        return (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
    }

    static var installed: Bool {
        guard let hooks = load()?["hooks"] as? [String: Any], let entries = hooks["PermissionRequest"] as? [[String: Any]] else { return false }
        return entries.contains { isOurs($0) }
    }

    private static func isOurs(_ entry: [String: Any]) -> Bool {
        (entry["hooks"] as? [[String: Any]] ?? []).contains { ($0["command"] as? String)?.contains(ApprovalServer.path) == true }
    }

    // Returns an error message, or nil when it worked. A copy of the old file is kept next to it.
    static func set(_ on: Bool) -> String? {
        guard var settings = load() else {
            return L("~/.claude/settings.json couldn't be read as JSON, so it was left alone.",
                     "~/.claude/settings.json kon niet als JSON gelezen worden en is niet aangepast.")
        }
        var hooks = settings["hooks"] as? [String: Any] ?? [:]
        var entries = (hooks["PermissionRequest"] as? [[String: Any]] ?? []).filter { !isOurs($0) }
        if on {
            entries.append(["matcher": "*", "hooks": [["type": "command", "command": command, "timeout": 120]]])
        }
        hooks["PermissionRequest"] = entries.isEmpty ? nil : entries
        settings["hooks"] = hooks.isEmpty ? nil : hooks
        do {
            try FileManager.default.createDirectory(atPath: (file as NSString).deletingLastPathComponent, withIntermediateDirectories: true)
            if FileManager.default.fileExists(atPath: file) {
                let backup = file + ".iserver-backup"
                try? FileManager.default.removeItem(atPath: backup)
                try FileManager.default.copyItem(atPath: file, toPath: backup)
            }
            let data = try JSONSerialization.data(withJSONObject: settings, options: [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes])
            try data.write(to: URL(fileURLWithPath: file), options: .atomic)
            return nil
        } catch {
            return error.localizedDescription
        }
    }
}

// The card shown in the notch while Claude Code waits for a decision.
final class ApprovalCard: NSView {
    override var isFlipped: Bool { true }
    var onAnswer: (ApprovalAnswer) -> Void = { _ in }
    private let title = makeLabel("", size: 13, weight: .semibold, color: .white)
    private let detail = makeLabel("", size: 11.5, weight: .regular, color: NSColor.white.withAlphaComponent(0.75))
    private let more = makeLabel("", size: 10.5, weight: .medium, color: NSColor.white.withAlphaComponent(0.5))
    private lazy var allow = AccentButton { [weak self] in self?.onAnswer(.allow) }
    private lazy var deny = QuietButton(L("Deny", "Weigeren")) { [weak self] in self?.onAnswer(.deny) }
    private lazy var terminal = QuietButton(L("In terminal", "In terminal")) { [weak self] in self?.onAnswer(.terminal) }

    override init(frame frameRect: NSRect) {
        super.init(frame: frameRect)
        detail.font = NSFont.monospacedSystemFont(ofSize: 11.5, weight: .regular)
        detail.lineBreakMode = .byTruncatingMiddle
        detail.cell?.lineBreakMode = .byTruncatingMiddle
        allow.title = L("Allow", "Toestaan")
        for view in [title, detail, more, allow, deny, terminal] as [NSView] { addSubview(view) }
    }

    required init?(coder: NSCoder) { fatalError() }

    override func mouseDown(with event: NSEvent) {}
    override func mouseUp(with event: NSEvent) {}

    func show(_ request: ApprovalRequest, queued: Int) {
        title.stringValue = "Claude Code " + L("wants to use", "wil gebruiken") + " \(request.tool)  ·  \(request.project)"
        detail.stringValue = request.summary
        detail.toolTip = request.summary
        more.stringValue = queued > 0 ? L("+\(queued) more waiting", "nog \(queued) wachtend") : ""
    }

    override func layout() {
        super.layout()
        title.frame = NSRect(x: 2, y: 2, width: bounds.width - 4, height: 18)
        detail.frame = NSRect(x: 2, y: 24, width: bounds.width - 4, height: 16)
        let y: CGFloat = 50
        allow.frame = NSRect(x: 0, y: y, width: 96, height: 30)
        deny.frame = NSRect(x: allow.frame.maxX + 8, y: y + 1, width: 92, height: 28)
        terminal.frame = NSRect(x: deny.frame.maxX + 8, y: y + 1, width: 110, height: 28)
        more.frame = NSRect(x: terminal.frame.maxX + 10, y: y + 8, width: max(0, bounds.width - terminal.frame.maxX - 12), height: 14)
    }
}

// MARK: - iNotch: controller

// Borderless panels can't become key by default; this one can, so the prompter text can be typed in.
final class NotchPanel: NSPanel {
    override var canBecomeKey: Bool { true }
    override var canBecomeMain: Bool { false }
}

// Owns the island window and everything it shows. Separate from the server menu.
final class NotchController {
    private let demo: Bool
    private var panel: NotchPanel?
    private let view = NotchView()
    private let companion = Companion()
    let prompter = Prompter()
    private var timers: [Timer] = []
    private var monitors: [Any] = []
    private var powerSource: CFRunLoopSource?
    private var lastPower = PowerInfo()
    private var warnedLow = false
    private var toldFull = false
    private var sessions: [AgentSession] = []
    private var sessionStates: [String: AgentState] = [:]
    private var usage: [ProviderUsage] = []
    private var usageUpdated: Date?
    private var alerts: [NotchAlert] = []
    private var alertUntil = Date.distantPast
    private var hovering = false
    private var lastMouse = NSPoint.zero
    private var lastMoved = Date()
    private var cpu = 0.0
    private var scanning = false
    private(set) var enabled = false
    private let approvals = ApprovalServer()
    private var pending: [ApprovalRequest] = []
    private let music = MusicWatcher()
    private var nowPlaying: NowPlaying?
    private let shelf = Shelf()
    private let countdown = NotchTimer()
    private var downloads: [DownloadItem] = []
    private var dragBoardIdle = NSPasteboard(name: .drag).changeCount
    private var dropping = false
    private var lastSecond = 0

    private var claudeConnected: Bool {
        get { UserDefaults.standard.bool(forKey: "notchClaudeUsage") }
        set { UserDefaults.standard.set(newValue, forKey: "notchClaudeUsage") }
    }

    init(demo: Bool) {
        self.demo = demo
        view.companion = companion
        view.onClick = { [weak self] in self?.toggleOpen() }
        view.content.onPage = { [weak self] in self?.view.refit() }
        view.onPip = { [weak self] in
            guard let self else { return }
            let all = Companion.Style.allCases
            let next = all[((all.firstIndex(of: self.companion.style) ?? 0) + 1) % all.count]
            self.companion.style = next
            self.companion.react(.happy, for: 1.2)
        }
        view.content.usage.onConnectClaude = { [weak self] in
            self?.claudeConnected = true
            self?.refreshUsage()
        }
        view.content.usage.onRefresh = { [weak self] in self?.refreshUsage() }
        let page = view.content.prompter
        page.onText = { [weak self] in self?.prompter.text = $0 }
        page.onPlay = { [weak self] in
            guard let self, let screen = self.screen else { return }
            self.prompter.toggle(below: self.notchRect(on: screen), on: screen)
            if self.prompter.running { self.collapse() }
        }
        page.onReset = { [weak self] in self?.prompter.restart() }
        page.onSpeed = { [weak self] in self?.prompter.adjust(speed: $0) }
        page.onSize = { [weak self] in self?.prompter.adjust(size: $0) }
        prompter.onChange = { [weak self] in self?.showPrompter() }
        view.content.agents.onHook = { [weak self] in self?.toggleHook() }
        view.card.onAnswer = { [weak self] in self?.answer($0) }

        // Music
        music.onChange = { [weak self] playing in
            guard let self else { return }
            let started = playing?.title != self.nowPlaying?.title && playing?.playing == true
            self.nowPlaying = playing
            self.companion.dancing = playing?.playing == true
            self.showNow()
            if started, let playing, self.view.mode != .expanded {
                self.say(NotchAlert(symbol: "music.note", tint: .systemPink, title: playing.title, detail: playing.artist), mood: .happy)
            }
        }
        let now = view.content.now
        now.onMusic = { [weak self] in self?.music.command($0) }
        now.onTimer = { [weak self] minutes in
            self?.countdown.start(minutes: minutes)
            self?.showNow()
        }
        now.onTimerPause = { [weak self] in
            self?.countdown.togglePause()
            self?.showNow()
        }
        now.onTimerStop = { [weak self] in
            self?.countdown.stop()
            self?.showNow()
        }
        countdown.onFinish = { [weak self] in
            NSSound(named: "Glass")?.play()
            self?.say(NotchAlert(symbol: "timer", tint: .systemOrange, title: L("Time's up", "De tijd is om"),
                                 detail: L("Your timer has finished", "Je timer is afgelopen")), mood: .surprised)
            self?.showNow()
        }

        // Shelf
        let shelfPage = view.content.shelf
        shelf.onChange = { [weak self] in self?.showShelf() }
        shelfPage.onRemove = { [weak self] in self?.shelf.remove($0) }
        shelfPage.onClear = { [weak self] in self?.shelf.clear() }
        shelfPage.onReveal = { url in NSWorkspace.shared.activateFileViewerSelecting([url]) }
        shelfPage.onAirDrop = { [weak self] in
            guard let self, !self.shelf.items.isEmpty else { return }
            NSSharingService(named: .sendViaAirDrop)?.perform(withItems: self.shelf.items)
        }
        view.onDragEnter = { [weak self] in self?.startDrop() }
        view.onDragExit = { [weak self] in self?.endDrop() }
        view.onDrop = { [weak self] urls in
            guard let self else { return }
            self.shelf.add(urls)
            self.endDrop()
            self.say(NotchAlert(symbol: "tray.and.arrow.down.fill", tint: .systemTeal,
                                title: urls.count == 1 ? L("On the shelf", "Op de plank") : L("\(urls.count) files on the shelf", "\(urls.count) bestanden op de plank"),
                                detail: urls.count == 1 ? urls[0].lastPathComponent : L("Open the notch to drag them out", "Open de notch om ze eruit te slepen")),
                     mood: .happy)
        }
        approvals.onRequest = { [weak self] in self?.received($0) }
        approvals.onExpire = { [weak self] id in self?.expired(id) }
    }

    // MARK: Turning on and off

    func setEnabled(_ on: Bool) {
        guard on != enabled else { return }
        enabled = on
        on ? start() : stop()
    }

    private func start() {
        let panel = NotchPanel(contentRect: .zero, styleMask: [.borderless, .nonactivatingPanel], backing: .buffered, defer: false)
        panel.isOpaque = false
        panel.backgroundColor = .clear
        panel.hasShadow = false
        panel.level = NSWindow.Level(rawValue: NSWindow.Level.mainMenu.rawValue + 3)
        panel.collectionBehavior = [.canJoinAllSpaces, .stationary, .fullScreenAuxiliary, .ignoresCycle]
        panel.appearance = NSAppearance(named: .darkAqua)
        panel.ignoresMouseEvents = true
        panel.contentView = view
        self.panel = panel
        place()
        view.mode = .compact
        view.settle()
        panel.orderFrontRegardless()

        // ~30 fps while visible: Pip's animation and the eyes following the cursor.
        timers.append(repeating(1.0 / 30) { [weak self] in self?.frame() })
        timers.append(repeating(4) { [weak self] in self?.scanAgents() })
        timers.append(repeating(600) { [weak self] in self?.refreshUsage() })
        timers.append(repeating(10) { [weak self] in self?.sampleCPU() })
        timers.append(repeating(2) { [weak self] in self?.scanDownloads() })
        if let monitor = NSEvent.addGlobalMonitorForEvents(matching: [.leftMouseDown, .rightMouseDown], handler: { [weak self] _ in
            self?.clickedElsewhere()
        }) { monitors.append(monitor) }
        NotificationCenter.default.addObserver(self, selector: #selector(screensChanged),
                                               name: NSApplication.didChangeScreenParametersNotification, object: nil)
        watchPower()
        approvals.start()
        music.start()
        if demo { music.onChange(MusicWatcher.demo()) }
        shelf.prune()
        showShelf()
        showNow()
        view.content.agents.showHook(installed: ClaudeHook.installed)
        lastPower = PowerInfo.sample()
        scanAgents()
        refreshUsage()
        say(NotchAlert(symbol: "hand.wave.fill", tint: Companion.body, title: L("Hi, I'm Pip!", "Hoi, ik ben Pip!"),
                       detail: L("Click the notch to open me", "Klik op de notch om me te openen")), mood: .happy)
    }

    private func stop() {
        timers.forEach { $0.invalidate() }
        timers = []
        monitors.forEach(NSEvent.removeMonitor)
        monitors = []
        if let powerSource { CFRunLoopRemoveSource(CFRunLoopGetMain(), powerSource, .defaultMode) }
        powerSource = nil
        NotificationCenter.default.removeObserver(self)
        prompter.stop()
        approvals.stop()
        pending.removeAll()
        music.stop()
        panel?.orderOut(nil)
        panel = nil
    }

    private func repeating(_ interval: TimeInterval, _ block: @escaping () -> Void) -> Timer {
        let timer = Timer(timeInterval: interval, repeats: true) { _ in block() }
        timer.tolerance = interval * 0.2
        RunLoop.main.add(timer, forMode: .common)
        return timer
    }

    // MARK: Geometry

    private var screen: NSScreen? {
        NSScreen.screens.first { $0.safeAreaInsets.top > 0 } ?? NSScreen.main
    }

    func notchRect(on screen: NSScreen) -> NSRect {
        let frame = screen.frame
        if screen.safeAreaInsets.top > 0,
           let left = screen.auxiliaryTopLeftArea, let right = screen.auxiliaryTopRightArea {
            let width = frame.width - left.width - right.width
            let height = screen.safeAreaInsets.top
            return NSRect(x: frame.minX + left.width, y: frame.maxY - height, width: width, height: height)
        }
        // No notch: a capsule just below the top edge
        let height = max(24, NSStatusBar.system.thickness - 2)
        return NSRect(x: frame.midX - 90, y: frame.maxY - height - 4, width: 180, height: height)
    }

    private func place() {
        guard let panel, let screen else { return }
        let notch = notchRect(on: screen)
        view.hasNotch = screen.safeAreaInsets.top > 0
        view.notch = notch.size
        let width: CGFloat = 760, height: CGFloat = 420
        let top = view.hasNotch ? screen.frame.maxY : notch.maxY
        panel.setFrame(NSRect(x: notch.midX - width / 2, y: top - height, width: width, height: height), display: true)
    }

    @objc private func screensChanged() {
        place()
        view.settle()
    }

    // MARK: Per frame

    private func frame() {
        guard let panel else { return }
        let mouse = NSEvent.mouseLocation
        if mouse != lastMouse {
            lastMouse = mouse
            lastMoved = Date()
        }
        // Clicks only land on the black shape; everywhere else they pass through to the menu bar and apps.
        let local = view.convert(panel.convertPoint(fromScreen: mouse), from: nil)
        let inside = view.shapePath.contains(local) || dropping
        if panel.ignoresMouseEvents == inside { panel.ignoresMouseEvents = !inside }
        let near = view.shapePath.bounds.insetBy(dx: -6, dy: -6).contains(local)
        if near != hovering {
            hovering = near
            updateMode()
        }
        countdown.tick()
        watchDrag(mouse: mouse)
        let second = Int(Date().timeIntervalSinceReferenceDate)
        if second != lastSecond {
            lastSecond = second
            updateWings()
            if view.mode == .expanded, view.content.page == 0 { view.content.now.needsDisplay = true }
        }
        if Date() > alertUntil, view.mode == .alert {
            if pending.isEmpty { nextAlert() } else { showApproval() }
        }

        let resting: Companion.Mood
        if cpu > 90 || (lastPower.hasBattery && !lastPower.pluggedIn && lastPower.level <= 15) {
            resting = .worried
        } else if Date().timeIntervalSince(lastMoved) > 300 && !sessions.contains(where: { $0.state == .working }) {
            resting = .sleepy
        } else {
            resting = .idle
        }
        companion.tick(resting: resting)
        // Redraw only the band around the notch (Pip and the wings); the open panel redraws itself when it changes.
        let shape = view.shapePath.bounds
        let band = view.mode == .expanded ? NSRect(x: shape.minX, y: shape.maxY - view.notch.height - 8,
                                                   width: shape.width, height: view.notch.height + 8) : shape.insetBy(dx: -8, dy: -8)
        view.setNeedsDisplay(band)
    }

    private func updateMode() {
        guard view.mode != .alert, view.mode != .expanded, view.mode != .approval, view.mode != .drop else { return }
        view.setMode(hovering ? .peek : .compact)
    }

    private func toggleOpen() {
        if view.mode == .approval { return }  // answer the card first
        if view.mode == .expanded {
            collapse()
        } else {
            alertUntil = .distantPast
            alerts.removeAll()
            showSessions()
            showUsage()
            showPrompter()
            if claudeConnected, (usageUpdated.map { Date().timeIntervalSince($0) > 300 } ?? true) { refreshUsage() }
            view.setMode(.expanded)
            companion.react(.happy, for: 1.2)
        }
    }

    private func collapse() {
        view.setMode(hovering ? .peek : .compact)
    }

    private func clickedElsewhere() {
        if view.mode == .expanded { collapse() }
    }

    // MARK: Approvals

    private func received(_ request: ApprovalRequest) {
        pending.append(request)
        companion.react(.surprised, for: 3)
        if pending.count == 1 { showApproval() } else { view.card.show(pending[0], queued: pending.count - 1) }
    }

    private func showApproval() {
        guard let first = pending.first else {
            view.setMode(hovering ? .peek : .compact)
            if !alerts.isEmpty { nextAlert() }
            return
        }
        view.card.show(first, queued: pending.count - 1)
        view.setMode(.approval)
        NSSound(named: "Tink")?.play()
    }

    private func answer(_ answer: ApprovalAnswer) {
        guard let first = pending.first else { return }
        approvals.answer(first.id, answer)
        pending.removeFirst()
        companion.react(answer == .allow ? .happy : .idle, for: 1.5)
        showApproval()
    }

    private func expired(_ id: UUID) {
        let wasFirst = pending.first?.id == id
        pending.removeAll { $0.id == id }
        if wasFirst { showApproval() }
    }

    private func toggleHook() {
        let installed = ClaudeHook.installed
        collapse()
        let alert = NSAlert()
        if installed {
            alert.messageText = L("Stop approving from the notch?", "Niet meer goedkeuren vanuit de notch?")
            alert.informativeText = L("iServer's hook is removed from ~/.claude/settings.json; Claude Code asks in the terminal again.",
                                      "De hook van iServer wordt uit ~/.claude/settings.json gehaald; Claude Code vraagt weer in de terminal.")
            alert.addButton(withTitle: L("Turn off", "Uitzetten"))
        } else {
            alert.messageText = L("Approve Claude Code requests from the notch?", "Claude Code-verzoeken goedkeuren vanuit de notch?")
            alert.informativeText = L("""
                iServer adds a PermissionRequest hook to ~/.claude/settings.json (a copy is kept as settings.json.iserver-backup). \
                When Claude Code asks for permission, the question shows in the notch: Allow, Deny, or answer in the terminal. \
                If iServer isn't running, Claude Code just asks in the terminal. New Claude Code sessions pick it up.
                """, """
                iServer voegt een PermissionRequest-hook toe aan ~/.claude/settings.json (een kopie blijft als settings.json.iserver-backup). \
                Vraagt Claude Code om toestemming, dan verschijnt de vraag in de notch: Toestaan, Weigeren of in de terminal antwoorden. \
                Draait iServer niet, dan vraagt Claude Code het gewoon in de terminal. Nieuwe Claude Code-sessies gebruiken het.
                """)
            alert.addButton(withTitle: L("Turn on", "Aanzetten"))
        }
        alert.addButton(withTitle: L("Cancel", "Annuleer"))
        NSApp.activate(ignoringOtherApps: true)
        guard alert.runModal() == .alertFirstButtonReturn else { return }
        if let error = ClaudeHook.set(!installed) {
            let failure = NSAlert()
            failure.messageText = L("Couldn't change Claude Code's settings", "Instellingen van Claude Code niet aangepast")
            failure.informativeText = error
            failure.runModal()
        }
        view.content.agents.showHook(installed: ClaudeHook.installed)
    }

    // MARK: Alerts

    func say(_ alert: NotchAlert, mood: Companion.Mood = .surprised) {
        guard enabled else { return }
        companion.react(mood)
        if view.mode == .expanded { return }  // the open panel already shows everything
        alerts.append(alert)
        if view.mode != .alert, view.mode != .approval { nextAlert() }
    }

    private func nextAlert() {
        guard !alerts.isEmpty else {
            view.alert = nil
            view.setMode(hovering ? .peek : .compact)
            return
        }
        view.alert = alerts.removeFirst()
        alertUntil = Date().addingTimeInterval(3.2)
        view.setMode(.alert)
    }

    func serversChanged(started: [ServerGroup], stopped: [String]) {
        for group in started.prefix(2) {
            let port = group.listeners.first.map { ":\($0.port)" } ?? ""
            say(NotchAlert(symbol: "play.circle.fill", tint: .systemGreen, title: group.title + " " + L("started", "gestart"),
                           detail: port), mood: .happy)
        }
        for name in stopped.prefix(2) {
            say(NotchAlert(symbol: "stop.circle.fill", tint: .systemGray, title: name + " " + L("stopped", "gestopt"),
                           detail: L("dev server", "dev server")), mood: .surprised)
        }
    }

    func awakeChanged(_ on: Bool) {
        say(NotchAlert(symbol: on ? "cup.and.saucer.fill" : "moon.zzz.fill", tint: on ? .systemOrange : .systemIndigo,
                       title: on ? L("Staying awake", "Blijft wakker") : L("Sleep allowed again", "Mag weer slapen"),
                       detail: on ? L("Mac and display won't sleep", "Mac en scherm slapen niet") : L("Awake is off", "Wakker staat uit")),
            mood: on ? .happy : .sleepy)
    }

    // MARK: Power

    private func watchPower() {
        let context = Unmanaged.passUnretained(self).toOpaque()
        guard let source = IOPSNotificationCreateRunLoopSource({ context in
            guard let context else { return }
            Unmanaged<NotchController>.fromOpaque(context).takeUnretainedValue().powerChanged()
        }, context)?.takeRetainedValue() else { return }
        CFRunLoopAddSource(CFRunLoopGetMain(), source, .defaultMode)
        powerSource = source
    }

    private func powerChanged() {
        let now = PowerInfo.sample()
        defer { lastPower = now }
        guard now.hasBattery else { return }
        if now.pluggedIn != lastPower.pluggedIn {
            say(NotchAlert(symbol: now.pluggedIn ? "bolt.fill" : "battery.75percent", tint: now.pluggedIn ? .systemGreen : .white,
                           title: now.pluggedIn ? L("Charging", "Opladen") : L("On battery", "Op batterij"), detail: "\(now.level)%"),
                mood: now.pluggedIn ? .happy : .surprised)
            if now.pluggedIn { warnedLow = false } else { toldFull = false }
        }
        if !now.pluggedIn, now.level <= 20, !warnedLow {
            warnedLow = true
            say(NotchAlert(symbol: "battery.25percent", tint: .systemRed, title: L("Battery low", "Batterij bijna leeg"),
                           detail: "\(now.level)%"), mood: .worried)
        }
        if now.pluggedIn, now.level >= 100, !toldFull {
            toldFull = true
            say(NotchAlert(symbol: "battery.100percent.bolt", tint: .systemGreen, title: L("Fully charged", "Volledig opgeladen"),
                           detail: "100%"), mood: .happy)
        }
    }

    private func sampleCPU() {
        DispatchQueue.global(qos: .utility).async { [weak self] in
            let load = Vitals.cpuLoad()
            DispatchQueue.main.async { self?.cpu = load }
        }
    }

    // MARK: Agents

    private func scanAgents() {
        guard !scanning else { return }
        scanning = true
        let demo = self.demo
        DispatchQueue.global(qos: .utility).async { [weak self] in
            let found = demo ? AgentWatcher.demo() : AgentWatcher.scan()
            DispatchQueue.main.async {
                guard let self else { return }
                self.scanning = false
                for session in found where self.sessionStates[session.id] == .working || self.sessionStates[session.id] == .waiting {
                    if session.state == .done {
                        self.say(NotchAlert(symbol: "checkmark.circle.fill", tint: .systemGreen,
                                            title: session.agent + " " + L("finished", "is klaar"), detail: session.project), mood: .happy)
                    } else if session.state == .waiting, self.sessionStates[session.id] == .working {
                        self.say(NotchAlert(symbol: "hand.raised.fill", tint: .systemOrange,
                                            title: session.agent + " " + L("is waiting", "wacht"), detail: session.project), mood: .worried)
                    }
                }
                self.sessionStates = Dictionary(found.map { ($0.id, $0.state) }, uniquingKeysWith: { first, _ in first })
                self.sessions = found
                self.showSessions()
            }
        }
    }

    private func showSessions() {
        let before = view.content.agents.count
        view.content.agents.show(sessions)
        if before != sessions.count { view.refit() }
        let working = sessions.filter { $0.state == .working }.count
        let waiting = sessions.filter { $0.state == .waiting }.count
        if waiting > 0 {
            view.rightText = "\(waiting) " + L("waiting", "wacht")
        } else if working > 0 {
            view.rightText = working == 1 ? L("1 agent working", "1 agent bezig") : "\(working) " + L("agents working", "agents bezig")
        } else {
            view.rightText = usageHeadline
        }
        view.leftText = usageSummary
        updateWings()
        view.claudeUsage = usage.first { $0.name == "Claude" }.flatMap { $0.fiveHour ?? $0.weekly }?.used
        view.codexUsage = usage.first { $0.name == "Codex" }.flatMap { $0.fiveHour ?? $0.weekly }?.used
    }

    // MARK: Live activities

    // The right wing shows the most urgent thing: an agent waiting, a timer, a download, music, an agent working, usage.
    private func updateWings() {
        let next: NotchView.Wing
        if sessions.contains(where: { $0.state == .waiting }) {
            next = .dot(.systemOrange)
        } else if countdown.running {
            next = .timer(NotchTimer.text(countdown.remaining), countdown.fraction)
        } else if !downloads.isEmpty {
            next = .download
        } else if nowPlaying?.playing == true {
            next = .bars
        } else if sessions.contains(where: { $0.state == .working }) {
            next = .dot(.systemBlue)
        } else if let headline = usageHeadline {
            next = .text(headline)
        } else {
            next = .none
        }
        view.music = nowPlaying
        guard next != view.rightWing else { return }
        let resize: Bool = {
            switch (next, view.rightWing) {
            case (.timer, .timer): return false
            default: return true
            }
        }()
        view.rightWing = next
        if resize, view.mode == .compact || view.mode == .peek { view.setMode(view.mode) }
    }

    private func showNow() {
        let page = view.content.now
        let before = page.preferredHeight
        page.music = nowPlaying
        page.timer = countdown
        page.downloads = downloads
        page.refresh()
        if page.preferredHeight != before { view.refit() }
        updateWings()
    }

    private func showShelf() {
        view.content.shelf.show(shelf.items)
        view.refit()
    }

    private func scanDownloads() {
        DispatchQueue.global(qos: .utility).async { [weak self] in
            let found = DownloadWatcher.scan()
            DispatchQueue.main.async {
                guard let self else { return }
                let names = Set(found.map(\.name))
                for item in self.downloads where !names.contains(item.name) && DownloadWatcher.finished(item) {
                    self.say(NotchAlert(symbol: "arrow.down.circle.fill", tint: .systemBlue, title: L("Downloaded", "Gedownload"),
                                        detail: item.name), mood: .happy)
                }
                let changed = found.map(\.name) != self.downloads.map(\.name)
                self.downloads = found
                if changed || self.view.content.page == 0 { self.showNow() }
            }
        }
    }

    // A file drag anywhere on screen: when it comes near the notch, open a big drop zone.
    private func watchDrag(mouse: NSPoint) {
        let board = NSPasteboard(name: .drag)
        let pressed = NSEvent.pressedMouseButtons & 1 != 0
        guard pressed else {
            dragBoardIdle = board.changeCount
            if dropping { endDrop() }
            return
        }
        guard board.changeCount != dragBoardIdle, board.types?.contains(.fileURL) == true,
              let screen, let panel else { return }
        let notch = notchRect(on: screen)
        let near = abs(mouse.x - notch.midX) < 240 && mouse.y > notch.minY - 120
        if near, !dropping {
            startDrop()
            panel.ignoresMouseEvents = false
        } else if !near, dropping {
            endDrop()
        }
    }

    private func startDrop() {
        guard !dropping, view.mode != .approval else { return }
        dropping = true
        companion.react(.surprised, for: 1.5)
        view.setMode(.drop)
    }

    private func endDrop() {
        guard dropping else { return }
        dropping = false
        if view.mode == .drop { view.setMode(hovering ? .peek : .compact) }
    }

    // MARK: Usage

    private var usageHeadline: String? {
        guard let window = usage.first(where: { $0.fiveHour != nil })?.fiveHour else { return nil }
        return "\(Int((window.used * 100).rounded()))%"
    }

    // The provider closest to its 5-hour limit; there's only room for one beside the notch.
    private var usageSummary: String? {
        let readings = usage.compactMap { provider -> (String, Double)? in
            guard let window = provider.fiveHour ?? provider.weekly else { return nil }
            return (provider.name, window.used)
        }
        guard let top = readings.max(by: { $0.1 < $1.1 }) else { return nil }
        return "\(top.0) \(Int((top.1 * 100).rounded()))%"
    }

    // Codex and Claude load separately: Claude may wait on a Keychain prompt, Codex never needs one.
    func refreshUsage() {
        if demo {
            AIUsage.demo().forEach(merge)
            return
        }
        let claude = claudeConnected
        DispatchQueue.global(qos: .utility).async { [weak self] in
            let codex = AIUsage.codex()
            DispatchQueue.main.async { self?.merge(codex) }
        }
        guard claude else { return }
        DispatchQueue.global(qos: .utility).async { [weak self] in
            let reading = AIUsage.claude()
            DispatchQueue.main.async { self?.merge(reading) }
        }
    }

    private func merge(_ provider: ProviderUsage) {
        let previous = usage.first { $0.name == provider.name }
        usage.removeAll { $0.name == provider.name }
        usage.append(provider)
        usage.sort { $0.name < $1.name }  // Claude, then Codex
        usageUpdated = Date()
        if let now = provider.fiveHour, now.used >= 0.9, (previous?.fiveHour?.used ?? 0) < 0.9 {
            say(NotchAlert(symbol: "gauge.with.dots.needle.100percent", tint: .systemOrange,
                           title: provider.name + " " + L("almost at its limit", "bijna aan de limiet"),
                           detail: "\(Int(now.used * 100))% " + L("of 5 hours", "van 5 uur")), mood: .worried)
        }
        showUsage()
        showSessions()
        if view.mode == .peek { view.setMode(.peek) }  // the hover width follows the new readings
    }

    private func showUsage() {
        view.content.usage.show(usage, claudeConnected: claudeConnected || demo, updated: usageUpdated)
    }

    private func showPrompter() {
        view.content.prompter.show(text: prompter.text, running: prompter.running, speed: prompter.speed, size: prompter.size)
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
    private var menuCPU: [Double] = []
    private lazy var notch = NotchController(demo: demo)
    private var notchEnabled: Bool {
        get { UserDefaults.standard.bool(forKey: "notchEnabled") }
        set { UserDefaults.standard.set(newValue, forKey: "notchEnabled") }
    }  // system CPU 0...1 for the menu bar graph, newest last
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
        board.setNotch = { [weak self] on in
            guard let self else { return }
            self.notchEnabled = on
            self.notch.setEnabled(on)
            self.board.notchOn = on
        }
        board.setAwake = { [weak self] on in
            guard let self else { return }
            Awake.set(on)
            self.notch.awakeChanged(Awake.isOn)
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
        board.deleteClip = { [weak self] in self?.clips.remove($0.id) }
        board.clearClips = { [weak self] in self?.clearClipHistory() }
        board.clipImage = { [weak self] in self?.clips.image($0) }
        board.clipBytes = { [weak self] in self?.clips.imageBytes($0) ?? 0 }
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
        if notchEnabled || CommandLine.arguments.contains("--notch") {
            notch.setEnabled(true)
            board.notchOn = true
        }
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
                let before = self.groups
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
                // Servers that started or stopped since the last scan (not on the very first one).
                if changed, !self.lastSignature.isEmpty {
                    let old = Set(before.map(\.id)), new = Set(result.map(\.id))
                    self.notch.serversChanged(started: result.filter { !old.contains($0.id) },
                                              stopped: before.filter { !new.contains($0.id) }.map(\.title))
                }
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

    private func clearClipHistory() {
        closePanel()
        let alert = NSAlert()
        alert.messageText = L("Clear clipboard history?", "Klembordgeschiedenis wissen?")
        alert.informativeText = L("Removes everything that isn't pinned.", "Verwijdert alles wat niet is vastgezet.")
        alert.addButton(withTitle: L("Clear", "Wissen"))
        alert.addButton(withTitle: L("Cancel", "Annuleer"))
        NSApp.activate(ignoringOtherApps: true)
        guard alert.runModal() == .alertFirstButtonReturn else { return }
        clips.clearHistory()
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
