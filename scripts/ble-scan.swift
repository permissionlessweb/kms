import AppKit
import CoreBluetooth
import Foundation

/// Scans for Zigner advertisements and holds one connection per pairing code
/// the console accepted (<dir>/chosen, one code per line, at most maxLinks).
/// Each phone gets its own request drop at <dir>/links/<code>/ (req.json,
/// resp.json, pub.hex, keys/), its own in-flight slot and its own redial
/// timer, so one phone stalling never holds back another. The Noise session
/// and pin checks live in the KMS (signing/bluetooth/mesh.go); this process
/// only moves sealed bytes and never holds a consensus private key.
let serviceUUID = CBUUID(string: "e7c8a1b0-4f3e-4c2a-9b6d-6b6d73000001")
let pubUUID = CBUUID(string: "e7c8a1b0-4f3e-4c2a-9b6d-6b6d73000002")
let signUUID = CBUUID(string: "e7c8a1b0-4f3e-4c2a-9b6d-6b6d73000003")
let sigUUID = CBUUID(string: "e7c8a1b0-4f3e-4c2a-9b6d-6b6d73000004")
let granterUUID = CBUUID(string: "e7c8a1b0-4f3e-4c2a-9b6d-6b6d73000005")
let statusUUID = CBUUID(string: "e7c8a1b0-4f3e-4c2a-9b6d-6b6d73000006")
/// Every validator key on the phone (public data):
/// 0x01 | count | per key: key id (8) | chain len | chain | label len | label | pub (32).
/// Written to <dir>/keys/<name>/pub.hex for signing/bluetooth/keylink.go
/// PubKeyFor, plus <dir>/keys.json. Keyed 0x12 sign frames travel inside
/// the Noise box like 0x10, so they need no scanner change.
let keysUUID = CBUUID(string: "e7c8a1b0-4f3e-4c2a-9b6d-6b6d73000007")

let maxLinks = 7

/// One phone connection.
final class PLink {
    let code: String
    let dir: URL
    var peripheral: CBPeripheral?
    var signChar: CBCharacteristic?
    var sigChar: CBCharacteristic?
    var granterChar: CBCharacteristic?
    var statusChar: CBCharacteristic?
    var keysChar: CBCharacteristic?
    var lastKeys = Date.distantPast
    var lastKeysBody = Data()
    var lastReq: UInt64 = 0
    var inflight: UInt64 = 0
    var inflightAt = Date.distantPast
    var inflightOp: UInt8 = 0
    var sigReady = false
    var timeouts = 0
    var helloMisses = 0
    var nextConnect = Date.distantPast
    var backoff: TimeInterval = 0
    var lastStatus = Date.distantPast
    var lastRSSI = Date.distantPast
    var state = "down"
    var keys: [Scan.PhoneKey] = []
    init(code: String, root: URL) {
        self.code = code
        dir = root.appendingPathComponent("links").appendingPathComponent(code)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    }
    func reset() {
        signChar = nil; sigChar = nil; granterChar = nil; statusChar = nil; keysChar = nil
        inflight = 0; timeouts = 0; helloMisses = 0; sigReady = false
    }
    /// Fast first redial, doubling to 1.5s, with jitter so links that drop
    /// together do not dial in lockstep.
    func scheduleRedial() {
        backoff = backoff == 0 ? 0.25 : min(backoff * 2, 1.5)
        nextConnect = Date().addingTimeInterval(backoff + Double.random(in: 0...0.3))
    }
}

final class Scan: NSObject, CBCentralManagerDelegate, CBPeripheralDelegate {
    var central: CBCentralManager!
    var byCode: [String: CBPeripheral] = [:]
    var links: [String: PLink] = [:]
    let helloMissLimit = 3
    let dir: URL = {
        let path = ProcessInfo.processInfo.environment["KMS_BLE_DIR"] ?? "/tmp/kms-ble"
        let url = URL(fileURLWithPath: path)
        try? FileManager.default.createDirectory(at: url.appendingPathComponent("links"), withIntermediateDirectories: true)
        return url
    }()

    func start() {
        central = CBCentralManager(
            delegate: self,
            queue: nil,
            options: [CBCentralManagerOptionShowPowerAlertKey: true]
        )
        Timer.scheduledTimer(withTimeInterval: 0.02, repeats: true) { [weak self] _ in
            self?.pump()
        }
    }

    func link(for p: CBPeripheral) -> PLink? {
        links.values.first { $0.peripheral == p }
    }

    func setState(_ l: PLink, _ v: String) {
        l.state = v
        emit(["event": "link", "code": l.code, "value": v])
    }

    func centralManagerDidUpdateState(_ central: CBCentralManager) {
        let value: String
        switch central.state {
        case .poweredOn:
            value = "on"
            central.scanForPeripherals(
                withServices: nil,
                options: [CBCentralManagerScanOptionAllowDuplicatesKey: true]
            )
        case .poweredOff:
            value = "off"
        case .unauthorized:
            value = "unauthorized"
        case .unsupported:
            value = "unsupported"
        case .resetting, .unknown:
            value = "starting"
        @unknown default:
            value = "starting"
        }
        emit(["event": "state", "value": value])
    }

    func centralManager(
        _ central: CBCentralManager,
        didDiscover peripheral: CBPeripheral,
        advertisementData: [String: Any],
        rssi RSSI: NSNumber
    ) {
        guard let data = advertisementData[CBAdvertisementDataManufacturerDataKey] as? Data,
              data.count >= 6,
              data[0] == 0xFF, data[1] == 0xFF
        else { return }
        let code = data.suffix(4).map { String(format: "%02x", $0) }.joined()
        let previous = byCode[code]
        byCode[code] = peripheral
        if let previous, previous != peripheral, let l = links[code], l.peripheral == previous {
            central.cancelPeripheralConnection(previous)
            l.peripheral = nil
            l.reset()
            l.nextConnect = Date()
        }
        emit(["event": "seen", "code": code, "rssi": RSSI.intValue])
    }

    func isPrimary(_ l: PLink) -> Bool { chosenCodes().first == l.code }

    func chosenCodes() -> [String] {
        let raw = (try? String(contentsOf: dir.appendingPathComponent("chosen"), encoding: .utf8)) ?? ""
        var out: [String] = []
        for f in raw.split(whereSeparator: { $0.isWhitespace }) {
            let c = f.lowercased()
            guard c.count == 8, c.allSatisfy({ $0.isHexDigit }), !out.contains(c) else { continue }
            out.append(c)
            if out.count == maxLinks { break }
        }
        return out
    }

    func pump() {
        guard central?.state == .poweredOn else { return }
        let chosen = chosenCodes()
        // Codes the console dropped: hang up those phones only.
        for (code, l) in links where !chosen.contains(code) {
            if let p = l.peripheral { central.cancelPeripheralConnection(p) }
            links[code] = nil
            emit(["event": "link", "code": code, "value": "removed"])
        }
        for code in chosen {
            let l = links[code] ?? { let n = PLink(code: code, root: dir); links[code] = n; return n }()
            pumpLink(l)
        }
    }

    func pumpLink(_ l: PLink) {
        if let peripheral = byCode[l.code] {
            if let current = l.peripheral, current != peripheral, current.state != .connected {
                l.peripheral = nil
                l.reset()
            }
            let p = l.peripheral ?? peripheral
            let down = p.state != .connected && p.state != .connecting
            if down && Date() >= l.nextConnect {
                l.scheduleRedial()
                l.peripheral = p
                p.delegate = self
                central.connect(p, options: nil)
                setState(l, "connecting")
            }
        }
        guard let p = l.peripheral, p.state == .connected, let signChar = l.signChar, l.sigReady else { return }
        if Date().timeIntervalSince(l.lastRSSI) > 3 {
            l.lastRSSI = Date()
            p.readRSSI()
        }
        // One lost reply is resent on the same link. A second one in a row
        // means the phone closed its GATT server while macOS kept the old
        // link and stale handles: drop this link (only) and dial again.
        if l.inflight != 0 {
            if Date().timeIntervalSince(l.inflightAt) > 8 {
                l.inflight = 0
                l.timeouts += 1
                if l.inflightOp == 0x50 {
                    l.helloMisses += 1
                    emit(["event": "hello-timeout", "code": l.code, "count": l.helloMisses])
                    if l.helloMisses >= helloMissLimit {
                        drop(l, "hello-timeouts")
                        return
                    }
                }
                if l.timeouts >= 2 {
                    drop(l, "no-reply")
                    return
                }
            } else {
                return
            }
        }
        if Date().timeIntervalSince(l.lastKeys) > 10, let keysChar = l.keysChar {
            l.lastKeys = Date()
            p.readValue(for: keysChar)
        }
        if Date().timeIntervalSince(l.lastStatus) > 2, let granter = l.granterChar {
            p.readValue(for: granter)
        }
        if Date().timeIntervalSince(l.lastStatus) > 2,
           let statusChar = l.statusChar,
           let status = try? Data(contentsOf: dir.appendingPathComponent("status.frame")),
           !status.isEmpty {
            l.lastStatus = Date()
            p.writeValue(status, for: statusChar, type: .withResponse)
        }
        guard let raw = try? Data(contentsOf: l.dir.appendingPathComponent("req.json")),
              let obj = try? JSONSerialization.jsonObject(with: raw) as? [String: Any],
              let id = (obj["id"] as? NSNumber)?.uint64Value,
              id != 0, id != l.lastReq,
              let frame = obj["frame"] as? String,
              let bytes = Data(base64Encoded: frame)
        else { return }
        l.inflight = id
        l.inflightAt = Date()
        l.inflightOp = bytes.first ?? 0
        p.writeValue(bytes, for: signChar, type: .withResponse)
    }

    func peripheral(_ peripheral: CBPeripheral, didReadRSSI RSSI: NSNumber, error: Error?) {
        guard error == nil, let l = link(for: peripheral) else { return }
        emit(["event": "seen", "code": l.code, "rssi": RSSI.intValue])
    }

    func peripheral(_ peripheral: CBPeripheral, didWriteValueFor characteristic: CBCharacteristic, error: Error?) {
        guard characteristic.uuid == signUUID, error != nil, let l = link(for: peripheral) else { return }
        // The frame never left. Allow the same id to be sent again.
        l.inflight = 0
    }

    func centralManager(_ central: CBCentralManager, didConnect peripheral: CBPeripheral) {
        guard let l = link(for: peripheral) else {
            central.cancelPeripheralConnection(peripheral)
            return
        }
        peripheral.delegate = self
        peripheral.discoverServices([serviceUUID])
        setState(l, "connected")
    }

    func centralManager(_ central: CBCentralManager, didFailToConnect peripheral: CBPeripheral, error: Error?) {
        guard let l = link(for: peripheral) else { return }
        forget(peripheral)
        l.peripheral = nil
        l.reset()
        l.scheduleRedial()
        setState(l, "down")
    }

    func centralManager(_ central: CBCentralManager, didDisconnectPeripheral peripheral: CBPeripheral, error: Error?) {
        guard let l = link(for: peripheral) else { return }
        forget(peripheral)
        l.peripheral = nil
        l.reset()
        l.scheduleRedial()
        setState(l, "down")
    }

    // drop tears one link down so the next pump dials that phone again.
    func drop(_ l: PLink, _ why: String) {
        if let current = l.peripheral {
            central?.cancelPeripheralConnection(current)
            forget(current)
        }
        l.peripheral = nil
        l.reset()
        l.backoff = 0
        l.nextConnect = Date()
        setState(l, "down")
        emit(["event": "dropped", "code": l.code, "why": why])
    }

    // The phone reopened its GATT server; the cached handles are gone.
    func peripheral(_ peripheral: CBPeripheral, didModifyServices invalidatedServices: [CBService]) {
        if invalidatedServices.contains(where: { $0.uuid == serviceUUID }), let l = link(for: peripheral) {
            drop(l, "services-changed")
        }
    }

    func forget(_ peripheral: CBPeripheral) {
        byCode = byCode.filter { $0.value != peripheral }
    }

    func peripheral(_ peripheral: CBPeripheral, didDiscoverServices error: Error?) {
        guard let service = peripheral.services?.first(where: { $0.uuid == serviceUUID }) else { return }
        peripheral.discoverCharacteristics([pubUUID, signUUID, sigUUID, granterUUID, statusUUID, keysUUID], for: service)
    }

    func peripheral(_ peripheral: CBPeripheral, didDiscoverCharacteristicsFor service: CBService, error: Error?) {
        guard let l = link(for: peripheral) else { return }
        for ch in service.characteristics ?? [] {
            if ch.uuid == pubUUID {
                peripheral.readValue(for: ch)
            } else if ch.uuid == signUUID {
                l.signChar = ch
            } else if ch.uuid == sigUUID {
                l.sigChar = ch
                peripheral.setNotifyValue(true, for: ch)
            } else if ch.uuid == granterUUID {
                l.granterChar = ch
                peripheral.setNotifyValue(true, for: ch)
                peripheral.readValue(for: ch)
            } else if ch.uuid == statusUUID {
                l.statusChar = ch
            } else if ch.uuid == keysUUID {
                l.keysChar = ch
                l.lastKeys = Date()
                peripheral.readValue(for: ch)
                if ch.properties.contains(.notify) { peripheral.setNotifyValue(true, for: ch) }
            }
        }
    }

    func peripheral(_ peripheral: CBPeripheral, didUpdateNotificationStateFor characteristic: CBCharacteristic, error: Error?) {
        if characteristic.uuid == sigUUID, error == nil, let l = link(for: peripheral) {
            l.sigReady = true
            l.backoff = 0
            setState(l, "up")
        }
    }

    func peripheral(_ peripheral: CBPeripheral, didUpdateValueFor characteristic: CBCharacteristic, error: Error?) {
        guard let value = characteristic.value, let l = link(for: peripheral) else { return }
        if characteristic.uuid == pubUUID, value.count == 32 {
            let hex = value.map { String(format: "%02x", $0) }.joined()
            try? Data(hex.utf8).write(to: l.dir.appendingPathComponent("pub.hex"))
            // Root copies are the legacy single-phone view: only the primary
            // (first chosen) link writes them, so phones never overwrite each other.
            if isPrimary(l) { try? Data(hex.utf8).write(to: dir.appendingPathComponent("pub.hex")) }
            emit(["event": "pubkey", "code": l.code, "hex": hex])
            return
        }
        if characteristic.uuid == keysUUID {
            if value.count == 1 && value.first == 0x4E {
                l.lastKeys = Date()
                peripheral.readValue(for: characteristic)
                return
            }
            publishKeys(l, value)
            return
        }
        if characteristic.uuid == granterUUID {
            guard let text = String(data: value, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines),
                  text.hasPrefix("terp1"), text.count <= 90
            else { return }
            try? Data(text.utf8).write(to: l.dir.appendingPathComponent("granter"))
            // Root copies are the legacy single-phone view: only the primary
            // (first chosen) link writes them, so phones never overwrite each other.
            if isPrimary(l) { try? Data(text.utf8).write(to: dir.appendingPathComponent("granter")) }
            emit(["event": "granter", "code": l.code, "address": text])
            return
        }
        if characteristic.uuid == sigUUID {
            var sig = value
            if sig.count == 65 && sig[0] == 0x11 {
                sig = sig.dropFirst()
            } else if sig.first != 0x11 {
                sig = value
            }
            guard !sig.isEmpty, l.inflight != 0 else { return }
            let answered = l.inflight
            l.lastReq = answered
            l.inflight = 0
            l.timeouts = 0
            if value.first == 0x51 { l.helloMisses = 0 }
            let body: [String: Any] = ["id": answered, "sig": sig.base64EncodedString()]
            if let data = try? JSONSerialization.data(withJSONObject: body) {
                try? data.write(to: l.dir.appendingPathComponent("resp.json"), options: .atomic)
            }
            if sig.first == 0x5f {
                var ev: [String: Any] = ["event": "refused", "code": l.code, "id": answered]
                if sig.count >= 2 { ev["refusal"] = Int(sig[sig.startIndex + 1]) }
                emit(ev)
            } else {
                emit(["event": "signed", "code": l.code, "id": answered])
            }
        }
    }

    struct PhoneKey { let id: String; let chain: String; let label: String; let pub: String; var name: String? = nil }

    static func parseKeys(_ v: Data) -> [PhoneKey]? {
        let b = [UInt8](v)
        guard b.count >= 2, b[0] == 1 else { return nil }
        var i = 2
        var out: [PhoneKey] = []
        func hex(_ s: ArraySlice<UInt8>) -> String { s.map { String(format: "%02x", $0) }.joined() }
        for _ in 0..<Int(b[1]) {
            guard i + 9 <= b.count else { return nil }
            let id = hex(b[i..<i + 8]); i += 8
            let cl = Int(b[i]); i += 1
            guard i + cl + 1 <= b.count else { return nil }
            let chain = String(decoding: b[i..<i + cl], as: UTF8.self); i += cl
            let ll = Int(b[i]); i += 1
            guard i + ll + 32 <= b.count else { return nil }
            let label = String(decoding: b[i..<i + ll], as: UTF8.self); i += ll
            let pub = hex(b[i..<i + 32]); i += 32
            out.append(PhoneKey(id: id, chain: chain, label: label, pub: pub))
        }
        // Optional name trailer: 'N' [count] { len u8, UTF-8 name }, entry order.
        // Absent on older zigner; a malformed trailer is ignored, not fatal.
        if i + 2 <= b.count, b[i] == 0x4E, Int(b[i + 1]) == out.count {
            var j = i + 2
            var names: [String] = []
            for _ in 0..<out.count {
                guard j < b.count else { break }
                let nl = Int(b[j]); j += 1
                guard nl <= 40, j + nl <= b.count,
                      let n = String(bytes: b[j..<j + nl], encoding: .utf8) else { break }
                names.append(n); j += nl
            }
            if names.count == out.count {
                for k in 0..<out.count { out[k].name = names[k] }
            }
        }
        return out
    }

    /// Directory names a key is published under. keylink.go reads
    /// keys/<label>/pub.hex where the engine's label is the config chain id
    /// ("/" -> "_"), so a chain held by exactly one key also gets its chain
    /// id. Every key gets its phone label and its 16-hex key id.
    static func safeName(_ s: String) -> String {
        let ok = s.map { $0.isLetter || $0.isNumber || $0 == "-" || $0 == "_" || $0 == "." ? $0 : "_" }
        let t = String(ok).trimmingCharacters(in: CharacterSet(charactersIn: "."))
        return t.isEmpty ? "" : t
    }

    /// Each phone's keys go to its own drop, and the union of every linked
    /// phone's keys to <dir>/keys and <dir>/keys.json, so the KMS resolves a
    /// configured key whichever phone holds it.
    func publishKeys(_ l: PLink, _ value: Data) {
        guard value != l.lastKeysBody, let keys = Scan.parseKeys(value) else { return }
        l.lastKeysBody = value
        l.keys = keys
        writeKeys(keys, to: l.dir)
        var all: [PhoneKey] = []
        for code in links.keys.sorted() {
            for k in links[code]!.keys where !all.contains(where: { $0.id == k.id }) { all.append(k) }
        }
        writeKeys(all, to: dir)
        emit(["event": "keys", "code": l.code, "count": keys.count, "ids": keys.map { $0.id }])
    }

    func writeKeys(_ keys: [PhoneKey], to base: URL) {
        let root = base.appendingPathComponent("keys")
        try? FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        var listed: [[String: Any]] = []
        for k in keys {
            var names = [k.id, Scan.safeName(k.label)]
            if keys.filter({ $0.chain == k.chain }).count == 1 {
                names.append(Scan.safeName(k.chain.replacingOccurrences(of: "/", with: "_")))
            }
            for name in Set(names) where !name.isEmpty {
                let d = root.appendingPathComponent(name)
                try? FileManager.default.createDirectory(at: d, withIntermediateDirectories: true)
                try? Data(k.pub.utf8).write(to: d.appendingPathComponent("pub.hex"), options: .atomic)
            }
            var row: [String: Any] = ["key_id": k.id, "chain_id": k.chain, "label": k.label, "pub": k.pub]
            if let n = k.name { row["name"] = n }
            listed.append(row)
        }
        if let data = try? JSONSerialization.data(withJSONObject: ["keys": listed], options: [.prettyPrinted, .sortedKeys]) {
            try? data.write(to: base.appendingPathComponent("keys.json"), options: .atomic)
        }
    }

    func emit(_ obj: [String: Any]) {
        guard let data = try? JSONSerialization.data(withJSONObject: obj),
              var line = String(data: data, encoding: .utf8)
        else { return }
        line.append("\n")
        let url = URL(fileURLWithPath: ProcessInfo.processInfo.environment["KMS_BLE_LOG"] ?? "/tmp/kms-ble-events.jsonl")
        if let handle = try? FileHandle(forWritingTo: url) {
            _ = try? handle.seekToEnd()
            try? handle.write(contentsOf: Data(line.utf8))
            try? handle.close()
        } else {
            try? Data(line.utf8).write(to: url)
        }
        print(line, terminator: "")
        fflush(stdout)
    }
}

final class App: NSObject, NSApplicationDelegate {
    let scan = Scan()
    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.accessory)
        scan.start()
    }
}

let app = NSApplication.shared
let delegate = App()
app.delegate = delegate
app.setActivationPolicy(.accessory)
app.run()
