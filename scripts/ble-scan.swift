import AppKit
import CoreBluetooth
import Foundation

/// Scans for a Zigner advertisement, then connects only to the pairing code
/// the console accepted. Sign bytes go to the phone. The signature comes back
/// on a notify. This process does not hold the consensus private key.
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

final class Scan: NSObject, CBCentralManagerDelegate, CBPeripheralDelegate {
    var central: CBCentralManager!
    var byCode: [String: CBPeripheral] = [:]
    var connected: CBPeripheral?
    var connectedCode = ""
    var pubChar: CBCharacteristic?
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
    var sigReady = false
    var timeouts = 0
    /// Noise hellos (0x50) in a row that got no reply. The phone can keep
    /// answering other frames from a dead session, so this is counted apart
    /// from `timeouts` and only a hello reply (0x51) clears it.
    var helloMisses = 0
    let helloMissLimit = 3
    var inflightOp: UInt8 = 0
    var nextConnect = Date.distantPast
    var lastStatus = Date.distantPast
    let dir: URL = {
        let path = ProcessInfo.processInfo.environment["KMS_BLE_DIR"] ?? "/tmp/kms-ble"
        let url = URL(fileURLWithPath: path)
        try? FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }()

    func start() {
        central = CBCentralManager(
            delegate: self,
            queue: nil,
            options: [CBCentralManagerOptionShowPowerAlertKey: true]
        )
        Timer.scheduledTimer(withTimeInterval: 0.05, repeats: true) { [weak self] _ in
            self?.pump()
        }
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
        if let previous, previous != peripheral, connected == previous {
            central.cancelPeripheralConnection(previous)
            connected = nil
            connectedCode = ""
            signChar = nil
            statusChar = nil
            nextConnect = Date()
        }
        emit(["event": "seen", "code": code, "rssi": RSSI.intValue])
    }

    func pump() {
        guard central?.state == .poweredOn else { return }
        let chosen = (try? String(contentsOf: dir.appendingPathComponent("chosen"), encoding: .utf8))?
            .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        if chosen.isEmpty {
            return
        }
        if let peripheral = byCode[chosen] {
            if let current = connected, current != peripheral {
                central.cancelPeripheralConnection(current)
                connected = nil
                connectedCode = ""
                signChar = nil
                statusChar = nil
            }
            let down = peripheral.state != .connected && peripheral.state != .connecting
            if down && Date() >= nextConnect {
                nextConnect = Date().addingTimeInterval(1.2)
                peripheral.delegate = self
                central.connect(peripheral, options: nil)
                emit(["event": "link", "value": "connecting"])
            }
        }
        guard connected != nil, signChar != nil, sigReady else { return }
        // One lost reply is resent on the same link. A second one in a row
        // means the phone closed its GATT server (Stop, reinstall, radio
        // restart) while macOS kept the old link and stale handles, so drop
        // the link and dial the phone again.
        if inflight != 0 {
            if Date().timeIntervalSince(inflightAt) > 8 {
                inflight = 0
                timeouts += 1
                if inflightOp == 0x50 {
                    helloMisses += 1
                    emit(["event": "hello-timeout", "count": helloMisses])
                    if helloMisses >= helloMissLimit {
                        drop("hello-timeouts")
                        return
                    }
                }
                if timeouts >= 2 {
                    drop("no-reply")
                    return
                }
            } else {
                return
            }
        }
        if Date().timeIntervalSince(lastKeys) > 10, let keysChar {
            lastKeys = Date()
            connected?.readValue(for: keysChar)
        }
        if Date().timeIntervalSince(lastStatus) > 2, let granter = granterChar {
            connected?.readValue(for: granter)
        }
        if Date().timeIntervalSince(lastStatus) > 2,
           let statusChar,
           let status = try? Data(contentsOf: dir.appendingPathComponent("status.frame")),
           !status.isEmpty {
            lastStatus = Date()
            connected?.writeValue(status, for: statusChar, type: .withResponse)
        }
        guard let raw = try? Data(contentsOf: dir.appendingPathComponent("req.json")),
              let obj = try? JSONSerialization.jsonObject(with: raw) as? [String: Any],
              let id = (obj["id"] as? NSNumber)?.uint64Value,
              id != 0, id != lastReq,
              let frame = obj["frame"] as? String,
              let bytes = Data(base64Encoded: frame)
        else { return }
        inflight = id
        inflightAt = Date()
        inflightOp = bytes.first ?? 0
        connected?.writeValue(bytes, for: signChar!, type: .withResponse)
    }

    func peripheral(_ peripheral: CBPeripheral, didWriteValueFor characteristic: CBCharacteristic, error: Error?) {
        guard characteristic.uuid == signUUID, error != nil else { return }
        // The frame never left. Allow the same id to be sent again.
        inflight = 0
    }

    func centralManager(_ central: CBCentralManager, didConnect peripheral: CBPeripheral) {
        connected = peripheral
        peripheral.delegate = self
        peripheral.discoverServices([serviceUUID])
        emit(["event": "link", "value": "connected"])
    }

    func centralManager(_ central: CBCentralManager, didFailToConnect peripheral: CBPeripheral, error: Error?) {
        forget(peripheral)
        connectedCode = ""
        nextConnect = Date().addingTimeInterval(1.2)
        emit(["event": "link", "value": "connect-failed"])
    }

    func centralManager(_ central: CBCentralManager, didDisconnectPeripheral peripheral: CBPeripheral, error: Error?) {
        forget(peripheral)
        inflight = 0
        timeouts = 0
        sigReady = false
        if connected == peripheral {
            connected = nil
            connectedCode = ""
            signChar = nil
            statusChar = nil
            pubChar = nil
            keysChar = nil
        }
        nextConnect = Date().addingTimeInterval(1.2)
        emit(["event": "link", "value": "disconnected"])
    }

    // drop tears the link down so the next pump connects again.
    func drop(_ why: String) {
        timeouts = 0
        helloMisses = 0
        inflight = 0
        sigReady = false
        if let current = connected {
            central?.cancelPeripheralConnection(current)
            forget(current)
        }
        connected = nil
        connectedCode = ""
        signChar = nil
        statusChar = nil
        pubChar = nil
        keysChar = nil
        nextConnect = Date()
        emit(["event": "link", "value": "dropped-" + why])
    }

    // The phone reopened its GATT server; the cached handles are gone.
    func peripheral(_ peripheral: CBPeripheral, didModifyServices invalidatedServices: [CBService]) {
        if invalidatedServices.contains(where: { $0.uuid == serviceUUID }) {
            drop("services-changed")
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
        for ch in service.characteristics ?? [] {
            if ch.uuid == pubUUID {
                pubChar = ch
                peripheral.readValue(for: ch)
            } else if ch.uuid == signUUID {
                signChar = ch
            } else if ch.uuid == sigUUID {
                sigChar = ch
                peripheral.setNotifyValue(true, for: ch)
            } else if ch.uuid == granterUUID {
                granterChar = ch
                peripheral.setNotifyValue(true, for: ch)
                peripheral.readValue(for: ch)
            } else if ch.uuid == statusUUID {
                statusChar = ch
            } else if ch.uuid == keysUUID {
                keysChar = ch
                lastKeys = Date()
                peripheral.readValue(for: ch)
                // zigner with names notifies a one-byte 'N' hint on rename.
                if ch.properties.contains(.notify) { peripheral.setNotifyValue(true, for: ch) }
            }
        }
    }

    func peripheral(_ peripheral: CBPeripheral, didUpdateNotificationStateFor characteristic: CBCharacteristic, error: Error?) {
        if characteristic.uuid == sigUUID, error == nil {
            sigReady = true
        }
    }

    func peripheral(_ peripheral: CBPeripheral, didUpdateValueFor characteristic: CBCharacteristic, error: Error?) {
        guard let value = characteristic.value else { return }
        if characteristic.uuid == pubUUID, value.count == 32 {
            let hex = value.map { String(format: "%02x", $0) }.joined()
            try? Data(hex.utf8).write(to: dir.appendingPathComponent("pub.hex"))
            emit(["event": "pubkey", "hex": hex])
            return
        }
        if characteristic.uuid == keysUUID {
            if value.count == 1 && value.first == 0x4E {
                // Change hint: the listing itself may be longer than one notify.
                lastKeys = Date()
                peripheral.readValue(for: characteristic)
                return
            }
            publishKeys(value)
            return
        }
        if characteristic.uuid == granterUUID {
            guard let text = String(data: value, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines),
                  text.hasPrefix("terp1"), text.count <= 90
            else { return }
            try? Data(text.utf8).write(to: dir.appendingPathComponent("granter"))
            emit(["event": "granter", "address": text])
            return
        }
        if characteristic.uuid == sigUUID {
            var sig = value
            if sig.count == 65 && sig[0] == 0x11 {
                sig = sig.dropFirst()
            } else if sig.first != 0x11 {
                sig = value
            }
            guard !sig.isEmpty, inflight != 0 else { return }
            let answered = inflight
            lastReq = answered
            inflight = 0
            timeouts = 0
            if value.first == 0x51 { helloMisses = 0 }
            let body: [String: Any] = ["id": answered, "sig": sig.base64EncodedString()]
            if let data = try? JSONSerialization.data(withJSONObject: body) {
                try? data.write(to: dir.appendingPathComponent("resp.json"))
            }
            if sig.first == 0x5f {
                // Refusal: bytes pass through untouched so kms parseRefusal reads the code
                // and floor itself (signing/bluetooth/refusal.go); this event is just for logs.
                var ev: [String: Any] = ["event": "refused", "id": lastReq]
                if sig.count >= 2 { ev["code"] = Int(sig[sig.startIndex + 1]) }
                emit(ev)
            } else {
                emit(["event": "signed", "id": lastReq])
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

    func publishKeys(_ value: Data) {
        guard value != lastKeysBody, let keys = Scan.parseKeys(value) else { return }
        lastKeysBody = value
        let root = dir.appendingPathComponent("keys")
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
            try? data.write(to: dir.appendingPathComponent("keys.json"), options: .atomic)
        }
        emit(["event": "keys", "count": keys.count, "ids": keys.map { $0.id }])
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
