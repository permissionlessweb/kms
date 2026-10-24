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
    var lastReq: UInt64 = 0
    var inflight: UInt64 = 0
    var inflightAt = Date.distantPast
    var sigReady = false
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
        // A lost reply must not drop the radio. The same request is sent again.
        if inflight != 0 {
            if Date().timeIntervalSince(inflightAt) > 8 {
                inflight = 0
            } else {
                return
            }
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
        sigReady = false
        if connected == peripheral {
            connected = nil
            connectedCode = ""
            signChar = nil
            statusChar = nil
            pubChar = nil
        }
        nextConnect = Date().addingTimeInterval(1.2)
        emit(["event": "link", "value": "disconnected"])
    }

    func forget(_ peripheral: CBPeripheral) {
        byCode = byCode.filter { $0.value != peripheral }
    }

    func peripheral(_ peripheral: CBPeripheral, didDiscoverServices error: Error?) {
        guard let service = peripheral.services?.first(where: { $0.uuid == serviceUUID }) else { return }
        peripheral.discoverCharacteristics([pubUUID, signUUID, sigUUID, granterUUID, statusUUID], for: service)
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
            let body: [String: Any] = ["id": answered, "sig": sig.base64EncodedString()]
            if let data = try? JSONSerialization.data(withJSONObject: body) {
                try? data.write(to: dir.appendingPathComponent("resp.json"))
            }
            emit(["event": "signed", "id": lastReq])
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
