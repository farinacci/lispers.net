//
// NetworkName.swift
//
// Best-effort human-readable name for the active RLOC interface: the Wi-Fi SSID
// (en0) or the cellular carrier (pdp_ip0). The SSID is gated by iOS — it needs
// the "Access WiFi Information" entitlement AND Location-When-In-Use permission
// (SSID is treated as location data) — so this degrades gracefully to nil when
// unavailable (e.g. the simulator, or before permission is granted).
//

import Foundation
import Combine
import NetworkExtension
import CoreLocation
import CoreTelephony
import Network

final class NetworkName: NSObject, ObservableObject {
    static let shared = NetworkName()

    @Published var wifiSSID: String?
    @Published var cellularName: String?       // e.g. "5G", "T-Mobile LTE"

    private let location = CLLocationManager()
    private let cell = CTTelephonyNetworkInfo()
    private let pathMonitor = NWPathMonitor()

    private override init() {
        super.init()
        location.delegate = self
        // Re-read whenever the network path changes (Wi-Fi <-> cellular, SSID
        // change) so the label tracks the live interface instead of going stale.
        pathMonitor.pathUpdateHandler = { [weak self] _ in
            DispatchQueue.main.async { self?.refresh() }
        }
        pathMonitor.start(queue: DispatchQueue(label: "lisp.netname.path"))
        refresh()
    }

    func refresh() {
        // Carrier name is usually withheld on iOS 16+, but the radio access
        // technology ("5G"/"LTE"/...) is available and is the useful bit.
        let carrier = cell.serviceSubscriberCellularProviders?.values
            .compactMap { $0.carrierName }
            .first { !$0.isEmpty && $0 != "--" && $0 != "Carrier" }
        let rat = cell.serviceCurrentRadioAccessTechnology?.values
            .compactMap { Self.ratName($0) }.first
        let name = [carrier, rat].compactMap { $0 }.joined(separator: " ")
        cellularName = name.isEmpty ? nil : name

        // Wi-Fi SSID needs location permission + the wifi-info entitlement.
        switch location.authorizationStatus {
        case .authorizedWhenInUse, .authorizedAlways: fetchSSID()
        case .notDetermined: location.requestWhenInUseAuthorization()
        default: DispatchQueue.main.async { self.wifiSSID = nil }
        }
    }

    private static func ratName(_ rat: String) -> String? {
        switch rat {
        case CTRadioAccessTechnologyNR, CTRadioAccessTechnologyNRNSA: return "5G"
        case CTRadioAccessTechnologyLTE: return "LTE"
        case CTRadioAccessTechnologyWCDMA, CTRadioAccessTechnologyHSDPA,
             CTRadioAccessTechnologyHSUPA, CTRadioAccessTechnologyCDMAEVDORev0,
             CTRadioAccessTechnologyCDMAEVDORevA, CTRadioAccessTechnologyCDMAEVDORevB,
             CTRadioAccessTechnologyeHRPD: return "3G"
        case CTRadioAccessTechnologyGPRS, CTRadioAccessTechnologyEdge,
             CTRadioAccessTechnologyCDMA1x: return "2G"
        default: return nil
        }
    }

    private func fetchSSID() {
        NEHotspotNetwork.fetchCurrent { [weak self] net in
            DispatchQueue.main.async { self?.wifiSSID = net?.ssid }
        }
    }
}

extension NetworkName: CLLocationManagerDelegate {
    func locationManagerDidChangeAuthorization(_ m: CLLocationManager) {
        switch m.authorizationStatus {
        case .authorizedWhenInUse, .authorizedAlways: fetchSSID()
        default: break
        }
    }
}
