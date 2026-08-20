// Mock network-segment labels for the mock client IP ranges used by
// backend/mock_data.py (CLIENT_SUBNETS). These are private/LAN addresses, so
// a "which internal segment" label is more honest than fake geolocation.
const SEGMENTS: Record<string, string> = {
  "192.168.1": "Corporate LAN",
  "192.168.2": "Guest WiFi",
  "10.0.0": "Server VLAN",
  "10.0.5": "Engineering VLAN",
  "172.16.4": "IoT / Devices Segment",
};

export function mockNetworkSegment(ip: string): string {
  const prefix = ip.split(".").slice(0, 3).join(".");
  return SEGMENTS[prefix] ?? "Unclassified Segment";
}
