# Feature Plan: Custom DNS Server Per Reservation

## Overview

Add the ability to specify custom DNS server(s) for individual DHCP reservations. This allows specific devices to receive different DNS servers than the subnet default when they request a DHCP lease.

## Background

Kea DHCP supports per-reservation DHCP options via the `option-data` array within host reservations. The DNS servers option is DHCP option 6 (`domain-name-servers` in Kea). Options defined at the host level take precedence over subnet-level and global-level options.

### Kea Syntax Reference

```json
{
  "hw-address": "aa:bb:cc:dd:ee:ff",
  "ip-address": "192.168.1.100",
  "hostname": "custom-dns-device",
  "option-data": [
    {
      "name": "domain-name-servers",
      "data": "8.8.8.8, 8.8.4.4"
    }
  ]
}
```

**Sources:**
- [Kea DHCPv4 reservations example](https://github.com/isc-projects/kea/blob/master/doc/examples/kea4/reservations.json)
- [Using Host Reservations in Kea](https://kb.isc.org/docs/what-are-host-reservations-how-to-use-them)

---

## Implementation Plan

### 1. Backend Changes

#### 1.1 Update `kea_client.py`

**File:** `kea_client.py`

**Changes:**

a) Modify `create_reservation()` method to accept and pass `option-data`:
   - Add optional `option_data` parameter (list of option dictionaries)
   - Include `option-data` in the reservation payload when provided
   - Works for both `reservation-add` command and `config-set` fallback

b) Modify `get_reservations()` to extract `option-data` from existing reservations:
   - Parse `option-data` array from each reservation in config
   - Extract `domain-name-servers` specifically for easy frontend access

c) Modify `_create_reservation_via_config()` fallback to include `option-data`

#### 1.2 Update `app.py`

**File:** `app.py`

**Changes:**

a) Update `/api/reservations` POST endpoint:
   - Accept optional `dns-servers` field (string, comma-separated IPs)
   - Validate DNS server IPs format
   - Convert to Kea `option-data` format before calling `kea_client`

b) Update `/api/promote` POST endpoint:
   - Accept optional `dns-servers` field
   - Pass through to reservation creation

c) Update `/api/reservations` GET endpoint:
   - Include `dns-servers` in response for each reservation (extracted from `option-data`)

d) Update `/api/reservations/export` endpoint:
   - Include `option-data` or simplified `dns-servers` field in export

e) Update `/api/reservations/import` endpoint:
   - Support both `option-data` format and simplified `dns-servers` format
   - Validate DNS IPs during import

f) Add new validation helper:
   - `validate_dns_servers(dns_string)` - validate comma-separated DNS IPs

g) Update Swagger/OpenAPI documentation for all affected endpoints

---

### 2. Frontend Changes

#### 2.1 Update Promote Lease Modal

**File:** `templates/index.html`

**Location:** `#promoteModal`

**Changes:**
- Add optional "Custom DNS Servers" input field below hostname
- Placeholder text: "e.g., 8.8.8.8, 8.8.4.4 (leave empty for subnet default)"
- Add help text explaining the feature
- Update `promoteLease()` JavaScript function to send `dns-servers` field

#### 2.2 Update Add Reservation Modal

**Location:** `#addReservationModal`

**Changes:**
- Add "Custom DNS Servers" input field
- Same format and validation as promote modal
- Update `addReservation()` JavaScript function

#### 2.3 Update Edit Reservation Modal

**Location:** `#editReservationModal`

**Changes:**
- Add "Custom DNS Servers" input field
- Pre-populate with existing DNS servers when editing
- Update `saveEditReservation()` JavaScript function

#### 2.4 Update Reservations Table

**Location:** `#reservationsModal` table

**Changes:**
- Add "DNS" column (or icon indicator) showing custom DNS if set
- Show dash or "Default" when no custom DNS
- Consider using a tooltip or collapsible detail for long DNS lists

#### 2.5 JavaScript Helpers

**Changes:**
- Add `validateDnsServers(input)` function for client-side validation
- Update `loadReservations()` to handle new `dns-servers` field
- Update `exportReservations()` to include DNS data

---

### 3. Data Model Updates

#### 3.1 Internal Reservation Object

**Current:**
```json
{
  "ip-address": "192.168.1.100",
  "hw-address": "aa:bb:cc:dd:ee:01",
  "hostname": "device1",
  "subnet-id": 1,
  "subnet": "192.168.1.0/24"
}
```

**New:**
```json
{
  "ip-address": "192.168.1.100",
  "hw-address": "aa:bb:cc:dd:ee:01",
  "hostname": "device1",
  "subnet-id": 1,
  "subnet": "192.168.1.0/24",
  "dns-servers": "8.8.8.8, 8.8.4.4",
  "option-data": [
    {
      "name": "domain-name-servers",
      "data": "8.8.8.8, 8.8.4.4"
    }
  ]
}
```

The `dns-servers` field is a simplified view for the UI. The `option-data` field is the full Kea format (included in export for compatibility).

#### 3.2 Update `sample_reservations.json`

Add example with custom DNS:
```json
{
  "ip-address": "192.168.1.103",
  "hw-address": "aa:bb:cc:dd:ee:04",
  "hostname": "custom-dns-device",
  "subnet-id": 1,
  "subnet": "192.168.1.0/24",
  "dns-servers": "1.1.1.1, 1.0.0.1"
}
```

---

### 4. Validation Requirements

#### 4.1 DNS Server Input Validation

- Accept comma or comma-space separated IPv4 addresses
- Validate each IP is a valid IPv4 format
- Allow 1-4 DNS servers (standard DHCP recommendation)
- Empty string = no custom DNS (use subnet default)
- Reject invalid IPs with clear error message

#### 4.2 Example Valid Inputs
- `8.8.8.8`
- `8.8.8.8, 8.8.4.4`
- `1.1.1.1,1.0.0.1,9.9.9.9`

#### 4.3 Example Invalid Inputs
- `not-an-ip` (invalid format)
- `256.1.1.1` (octet out of range)
- `8.8.8.8,` (trailing comma)

---

### 5. Testing Plan

#### 5.1 Manual Testing Checklist

- [ ] Create reservation with custom DNS via promote flow
- [ ] Create reservation with custom DNS via add modal
- [ ] Edit existing reservation to add custom DNS
- [ ] Edit existing reservation to remove custom DNS
- [ ] Edit existing reservation to modify custom DNS
- [ ] View reservations shows DNS column correctly
- [ ] Export includes DNS data
- [ ] Import with DNS data works correctly
- [ ] Import without DNS data still works (backward compatible)
- [ ] Invalid DNS input shows validation error
- [ ] Device receives custom DNS when leasing (test with actual Kea)

#### 5.2 Edge Cases

- [ ] Reservation with only DNS (no hostname)
- [ ] Multiple DNS servers (2, 3, 4)
- [ ] Single DNS server
- [ ] Switching from custom DNS to default (clear field)
- [ ] Import file with mix of DNS/no-DNS reservations

---

### 6. File Change Summary

| File | Type | Changes |
|------|------|---------|
| `kea_client.py` | Backend | Add option-data support to create/get reservations |
| `app.py` | Backend | Add dns-servers parameter to API endpoints, validation |
| `templates/index.html` | Frontend | Add DNS fields to 3 modals, add DNS column to table |
| `sample_reservations.json` | Example | Add example with custom DNS |

---

### 7. Future Considerations (Out of Scope)

These are not part of the current implementation but could be added later:

- Support for other per-reservation DHCP options (NTP servers, domain name, etc.)
- IPv6 DNS servers (DHCPv6 option 23)
- DNS server presets (e.g., "Google DNS", "Cloudflare DNS" dropdown)
- Bulk DNS assignment to multiple reservations

---

### 8. Implementation Order

1. **Backend first:** Update `kea_client.py` with option-data support
2. **API layer:** Update `app.py` endpoints and validation
3. **Frontend forms:** Add DNS fields to all three modals
4. **Frontend display:** Add DNS column to reservations table
5. **Import/Export:** Update sample file and ensure backward compatibility
6. **Testing:** Full manual testing with actual Kea server

---

## Risks and Mitigations

| Risk | Mitigation |
|------|------------|
| Kea version incompatibility | Test with common Kea versions (2.0+). The `option-data` feature has been stable since Kea 1.x |
| `reservation-add` command may not support option-data | Fallback to `config-set` already exists in codebase |
| UI clutter with new field | Keep field collapsed/optional, use good placeholder text |
| Import breaking for old exports | Support both formats, DNS field is optional |
