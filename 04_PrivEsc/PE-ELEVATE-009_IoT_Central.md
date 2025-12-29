# [PE-ELEVATE-009]: IoT Central Device Group Escalation

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | PE-ELEVATE-009 |
| **MITRE ATT&CK v18.1** | [Abuse Elevation Control Mechanism (T1548)](https://attack.mitre.org/techniques/T1548/) |
| **Tactic** | Privilege Escalation |
| **Platforms** | Azure IoT Central |
| **Severity** | **Medium** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** Azure IoT Central uses "Device Groups" to apply jobs (updates/commands) to sets of devices. Permissions are often scoped to specific Device Groups. However, Device Groups are dynamic queries (e.g., `SELECT * FROM devices WHERE organization = 'Seattle'`). If an attacker has permissions to *edit* a device's properties (e.g., changing its "Organization" or "Location" tag), they can move a device *into* a Device Group they control, or modify a device to *leave* a restrictive group. More dangerously, if they can edit the Device Group query itself, they can expand their scope to manage *all* devices.
- **Attack Surface:** Device Properties / Group Queries.
- **Business Impact:** **Operational Technology (OT) Impact**.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** IoT Central Operator (Scoped).
- **Tools:**
    - Azure CLI / IoT Central UI

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Check Group Logic**
View the query for the "Admin Devices" group (e.g., `type = 'gateway'`).

**Step 2: Modify Device**
Change a controlled device's property to match the high-privilege group.
```bash
az iot central device update --app-id <AppID> --device-id <MyDevice> --content '{"type": "gateway"}'
```

**Step 3: Execute Job**
Now the device is part of the "Gateway" group, potentially receiving sensitive firmware updates or commands intended for gateways.

## 5. DETECTION (Blue Team Operations)

#### 5.1 IoT Central Logs
| Source | Event | Filter Logic |
|---|---|---|
| **Audit** | `UpdateDevice` | Property changes that trigger group membership changes. |
| **Audit** | `UpdateDeviceGroup` | Modification of the group query definition. |

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **Static Groups:** Use static lists of devices for sensitive operations rather than dynamic queries.
*   **Property Locking:** Restrict who can write to properties like `type`, `location`, or `organization`.

## 7. ATTACK CHAIN
> **Preceding Technique:** [IA-CLOUD-004]
> **Next Logical Step:** [PE-EXPLOIT-007]
