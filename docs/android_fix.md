# Umbrella Client for Android — Background Work Configuration

To ensure the correct operation of `Umbrella Client` on Android, several settings must be configured to prevent the system from "killing" the application and dropping the tunnel.

> **⚠️ Warning** 
>  
> The changes described below may lead to **increased power consumption** and faster battery drain.
>  
> Before applying these settings, it is recommended to:
> - Study the purpose of each command/parameter
> - Remember or write down the original values of the settings being changed
> - Be prepared to revert the settings to their original state after testing
>  
> **The author is not responsible for any consequences caused by applying these settings.** 

---

## 1. Device Power Settings

### Disabling Optimization Restrictions

1. **Disable all optimization restrictions for** `Umbrella_client`
2. **Disable "Adaptive Battery" mode** 

### Developer Options Settings

In Developer Options:

* **Turn OFF** "Suspend execution for cached apps".
* **Turn ON** "Disable child process restrictions".

### Pinning the Application

On the open application window, activate the **"Lock" (Keep open)** option in the multitasking (recent apps) menu.

> **Note:** The menu names described above are specific to Samsung smartphones. On other devices, the names may differ, some parameters may be missing, or there may be additional ones. The principle remains the same: find all settings related to optimization and restrictions and exclude `Umbrella_client` from them.

---

## 2. ADB Commands

For stable background process operation, download any application that provides access to debugging and `abd shell` , and execute the following commands:

```bash
# Add the app to the Device Idle whitelist
adb shell dumpsys deviceidle whitelist +com.umbrella.client

# Allow running in the background
adb shell appops set com.umbrella.client RUN_IN_BACKGROUND allow

# Allow exact alarms
adb shell appops set com.umbrella.client SCHEDULE_EXACT_ALARM allow

# Increase the phantom process limit
adb shell device_config put activity_manager max_phantom_processes 2147483647

# Disable the cached apps freezer
adb shell settings put global cached_apps_freezer disabled
```

---

## 3. Before locking the screen, it is recommended to have the `Umbrella client` window open in the foreground.
