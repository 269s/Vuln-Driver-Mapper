# Custom Mapper (CorMem-based kdmapper)



This repository will allow you to create your own driver mapping solution using a custom version of a manual kdmapper. This mapper will use CORMEM.SYS (Teledyne/Sapera Memory Manager driver) as the vulnerable primitive instead of the more common intel driver (iqvw64e.sys).



This repository contains an example (root/) to show how you can interact with the CorMem driver within userland to map physical memory, translate addresses, read memory from processes.

This should only be used for EDUCATIONAL purposes and for authorised security research.

Loading vulnerable drivers, bypassing driver signing, manually mapping unsigned kernel drivers and accessing physical and/or process memory can cause instability, PatchGuard/BSODs, policy violations and may be illegal. Only use on your own systems or those you have been authorised to test.

## Project Structure

mapper.sln - Visual Studio solution file for the mapper project.

kdmapper/

src/main.cpp - Entry point of the mapper (map-workspace.exe). Loads the CorMem driver handle and maps the target .sys.

src/kdmapper.cpp include/kdmapper.hpp - Code for mapping the PE (Relocations, Imports, Cookie Fix, Kernel Alloc, Write Remote & DriverEntry).

`src/cormem_driver.{cpp,hpp}` - Kernel primitives using CorMem.

`lib/VMProtectSDK` - VMProtect SDK artefacts.

root/ - Example standalone CorMem code.

cordrv.hpp cordrv.cpp - Userland wrapper for interacting with the CorMem driver (\\.\CORMEM) via IOCTLs. Includes pool mapping, physical memory mapping, reading/writing physical memory, VA Translation, and discovering DTB(Processes).

main.cpp - Example code of how to setup the driver interface, discover DTBs, launch Notepad, find its base and DTB, translate a VA and read the PE header from physical memory.



Cormem.sys CorMem.dll - Binary files.

## How it Works

Load the vulnerable driver interface. We load a handle to the CorMem driver (\\.\CORMEM) so we can access the privileges provided.

Map the target driver. We will read the target .sys file from disk, relocate/clone it in userland, allocate it in kernel land, resolve imports and then write the image into kernel space.

Call DriverEntry. We call the DriverEntry function of the newly mapped driver.

[OPTIONAL] Unload the vulnerable driver. Depending on what flow you take you may want to unload the vulnerable driver once mapped. However the mapped image will usually stay loaded.

The example code in root/cordrv shows how to use the physical memory features of CorMem. Mapping physical pages, walking the page table, translating VAs, reading process memory.

## Build

Use Visual Studio (MSVC) with Windows SDK (x64).

Open mapper.sln.

Build the x64 target. The Release binaries can be found in the folders x64/Release/ & kdmapper/x64/Release/.

All the settings, dependencies and required SDK versions can be found in the .vcxproj files inside the kdmapper/ folder.

## Usage

### 1. Ensure CORMEM.SYS is available

You need to have access to the CorMem driver. You will need admin rights to load/unload a kernel driver.

Run the following command as Administrator (ensure the path is correct):

```powershell

sc.exe create CORMEM binPath= "C:\path\to\CORMEM.SYS" type= kernel start= demand

sc.exe start CORMEM

```

Once done you can stop/remove the driver with:

```powershell

sc.exe stop CORMEM

sc.exe delete CORMEM

```

### 2. Map the driver

Navigate to the output folder of the mapper and run:

```text

map-workspace.exe

```

The programme will expect a path to a .sys file. It will attempt to load the CorMem driver, map the target image and call DriverEntry.

You will see logs in the console showing the allocations, mapping, callbacks and clean up.

The current implementation will not free any memory allocated to the driver once DriverEntry has been called successfully, to avoid crashing any loaded mapped drivers.

### 3. CorMem Physical Memory Example

Build and run the example target from root/main.cpp. This will show you how to do the following:

Initialise CorMem Wrapper.

Discover system/process DTB.

Translate VA.

Read PE header from remote process.



## Recent CVE: CORMEM.SYS (CVE-2026-38194)

This project makes use of the CORMEM.SYS kernel driver which has been publicly disclosed as being vulnerable.

Component: Teledyne Digital Imaging Sapera Memory Manager (CORMEM.SYS) (v9.0.0.0 & below).

Issue: The IOCTL functions exposed by the driver have insufficient access checks/validations allowing a local user to gain powerful physical memory primitives.

Impact: This can be abused to allow arbitrary kernel/physical memory access from userland. This can then be used to escalate priviliges, tamper with protected processes, perform BYOVD attacks and manually map or utilise other methods to compromise the kernel.

Mitigations: Some systems may have mitigations in place such as vulnerable driver blocklists, HVCI, Secure Boot & EDR detections. This can also depend on the version of the vulnerable driver and policies in place.

### References

NVD/CVE: https://nvd.nist.gov/vuln/detail/CVE-2026-38194

Public PoC: https://github.com/4D4J/cormem-read-poc

Writeup: https://t0asts.com/cormem

LOLDrivers: https://www.loldrivers.io/drivers/a7c3e2d1-8f4b-4e6a-b5d9-3c1f0e7a9b82/

kdmapper Manual Mapping Info: https://github.com/TheCruZ/kdmapper



## Security Notice



This code is intended for Research/Test/Defence purposes only.

Do not use against any systems you have not been authorised to.

This may be detected by security products and may cause instability/BSOD.

If you are looking to test if you are exposed make sure to remove/block any vulnerable versions of CORMEM.SYS and ensure driver blocklist/HVCI policies are enabled.