# AMSI_bypussy
AMSI stands for "Antimalware Scan Interface." This script essentially smashes the AMSI protection by breaking one of the components in the AMSI chain. How can we detect this kind of technique? keep reading.
---
![881b1972cd1a67891f80aa1931bdb438 (1)](https://user-images.githubusercontent.com/65976929/214705830-9f35e0dc-0f3c-4c86-969b-a048ac213696.jpg)
---

🔊 suggested background:

![IMG_20230129_113434](https://user-images.githubusercontent.com/65976929/215320680-a39986d9-33f8-486f-8447-7bfdbf5a9166.jpg)

https://youtu.be/QQYyJhuwPwI?t=1

**Fast Recap of what exactly AMSI is:**
---
Powershell has a cmdlet i.e., Invoke-Expression which evaluates or runs the string passed to it completely in memory without storing it on disk.
That’s when Microsoft introduce AMSI with the release of Windows 10. At a high level, think of AMSI like a bridge which connects powershell to the antivirus software, every command or script we run inside powershell is fetched by AMSI and sent to installed antivirus software for inspection.

The AMSI API calls that the program can use (in our case powershell) is defined inside amsi.dll. As soon as the powershell process has started, amsi.dll is loaded into it. AMSI protects PowerShell by loading AMSI’s DLL (amsi.dll) into the PowerShell’s memory space. AMSI protection does not distinguish between a simple user with low privileges and a powerful user, such as an admin. AMSI loads its DLL for any PowerShell instance.

![image](https://user-images.githubusercontent.com/65976929/214707517-9e7052b3-7a6a-4250-bcf1-801389e33ee8.png)

AMSI exports the below mentioned API functions that the program uses to communicate with the local antivirus software through RPC.

![image](https://user-images.githubusercontent.com/65976929/214707702-5c2a6b01-c554-4e19-ad0d-424d8dd30363.png)

Most interesting is **AmsiScanBuffer**: Similar to AmsiScanString, this method takes in the buffer instead of string and returns the result.

![image](https://user-images.githubusercontent.com/65976929/214708244-01d514a6-a6b6-4f86-88ed-541c309f4c61.png)
https://learn.microsoft.com/en-us/windows/win32/api/amsi/nf-amsi-amsiscanbuffer

AmsiScanString later calls AmsiScanBuffer underneath.

![image](https://user-images.githubusercontent.com/65976929/214708528-27b34a1b-73fc-48dc-9264-099b0ee51fed.png)

---
ok, now we understand that (maybe) we can patch this API call in order to break something and run whatever we want.

![image](https://user-images.githubusercontent.com/65976929/214709073-5bf5ed8e-e3d9-4107-b8bb-314112627cbb.png)

so, we can continue by patching the AmsiScanBuffer function as the amsi.dll library is loaded in the same virtual memory space of the process, so we have pretty much full control in that address space. Let’s see the AMSI API calls made by powershell with the help of Frida.
When we first start frida session, it creates handler files, we can modify those file to print the arguments and results at runtime.

![image](https://user-images.githubusercontent.com/65976929/214710372-7b44b7c9-1377-4ed4-8e19-db8f2e223b86.png)

![image](https://user-images.githubusercontent.com/65976929/214710440-d089b0c4-9770-4be6-be73-00bb1918a008.png)

-- The antimalware provider may return a result between 1 and 32767, inclusive, as an estimated risk level. .. Any return result equal to or larger than 32768 is considered malware, and the content should be blocked. - (https://learn.microsoft.com/en-us/windows/win32/api/amsi/ne-amsi-amsi_result) --

---

Let’s look into the AmsiScanBuffer function in more detail inside Disassembler:


![image](https://user-images.githubusercontent.com/65976929/214711717-0d73b05e-d309-4642-ab6d-666d0c63b5c4.png)

The actual scanning is performed by the instructions in the left box. The instructions at right is called whenever the arguments passed by the caller is not valid, 80070057h corresponds to **E_INVALIDARG**. And then the function ends.

So we can **patch** the beginning of AmsiScanBuffer() with the instructions in right box i.e., mov eax, 80070057h; ret. So that whenever AmsiScanBuffer() is called, it returns with the error code instead of performing the actual AMSI Scan. The byte that corresponds to that instruction is b85700780.

![image](https://user-images.githubusercontent.com/65976929/214712038-9b493316-f5f6-42aa-8c17-404d03445d4a.png)


![image](https://user-images.githubusercontent.com/65976929/214712321-f835a43c-fb11-45b8-8dcb-9c0671629ff4.png)


As can be seen, now the result is 0 and AMSI is not triggered when we passed “Invoke-Mimikatz” string in powershell.

![image](https://user-images.githubusercontent.com/65976929/214712629-a8e55ec6-55d8-4128-9842-1316dcc20f95.png)

---

OK. HERE WE GO.
BUT, how can we be leveraging the below Windows APIs to programatically patch the AmsiScanBuffer() ?!

![image](https://user-images.githubusercontent.com/65976929/214714738-55510ee6-a0fa-4341-b523-a4d1b67d8613.png)

- **LoadLibrary** : load amsi.dll library
- **GetProcAddress** : retrieve the address of AmsuScanBuffer()
- **VirtualProtect** : to make the address region writable as by 
                 default it’s RX. We need to make it writable 
                 as well so that we can overwrite the instructions 
                 and later we’ll again make it to RX from RWX.
                 
---

Let's take a look from **Blue Team** perspective.
---

![1d2a708b97906e4faeb5099d8efa805f](https://user-images.githubusercontent.com/65976929/214939421-745460ab-35a7-4569-b83e-49dbca8a2d19.jpg)



Checking spawned processes (e.g. checking EventID 4688 "New Process Created") we can't see anything related about that.
But let's take a look about Powershell Operational logs (Microsoft-Windows-PowerShell%4Operational.evtx): we had something interesting, like Windows APIs calls.

![image](https://user-images.githubusercontent.com/65976929/214823890-5de207b6-a9bb-4e5e-a39e-6d79aa8d2171.png)

![image](https://user-images.githubusercontent.com/65976929/214823764-32f86795-01a6-4404-b2bc-671a67f3eeb3.png)

![VirtualProtect_0x40](https://user-images.githubusercontent.com/65976929/215766955-2d68cd9b-4622-4a37-9e7e-a845c58782fb.png)

as we can observed, on the VirtualProtect function is passed the "0x40" paremeters as memory protection constant.
VirtualProtect function is used to changes protection on a memory region. First parameters correspond to the lpAddress of $Address (AmsiScanBuffer). Int "5" as the size of the region whose access protection attributes are to be changed, in bytes. And $p (=0).

![VirtualProtect funciton](https://user-images.githubusercontent.com/65976929/215767510-cbdb8e29-e09e-40a7-9d49-7723917697d1.png)

Third parameters corresponds to the flNewProtect, the memory protection option that is setted to PAGE_EXECUTE_READWRITE

![Constants_Variables](https://user-images.githubusercontent.com/65976929/215768580-863a10b1-7dd7-4aae-9d15-bd6bf21078f8.png)

Another observed evidence is related the copy() function:

![System Runtime InteropServices Marshal](https://user-images.githubusercontent.com/65976929/215769042-18012f7c-e0e0-4f7c-9d25-14eedb8a7056.png)

Setted parameters are: Copy(source, startIndex, IntPtr destination, lenght)

![image](https://user-images.githubusercontent.com/65976929/215770500-c953072e-9651-4cf0-960c-46ba9d8327e5.png)

as "source" parameters is set $Patch, 
"0" Int as startIndex (begin here), 
pointer to AmsiScanBuffer address as the "IntPtr destination",
Int "6" as "lenght" parameters that exactly correspond to byte numbers of the $Patch.

Filtering on EventViewer by EventID 4104 we had some info to correlate in order to detect this kind of technique and proceed with the hunt.
This log is enabled by default, if not, to enable script block logging, go to the Windows PowerShell GPO settings and set Turn on PowerShell Script Block Logging to enabled.
Alternately, you can set the following registry value: "HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging → EnableScriptBlockLogging = 1" (https://docs.splunk.com/Documentation/UBA/5.1.0.1/GetDataIn/AddPowerShell#:~:text=To%20enable%20script%20block%20logging,Script%20Block%20Logging%20to%20enabled.&text=In%20addition%2C%20turn%20on%20command%20line%20process%20auditing.)

---
Some pseudo code for Splunk and AzSentinel SIEMs 

index=windows sourcetype="*PowerShell/Operational*" EventID=4104 
| where 1APICalls = "LoadLibrary" AND 2APICalls = "GetProcAddress" AND 3APICalls = "VirtualProtect" 

--

PowerShellOperational
| where EventID == "4104"
| where parse_json(Parameters)[1].Log == "1APICalls"
| where parse_json(Parameters)[1].Log == "2APICalls"
| where parse_json(Parameters)[1].Log == "3APICalls"
| where 1APICalls = "LoadLibrary" and 2APICalls = "GetProcAddress" and 3APICalls = "VirtualProtect" 
  

______________________________________________________________________________________________________________________________________

Steps for the Purple Test:
1. Run (not mandatory high priv) AMSI_bypass.txt in powershell; (DONE 🔥)
2. (optional) Run everything you want to test the bypass (e.g. Invoke-OneShot-Mimikatz.txt)
3. check operational PowerShell logs 🔎.

---

This repo is intended as an overview of AMSI bypass with API patching and technique detection.
There are several ways to do AMSI bypass, the repo may be updated with the other techniques.

---

Credits: @C2melBoyz, @dazzyddos, @pentest_swissky and @_rastamouse.

![image](https://user-images.githubusercontent.com/65976929/214842518-b8a1d783-7e52-4a8c-9fa5-e781afedd7d8.png)


