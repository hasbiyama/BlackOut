# BlackOut
a small rootkit dealing with file operations, dse, and process protection

> **Target**: Any version/build of Windows 8.1, 10 and 11. 

## Overview
1. Utilise minifilter for file ops on IRP_MJ_DIRECTORY_CONTROL
   - 2 FLT_PREOP_CALLBACK_STATUS (1 IRP_MJ_CREATE on its Callbacks)
   - FLT_POSTOP_CALLBACK_STATUS
3. Utilise g_CiOptions to enable/disable DSE (No VBS)
4. Utilise PsIsProtectedProcess to get PPS_PROTECTION offset

## Setup

![Screenshot (4)](https://github.com/user-attachments/assets/50389314-6beb-453a-b4e7-c55295786d96)
> **Note**: Use this range for the altitude: 360000 - 389999
<br> https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/allocated-altitudes

## Demo
>file ops
>
https://github.com/user-attachments/assets/4839f83d-ea89-46ed-9a27-29fb7e247775

> dse
>
https://github.com/user-attachments/assets/b8a4126b-4914-42af-8a16-5d3ed058f69a

> process protection
>
https://github.com/user-attachments/assets/6dbdea75-bdbf-4ad6-a476-63ca9c4b63d6

## References
1. https://github.com/JKornev/hidden
2. https://github.com/Idov31/Nidhogg
3. https://github.com/joaoviictorti/shadow-rs
4. https://blog.xpnsec.com/gcioptions-in-a-virtualized-world/
5. https://tierzerosecurity.co.nz/2024/04/29/kexecdd.html
6. https://itm4n.github.io/debugging-protected-processes/
