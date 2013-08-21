#define  PATCH(i,w)  WriteProcessMemory(hopen,(LPVOID)(g_dwGameAddr+i),w,sizeof(w)-1,0);
#define  WPM(i,w,l)  WriteProcessMemory(hopen,reinterpret_cast<LPVOID>(gamebase+i),w,l,NULL);
#define IN
#define OUT
#include<stdio.h>
#include<windows.h>
#include<TLHELP32.H>
#include<TCHAR.H>

typedef enum _MEMORY_INFORMATION_CLASS 
{
	MemoryBasicInformation,
	MemoryWorkingSetList,
	MemorySectionName,
	MemoryBasicVlmInformation
} MEMORY_INFORMATION_CLASS;


typedef long (NTAPI * PF_ZwQueryVirtualMemory) 
(        
 IN HANDLE ProcessHandle,
 IN PVOID BaseAddress,
 IN MEMORY_INFORMATION_CLASS MemoryInformationClass,
 OUT PVOID MemoryInformation,
 IN ULONG MemoryInformationLength,
 OUT PULONG ReturnLength OPTIONAL 
 );


typedef struct _UNICODE_STRING
{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;


enum WC3VER{_UN,_120E,_124B,_124E,_125B,_126B};

//全局变量定义
WC3VER  g_War3Ver;//war3 版本
TCHAR  LastDLLPath[260];
DWORD g_dwGameAddr;
DWORD gamebase;
HANDLE hopen;





DWORD GetGameDLLAddr(HANDLE hWar3Handle,WCHAR * ModuleName)
{
	DWORD startAddr;
	BYTE buffer[MAX_PATH*2+4];
	MEMORY_BASIC_INFORMATION memBI;
	PUNICODE_STRING secName;   
	PF_ZwQueryVirtualMemory ZwQueryVirtualMemory;

	startAddr = 0x00000000;
	ZwQueryVirtualMemory = (PF_ZwQueryVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll"),"ZwQueryVirtualMemory");
	do{
		if(ZwQueryVirtualMemory(hWar3Handle,(PVOID)startAddr,MemoryBasicInformation,&memBI,sizeof(memBI),0 ) >= 0 &&
			(memBI.Type == MEM_IMAGE))
		{
			if( ZwQueryVirtualMemory(hWar3Handle,(PVOID)startAddr,MemorySectionName,buffer,sizeof(buffer),0 ) >= 0 )
			{
				secName = (PUNICODE_STRING)buffer;
				if(wcsicmp(ModuleName, wcsrchr(secName->Buffer,'\\')+1) == 0)
				{
					return startAddr;
				}
			}
			// 递增基址,开始下一轮查询!
		}
		startAddr += 0x10000;
	}
	while( startAddr < 0x80000000 );
	return 0;
};


/*
void EnableDebugPriv()//提升程序自身权限
{
        HANDLE hToken;
        LUID sedebugnameValue;
        TOKEN_PRIVILEGES tkp;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) return;
        if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME,&sedebugnameValue))
        {
                CloseHandle(hToken);
                return;
        }
        tkp.PrivilegeCount = 1;
        tkp.Privileges[0].Luid = sedebugnameValue;
        tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        if (!AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof tkp, NULL, NULL)) CloseHandle(hToken);
}
*/

BOOL ImproveProcPriv()
{
	//得到进程的令牌句柄
	HANDLE token;
	if(!OpenProcessToken(GetCurrentProcess(),TOKEN_ADJUST_PRIVILEGES,&token))
	{
		printf("打开进程令牌失败...\n");
		return FALSE;
	}

	//查询进程的权限
	TOKEN_PRIVILEGES tkp;
	tkp.PrivilegeCount = 1;
	LookupPrivilegeValue(NULL,SE_DEBUG_NAME,&tkp.Privileges[0].Luid);

	//修改进程权限
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	if(!AdjustTokenPrivileges(token,FALSE,&tkp,sizeof(tkp),NULL,NULL))
	{
		printf("调整令牌权限失败...\n");
		return FALSE;
	}
	CloseHandle(token);
	return TRUE;
}

DWORD GetPIDForProcess(char* process)//获取进程ID
{
        BOOL                    working;
        PROCESSENTRY32          lppe= {0};
        DWORD                   targetPid=0;
        HANDLE hSnapshot=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS ,0);
        if (hSnapshot)
        {
                lppe.dwSize=sizeof(lppe);
                working=Process32First(hSnapshot,&lppe);
                while (working)
                {
                        if(strcmp((const char *)lppe.szExeFile,process)==0)
                        {
                                targetPid=lppe.th32ProcessID;
                                break;
                        }
						working=Process32Next(hSnapshot,&lppe);
                }
        }
        CloseHandle( hSnapshot);
        return targetPid;
}


DWORD GetDLLBase(char* DllName, DWORD tPid)
{
        HANDLE snapMod; 
        MODULEENTRY32 me32;
        if (tPid == 0) return 0;
        snapMod = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, tPid); 
        me32.dwSize = sizeof(MODULEENTRY32); 
        if (Module32First(snapMod, &me32))
        { 
                do
                {
                        if (strcmp(DllName,(const char *)me32.szModule) == 0)
                        { 
                                strcpy(LastDLLPath ,me32.szExePath);//game.dll路径
                                CloseHandle(snapMod);
                                return (DWORD) me32.modBaseAddr; 
                        }
                }while(Module32Next(snapMod,&me32));
        }
        else
        {
         //        Powers=true;
        }
        CloseHandle(snapMod); 
        return 0; 
} 


DWORD  GetFileVer( LPTSTR FileName,  LPTSTR lpVersion,  DWORD nSize) 
{ 
        TCHAR  SubBlock[64]; 
        DWORD  InfoSize; 
        InfoSize = GetFileVersionInfoSize(FileName,NULL);        
		if(InfoSize==0) return 0; 
        
		TCHAR *InfoBuf = new TCHAR[InfoSize];  
        GetFileVersionInfo(FileName,0,InfoSize,InfoBuf); 
        unsigned int  cbTranslate = 0; 
        struct LANGANDCODEPAGE
        { 
                WORD wLanguage; 
                WORD wCodePage; 
        }
        *lpTranslate; 
        VerQueryValue(InfoBuf, TEXT("\\VarFileInfo\\Translation"), 
                (LPVOID*)&lpTranslate,&cbTranslate); 
        // Read the file description for each language and code page. 
        wsprintf( SubBlock,  
                TEXT("\\StringFileInfo\\%04x%04x\\FileVersion"), 
                lpTranslate[0].wLanguage, 
                lpTranslate[0].wCodePage); 
        void *lpBuffer=NULL; 
        unsigned int dwBytes=0; 
        VerQueryValue(InfoBuf, SubBlock, &lpBuffer, &dwBytes);  
        lstrcpyn(lpVersion,(LPTSTR)lpBuffer,nSize); 
        delete[] InfoBuf; 
        return dwBytes; 
}


void GetWar3Ver()
{
        TCHAR FileVer[64];
  //      ODV(TEXT("%s"),LastDLLPath);
        GetFileVer(LastDLLPath,FileVer,64);
   //    ODV(TEXT("%s"),FileVer);
        if(lstrcmpi(FileVer,TEXT("1, 20, 4, 6074")) ==0)
        {
                g_War3Ver=_120E;
        }
        else if(lstrcmpi(FileVer,TEXT("1, 24, 1, 6374")) ==0)
        {
                g_War3Ver=_124B;
        }
        else if(lstrcmpi(FileVer,TEXT("1, 24, 4, 6387")) ==0)
        {
                g_War3Ver=_124E;
        }
        else if(lstrcmpi(FileVer,TEXT("1, 25, 1, 6397")) ==0)
        {
                g_War3Ver=_125B;
        }
        else if(lstrcmpi(FileVer,TEXT("1, 26, 0, 6401")) ==0)
        {
                g_War3Ver=_126B;
        }
        else
        {
                g_War3Ver=_UN;
        }
		
}


void loadcode()
{ 
	WPM(0x74D1B9,"\xB2\x00\x90\x90\x90\x90",6);       
    ////////////////////////////大地图显示单位     
   
    WPM(0x39EBBC,"\x75",1);       
    WPM(0x3A2030,"\x90\x90",2);     
    WPM(0x3A20DB,"\x8B\xC0",2);     //用相同指令替换掉      
    ///////////////////////////////显示隐形单位    
    
    WPM(0x28357C,"\x40\xC3",2);       
    /////////////////////////////////////////////////////显示物品    
  
    WPM(0x3A201B,"\xEB",1);           
    WPM(0x40A864,"\x90\x90",2);       
    ////////////////////////////////////////////小地图 去除迷雾     
  
    WPM(0x357065,"\x90\x90",2);                   
    
    ///////////////////////////////////////////小地图显示单位    
  
    //PATCH(0x361F7C,"\x00",1);  
    WPM(0x361F7C,"\xC1\x90\x90\x90",4);                                             //换了种方法绕过检测  
    /////////////////////////////////////////////敌方信号       
  
    WPM(0x43F9A6,"\x3B",1);       
    WPM(0x43F9A9,"\x85",1);       
    WPM(0x43F9B9,"\x3B",1);       
    WPM(0x43F9BC,"\x85",1);       
  
    /////////////////////////////////////////////他人提示    
    //    
    WPM(0x3345E9,"\x39\xC0\x0F\x85",4);       
    ////////////////////////////////////////////////敌方头像    
    WPM(0x371700,"\xE8\x3B\x28\x03\x00\x85\xC0\x0F\x85\x8F\x02\x00\x00\xEB\xC9\x90\x90\x90\x90",19);       
    /////////////////////////////////////盟友头像       
    WPM(0x371700,"\xE8\x3B\x28\x03\x00\x85\xC0\x0F\x84\x8F\x02\x00\x00\xEB\xC9\x90\x90\x90\x90",19);     
    //////////////////////////////////////////////////////资源面板       
    WPM(0x36058A,"\x90",1);       
    WPM(0x36058B,"\x90",1);       
    ///////////////////////////////////////////   允许交易    
    WPM(0x34E8E2,"\xB8\xC8\x00\x00",4);          
    WPM(0x34E8E7,"\x90",1);       
    WPM(0x34E8EA,"\xB8\x64\x00\x00",4);          
    WPM(0x34E8EF,"\x90",1);       
    ////////////////////////////////////////////////显示技能        
    WPM(0x2031EC,"\x90\x90\x90\x90\x90\x90",6);       
    WPM(0x34FDE8,"\x90\x90",2);       
  
    /////////////////////////////////////////////////技能CD    
    WPM(0x28ECFE,"\xEB",1);       
    WPM(0x34FE26,"\x90\x90\x90\x90",4);       
     //////////////////////////////////////////////资源条       
    //////////////////////////////////////////////野外显血       
    ///////////////////////////////////////////////视野外点击    
    WPM(0x285CBC,"\x90\x90",2);       
    WPM(0x285CD2,"\xEB",1);       
    /////////////////////////////////////////////////无限取消       
    WPM(0x57BA7C,"\xEB",1);       
    WPM(0x5B2D77,"\x03",1);       
    WPM(0x5B2D8B,"\x03",1);       
    //1111  
    /////////////////////////////////////////////////////过-MH       
    WPM(0x3C84C7,"\xEB\x11",2);       
    WPM(0x3C84E7,"\xEB\x11",2);       
    ////////////////////////////////////////////////////反-AH       
    WPM(0x3C6EDC,"\xB8\xFF\x00\x00\x00\xEB",6);       
    WPM(0x3CC3B2,"\xEB",1);       
  
    WPM(0x362391,"\x3B",1);       
    WPM(0x362394,"\x85",1);       
    WPM(0x39A51B,"\x90\x90\x90\x90\x90\x90",6);       
    WPM(0x39A52E,"\x90\x90\x90\x90\x90\x90\x90\x90\x33\xC0\x40",11);    
    ///////////////////////////////////////////////////分辨幻影 

}
void main()
{

//HWND hwar3=::FindWindow(NULL,TEXT("Warcraft III"));
//DWORD PID, TID;
//TID = ::GetWindowThreadProcessId (hwar3, &PID);

DWORD PID=GetPIDForProcess("war3.exe");
if(!PID)
{
	printf("请先打开程序\n");
	return;
}

if(ImproveProcPriv())    //提升当前进程的权限  
//EnableDebugPriv();//提升程序自身权限
{
printf("提权成功，开始打开句柄\n");
hopen = OpenProcess( PROCESS_ALL_ACCESS|PROCESS_TERMINATE|PROCESS_VM_OPERATION|PROCESS_VM_READ|   
        PROCESS_VM_WRITE,FALSE, PID);  

}

else {
printf("提权失败\n");
return;
}

if (hopen == NULL)  
 {  
     printf("不能打开war3进程！\n");
     return ;  
 }  




gamebase=GetDLLBase(_T("Game.dll"), PID);
if(gamebase==0)
{
GetDLLBase(_T("game.dll"), PID);
}

printf("当前DLL基址：%d\n",gamebase);
printf("当前War3进程ID为 %d\n",PID);
printf("Dll Path: %s\n",LastDLLPath);

g_dwGameAddr=GetGameDLLAddr(hopen,(WCHAR*)LastDLLPath);
printf("当前基址为 %d\n",g_dwGameAddr);
GetWar3Ver();

printf("g_War3Ver版本是%d\n",g_War3Ver);
printf("现在开始修改...........\n");
switch(g_War3Ver)
{
      case _120E:
      //修改内存代码自己去找吧//大地图去除迷雾
      PATCH(0x406B53,"\x90\x8B\x09");
      PATCH(0x2A0930,"\xD2");
      //野外显血        
      PATCH(0x166E5E,"\x90\x90\x90\x90\x90\x90\x90\x90");
      PATCH(0x16FE0A,"\x33\xC0\x90\x90");
      //视野外点选
      PATCH(0x1BD5A7,"\x90\x90");
      PATCH(0x1BD5BB,"\xEB");
      //小地图显示单位
      PATCH(0x1491A8, "\x00");
break;
      case _124B:
      //小地图显示单位
      PATCH(0x361EAB,"\x90\x90\x39\x5E\x10\x90\x90\xB8\x00\x00\x00\x00\xEB\x07");
break;
      case _124E:
		  printf("开始修改1.24e版本\n");
		  loadcode();

break;
       case _UN:
       default:
break;
  printf("修改完成，试试效果吧\n");

}

}
