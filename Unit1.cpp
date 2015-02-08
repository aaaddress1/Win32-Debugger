#include <vcl.h>
#pragma hdrstop
#include <tlhelp32.h>
#include "Unit1.h"
#pragma package(smart_init)
#pragma resource "*.dfm"
TForm1 *Form1;
void*  Target__hProcess ;
String Target__ProcessName;
long   Target__ProcessID;
long TargetAddress;
DEBUG_EVENT debugEvent;

DWORD OldProtection;


//======================================================================================
bool EnablePrivilege(HANDLE   hToken,LPCTSTR   szPrivName,BOOL   fEnable){
TOKEN_PRIVILEGES   tp;
tp.PrivilegeCount   =   1;
LookupPrivilegeValue(NULL,szPrivName,&tp.Privileges[0].Luid);
tp.Privileges[0].Attributes   =   fEnable   ?   SE_PRIVILEGE_ENABLED:0;
AdjustTokenPrivileges(hToken,FALSE,&tp,sizeof(tp),NULL,NULL);
return((GetLastError()   ==   ERROR_SUCCESS));
}
void __fastcall TForm1::FormCreate(TObject *Sender){
HANDLE hToken=NULL;
if(0!=OpenProcessToken(GetCurrentProcess(),TOKEN_ADJUST_PRIVILEGES,&hToken)){
EnablePrivilege(hToken,SE_DEBUG_NAME,true); //提權
}else{ShowMessage("Fail To Get Debug Privilege.");return ;}
}
__fastcall TForm1::TForm1(TComponent* Owner): TForm(Owner){}
//======================================================================================
void HideDebug(PROCESS_INFORMATION pi)
{
    BYTE ISDEBUGFLAG = 0x00;
    int ISHEAPFLAG = 2;
    SuspendThread(pi.hThread);
    CONTEXT context;
    ZeroMemory(&context,sizeof(CONTEXT));
    context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;
    GetThreadContext(pi.hThread,&context);
    //IsDebugPresent_Flag
    WriteProcessMemory(pi.hProcess,(LPVOID)(context.Ebx+0x2),&ISDEBUGFLAG,1,NULL);
	//NTGlobal_Flag  用0D则为70  这个为0 防止其他调试器存在
    WriteProcessMemory(pi.hProcess,(LPVOID)(context.Ebx+0x68),&ISDEBUGFLAG,1,NULL);
    //GetProcessHeap_Flag
    DWORD HeapAddress;
    ReadProcessMemory(pi.hProcess,(LPCVOID)(context.Ebx + 0x18),&HeapAddress,sizeof(HeapAddress),NULL);
	WriteProcessMemory(pi.hProcess,(LPVOID)HeapAddress,&ISHEAPFLAG,sizeof(ISHEAPFLAG),NULL);
	ReadProcessMemory(pi.hProcess,(LPCVOID)(context.Ebx + 0x68),&ISDEBUGFLAG,1,NULL);
	ResumeThread(pi.hThread);
}

//======================================================================================

DWORD WINAPI Thread(LPVOID lpParameter){
bool DebugFinish = DebugActiveProcess(Target__ProcessID);
if (!DebugFinish) {return true;}
bool Wait = true;
long NextAction = DBG_EXCEPTION_NOT_HANDLED;
CONTEXT ct = {0};
void* hThread ;

		while(Wait){
				WaitForDebugEvent(&debugEvent,INFINITE);
				switch (debugEvent.dwDebugEventCode){

						case EXCEPTION_DEBUG_EVENT:
							if (debugEvent.u.Exception.ExceptionRecord.ExceptionCode != EXCEPTION_BREAKPOINT ) {
							VirtualProtectEx(Target__hProcess,(LPVOID)TargetAddress,0x4,PAGE_EXECUTE_READWRITE, &OldProtection);

								hThread = OpenThread(THREAD_ALL_ACCESS, false, debugEvent.dwThreadId);
								SuspendThread(hThread);
							//	ShowMessage("catch");
								//	NextAction = DBG_EXCEPTION_NOT_HANDLED;
								NextAction =  DBG_CONTINUE        ;
								ZeroMemory(&ct,sizeof(CONTEXT));
								ct.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;
								GetThreadContext(hThread,&ct);
								Form1->ListBox1->Items->Clear() ;
								Form1->ListBox1->Items->Add("EIP:"+IntToHex((int)ct.Eip,sizeof(long)));//這裡可以取得寄存器資料
								Form1->ListBox1->Items->Add("Eax:"+IntToHex((int)ct.Eax,sizeof(long)));//這裡可以取得寄存器資料
								Form1->ListBox1->Items->Add("Ebx:"+IntToHex((int)ct.Ebx,sizeof(long)));//這裡可以取得寄存器資料
								Form1->ListBox1->Items->Add("Ecx:"+IntToHex((int)ct.Ecx,sizeof(long)));//這裡可以取得寄存器資料
								Form1->ListBox1->Items->Add("Edx:"+IntToHex((int)ct.Edx,sizeof(long)));//這裡可以取得寄存器資料
								long EspValue ;
								ReadProcessMemory(Target__hProcess,(void*)ct.Esp,&EspValue,sizeof(long),NULL);
								Form1->ListBox1->Items->Add(IntToHex((int)ct.Esp,sizeof(long))+"(Esp+0):"+IntToHex((int)EspValue,sizeof(long)));//這裡可以取得寄存器資料

							   //	ct.Eip-= 5;
								SetThreadContext(hThread,&ct);
								ResumeThread(hThread);

							}else{
								NextAction = DBG_EXCEPTION_NOT_HANDLED;
							}
						break;

						case EXCEPTION_BREAKPOINT:
						NextAction = DBG_EXCEPTION_NOT_HANDLED;
						break;

						case EXIT_PROCESS_DEBUG_EVENT:
						ExitProcess(0);
						break;
				}
		ContinueDebugEvent(debugEvent.dwProcessId,debugEvent.dwThreadId,NextAction);
		}
return true;
}

//=====================================下拖更新進程=======================================
void __fastcall TForm1::ComboBox1DropDown(TObject *Sender){
	this->ComboBox1->Items->Clear() ;
	HANDLE snapshot ;
	PROCESSENTRY32 processinfo ;
	processinfo.dwSize = sizeof (processinfo) ;
	snapshot = CreateToolhelp32Snapshot (TH32CS_SNAPPROCESS, 0) ;
	if (snapshot == NULL) return ;
	bool status = Process32First (snapshot, &processinfo) ;
	while (status){
	String ThisGet =  processinfo.szExeFile;
	this->ComboBox1->Items->Add(ThisGet);
	 status = Process32Next (snapshot, &processinfo) ;
	}
}
//===================================讀取選定之進程資料===================================
void __fastcall TForm1::ComboBox1Change(TObject *Sender){
	String ProcessChoise  =  this->ComboBox1->Items->operator [](this->ComboBox1->ItemIndex) ;
	this->Text = "黑帝斯 (" +ProcessChoise+")";
	HANDLE snapshot ;
	PROCESSENTRY32 processinfo ;
	processinfo.dwSize = sizeof (processinfo) ;
	snapshot = CreateToolhelp32Snapshot (TH32CS_SNAPPROCESS, 0) ;
	if (snapshot == NULL) return ;
	bool status = Process32First (snapshot, &processinfo) ;
	while (status){
	String ThisGet =  processinfo.szExeFile;
		if (ProcessChoise == ThisGet) {
			if (!OpenProcess(PROCESS_ALL_ACCESS,false,processinfo.th32ProcessID)) {
			ShowMessage("The Process Has Been Protected.");
			this->ComboBox1->Text = Target__ProcessName;
			}else{
				Target__ProcessName = ProcessChoise;
				Target__ProcessID = processinfo.th32ProcessID;
				Target__hProcess=OpenProcess(PROCESS_ALL_ACCESS,false,Target__ProcessID);
				this->Label2->Caption = ProcessChoise+" - " +Target__ProcessID ;
			}
		}
	 status = Process32Next (snapshot, &processinfo) ;
	}
}
//===============================================================================
void __fastcall TForm1::Button1Click(TObject *Sender){
 TargetAddress = ("0x"+this->Edit1->Text).ToInt();
//bool GetBt = ReadProcessMemory(Target__hProcess,(void*)TargetAddress,&OldByte,sizeof(Int3Byte),NULL);
VirtualProtectEx(Target__hProcess,(LPVOID)TargetAddress,0x4,PAGE_NOACCESS, &OldProtection);
}
//===============================================================================
void __fastcall TForm1::Button2Click(TObject *Sender){
if (Target__hProcess != 00) {
		CreateThread(NULL,0xFF,Thread,NULL,0,NULL);
		this->ComboBox1->Enabled=false;
		this->Button2->Enabled=false;
		this->Label2->Caption = "Attack "+ Target__ProcessName+"(" +Target__ProcessID+") Over." ;
	}else{
	ShowMessage("Please Choose A Process.");
}
}
//===============================================================================





