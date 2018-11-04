#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <ntsecapi.h>
#pragma warning(push)
#pragma warning(disable:4005)
#include <ntstatus.h>
#pragma warning(pop)

/*
Documentation

Password Filters
https://docs.microsoft.com/en-us/windows/desktop/SecMgmt/management-functions#password-filter-functions

Blog
https://userexistserror.blogspot.com/2018/11/active-directory-password-enforcement.html
*/


extern "C" __declspec(dllexport)
BOOLEAN WINAPI InitializeChangeNotify()
/*
https://docs.microsoft.com/en-us/windows/desktop/api/Ntsecapi/nc-ntsecapi-psam_init_notification_routine
*/
{
	return TRUE;
}


extern "C" __declspec(dllexport)
NTSTATUS WINAPI PasswordChangeNotify(PUNICODE_STRING UserName, ULONG RelativeId, PUNICODE_STRING NewPassword)
/*
https://docs.microsoft.com/en-us/windows/desktop/api/Ntsecapi/nc-ntsecapi-psam_password_notification_routine
*/
{
	return STATUS_SUCCESS;
}


extern "C" __declspec(dllexport)
BOOLEAN WINAPI PasswordFilter(PUNICODE_STRING AccountName, PUNICODE_STRING FullName, PUNICODE_STRING Password, BOOLEAN SetOperation)
/*
https://docs.microsoft.com/en-us/windows/desktop/api/Ntsecapi/nc-ntsecapi-psam_password_filter_routine
*/
{
	if (Password == NULL)
		return FALSE;

	// Password->Length is size of Buffer in bytes
	size_t length = Password->Length / sizeof(WCHAR);

	// Note that minimum length check is already done by the password policy.
	if (length < 8)
		return FALSE;

	WCHAR *banned[] = { L"Changeme5?", L"Password123!" };
	for (size_t i = 0; i < sizeof(banned) / sizeof(banned[0]); i++) {
		if (lstrlenW(banned[i]) == length) {
			if (wcsncmp(Password->Buffer, banned[i], length) == 0)
				return FALSE;
		}
	}
	return TRUE;
}
