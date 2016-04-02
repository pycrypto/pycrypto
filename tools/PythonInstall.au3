#RequireAdmin
#pragma compile(ExecLevel, requireAdministrator)
#pragma compile(Out, PythonInstall.exe)
#pragma compile(Console, true)

Const $iTimeout = 10
Const $iInstallTimeout = 900


;Const $sProcName = "Python-2.1.2.exe"
Const $sProcName = $CmdLine[2]
Local $pid = ProcessExists($sProcName)
If Not $pid Then
	$pid = Run($sProcName)
	If @error Then
		; TODO
	EndIf
EndIf

Const $sWinTitle = "[REGEXPTITLE:Python 2.[123].[0-9]+ Installation]"
;Const $sDestDir = "C:\Python21"
Const $sDestDir = $CmdLine[1]

; Wait for the wizard window to open
Local $hWnd = WinWait($sWinTitle, "&Next >", $iTimeout)
If Not IsHWnd($hWnd) Then
	; TODO
EndIf

; Activate the window for good measure.
If Not IsHWnd(WinActivate($hWnd, "")) Then
	; TODO
EndIf

Local $stepDestDir = False
Local $stepDestDirSet = False
Local $stepAlreadyExists = False
Local $stepReplacedFiles = False
Local $stepSelectComponents = False
Local $stepSelectStartMenuGroup = False
Local $stepReadyToInstall = False
Local $stepFinish = False
Local $timeout = False

Local $hTimer = TimerInit()
While IsHWnd(WinGetHandle($hWnd)) Or Not $stepFinish
	Select
		Case Not $stepDestDirSet And ControlSetText($sWinTitle, "Select Destination Directory", "[CLASS:Edit; INSTANCE:1]", $sDestDir)
			$stepDestDirSet = True
		Case Not $stepDestDir And $stepDestDirSet And ControlSend($sWinTitle, "Select Destination Directory", "&Next >", "!n")
			$stepDestDir = True
		Case Not $stepAlreadyExists And ControlClick("Install", "The directory " & $sDestDir & " already exists", "Yes")
			$stepAlreadyExists = True
		Case Not $stepReplacedFiles And ControlSend($sWinTitle, "Backup Replaced Files", "&Next >", "!o!n")	; "o" -- No, don't do backups
			$stepReplacedFiles = True
		Case Not $stepSelectComponents And ControlSend($sWinTitle, "Select Components", "&Next >", "!n")
			$stepSelectComponents = True
		Case Not $stepSelectStartMenuGroup And ControlSend($sWinTitle, "Select Start Menu Group", "&Next >", "!n")
			$stepSelectStartMenuGroup = True
		Case Not $stepReadyToInstall And ControlSend($sWinTitle, "Ready to Install!", "&Next >", "!n") ; DEBUG FIXME
			$stepReadyToInstall = True
		Case Not $stepFinish And ControlSend($sWinTitle, "Installation Completed!", "&Finish", "!f")
			$stepFinish = True
		Case Not ProcessExists($pid)
			ExitLoop
		Case TimerDiff($hTimer) >= $iInstallTimeout * 1000
			$timeout = True
			ExitLoop
	EndSelect
	Sleep(250)
	; TODO - Timeout
WEnd

If $timeout Then
	; TODO
EndIf

If Not $stepFinish Then
	; TODO
EndIf

Local $success = ProcessWaitClose($pid, $iTimeout)
If Not $success Then
	; TODO
EndIf
