#Written by DPEH
#Powershell Malware Scanner
#Version 0.1

$obj_defender = Get-MpComputerStatus
Write-Host "Defender [Enabled] " + $obj_defender.AntiVirusEnabled
Write-Host "Defender [Last Full Scan] " + $obj_defender.FullScanEndTime + " (Days old"+ $obj_defender.FullScanAge +")"
Write-Host "Defender [Current Signature Version] " + $obj_defender.AntivirusSignatureVersion + " (Days old "+ $obj_defender.AntivirusSignatureAge +" )"
if ($obj_defender.FullScanAge > 0)
{
    Write-Host "Updating Signatures"
    #update defender signature
    Update-MpSignature -verbose
    Write-Host "Defender [Current Signature Version] " + $obj_defender.AntivirusSignatureVersion + " (Days old "+ $obj_defender.AntivirusSignatureAge +" )"   
}

#quick scan
#Start-MpScan -ScanType QuickScan
#full scan
#Start-MpScan -ScanType FullScan

$FileList = Get-Content -Path ".\findfiles.txt"
$ArrayFullPathFileFound = @()
$filenamedate = $(((get-date).ToUniversalTime()).ToString("yyyyMMddTHHmmssZ"))

foreach($filelocation in $FileList) {
    $resultfullfilepath = $false
    $resultfullfilepath = Test-Path $filelocation -PathType Leaf
    $justfilename = Split-Path $filelocation -leaf
    #Write-Host $filelocation
    #Write-Host $resultfullfilepath

    $outcome = "[" + $resultfullfilepath + "]" + $filelocation
    if ($resultfullfilepath -eq $True)
    {
        $ArrayFullPathFileFound.Add($outcome)
        #Write-Host $outcome
    }
    else {
        #Write-Host $outcome
    }
}



#users
$ArrayfullfileList = Get-ChildItem -Path 'C:\Users\Public\Desktop' -File -Filter * -Recurse -ErrorAction SilentlyContinue -Force -Verbose | Where-Object { Write-Progress "Filename - $($_.Fullname)"; $true }
#$arrayallfilesinusers = Get-ChildItem -Path 'C:\Users\' -Name 'F*' -File -Recurse -ErrorAction SilentlyContinue -Force -Verbose
#$arrayallfilesinusers = Get-ChildItem -Path 'C:\Users\' -File -Recurse -ErrorAction SilentlyContinue -Force -Verbose
#export list of files to csv

$ArrayfullfileList | Export-Csv -Path "C:\temp\$filenamedate-FILEINVENTORY-USERS.csv" -NoTypeInformation

#now check through it for file names

foreach($filesweep in $ArrayfullfileList) {
    Write-Host $filesweep.Name
}


#if ($resultfullfilepath -eq $True)
#{
#    $ArrayFullPathFileFound.Add($justfilename)
#    #Write-Host $outcome
#}
#else {
#    #Write-Host $outcome
#}


if(($ArrayFullPathFileFound | Measure-Object -Maximum).Maximum -gt 0){
    Write-Host "OBJECTS FOUND - Contact itsupport@!" + $filenamedate
    $ArrayFullPathFileFound | Export-Csv -Path "C:\temp\$filenamedate-FOUND-scan-custom.csv" -NoTypeInformation
} else {
    Write-Host "CLEAN - Nothing Found!" + $filenamedate
    Write-Output "CLEAN - Nothing Found!" | Out-File -FilePath "C:\temp\$filenamedate-CLEAN-scan-custom.txt"
}
